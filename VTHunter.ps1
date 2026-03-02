<#
.SYNOPSIS
VTHunter automates SHA256 triage and optional VirusTotal classification.

.DESCRIPTION
VTHunter reads candidate hashes from Splunk XML, text, CSV, JSON, or direct input,
normalizes and validates SHA256 values, de-duplicates them, stages pending hashes,
and optionally classifies them with VirusTotal.

.PARAMETER InputHash
One or more hashes provided directly as arguments or pipeline input.

.PARAMETER InputPath
Path to the input file. Defaults to .\Hashes.xml.

.PARAMETER InputType
Input format. Valid values are Auto, SplunkXml, Text, Csv, Json.
Auto infers format from file extension.

.PARAMETER HashField
Column/property name containing the hash value for CSV and JSON inputs.
Defaults to SHA256.

.PARAMETER HashDirectory
Root working directory for hash staging and output subdirectories.
Defaults to .\Hashes.

.PARAMETER LogPath
Path to the log file. Defaults to .\Hashes.log.

.PARAMETER ThrottleSeconds
Delay in seconds between VirusTotal API requests. Defaults to 15.

.PARAMETER NoVT
If set, skip VirusTotal lookups and only perform parsing/normalization/staging.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1
Runs with defaults (expects .\Hashes.xml, auto-detected as SplunkXml).

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.txt -InputType Text -NoVT
Parses hashes from a text file and stages valid SHA256 values without VT queries.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.csv -InputType Csv -HashField SHA256 -NoVT
Parses hashes from CSV using the SHA256 column and stages valid values.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.json -InputType Json -HashField SHA256 -NoVT
Parses hashes from JSON objects using the SHA256 property and stages valid values.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputHash AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -NoVT
Stages a directly provided hash without reading an input file or querying VT.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias("Hash", "SHA256")]
    [string[]]$InputHash,

    [string]$InputPath = ".\Hashes.xml",

    [ValidateSet("Auto", "SplunkXml", "Text", "Csv", "Json")]
    [string]$InputType = "Auto",

    [string]$HashField = "SHA256",
    [string]$HashDirectory = ".\Hashes",
    [string]$LogPath = ".\Hashes.log",
    [int]$ThrottleSeconds = 15,
    [switch]$NoVT
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $date = Get-Date -Format "dd-MM-yyyy HH:mm:ss:ff"
    "$date $Message" | Add-Content -Path $Path
}

function Resolve-InputType {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Type
    )

    if ($Type -ne "Auto") {
        return $Type
    }

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($extension) {
        ".xml" { "SplunkXml" ; break }
        ".csv" { "Csv" ; break }
        ".json" { "Json" ; break }
        default { "Text" }
    }
}

function Get-HashesFromSplunkXml {
    param([Parameter(Mandatory = $true)][string]$Path)
    Select-Xml -Path $Path -XPath 'results/result/field/value/text' |
        ForEach-Object { $_.Node.InnerXml }
}

function Get-HashesFromText {
    param([Parameter(Mandatory = $true)][string]$Path)
    Get-Content -Path $Path
}

function Get-HashesFromCsv {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Field
    )

    Import-Csv -Path $Path | ForEach-Object {
        if ($_.PSObject.Properties.Name -contains $Field) {
            $_.$Field
        }
    }
}

function Get-HashesFromJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $content = Get-Content -Path $Path -Raw
    $json = $content | ConvertFrom-Json
    $items = if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) { $json } else { @($json) }

    foreach ($item in $items) {
        if ($item -is [string]) {
            $item
        }
        elseif ($item.PSObject -and ($item.PSObject.Properties.Name -contains $Field)) {
            $item.$Field
        }
    }
}

function Get-HashesFromInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Field
    )

    switch ($Type) {
        "SplunkXml" { Get-HashesFromSplunkXml -Path $Path }
        "Text" { Get-HashesFromText -Path $Path }
        "Csv" { Get-HashesFromCsv -Path $Path -Field $Field }
        "Json" { Get-HashesFromJson -Path $Path -Field $Field }
        default { throw "Unsupported input type: $Type" }
    }
}

function Get-NormalizedHashes {
    param([string[]]$RawHashes)

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in $RawHashes) {
        if ($null -eq $raw) {
            continue
        }

        $candidate = $raw.Trim().ToUpperInvariant()
        if ($candidate -match '^[0-9A-F]{64}$' -and $seen.Add($candidate)) {
            $candidate
        }
    }
}

function Ensure-HashDirectories {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $dirs = @{
        Root = $RootPath
        Whitelist = Join-Path $RootPath "Whitelist"
        Blacklist = Join-Path $RootPath "Blacklist"
        Unknown = Join-Path $RootPath "Unknown"
        Reports = Join-Path $RootPath "Reports"
    }

    foreach ($dir in $dirs.Values | Select-Object -Unique) {
        if (-not (Test-Path -Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }

    return $dirs
}

function Initialize-PendingHashes {
    param(
        [Parameter(Mandatory = $true)][string[]]$Hashes,
        [Parameter(Mandatory = $true)][hashtable]$Dirs,
        [Parameter(Mandatory = $true)][string]$LogFile
    )

    foreach ($hash in $Hashes) {
        $pendingPath = Join-Path $Dirs.Root $hash
        $whitelistPath = Join-Path $Dirs.Whitelist "$hash.clean"
        $unknownPath = Join-Path $Dirs.Unknown "$hash.unknown"
        $blacklistPath = Join-Path $Dirs.Blacklist "$hash.*"

        if (Test-Path -Path "$pendingPath*") {
            Write-Log -Message "File exists but not scanned - Path: $pendingPath" -Path $LogFile
            continue
        }

        if (Test-Path -Path $whitelistPath) {
            Write-Log -Message "Hash has been whitelisted - Path: $whitelistPath" -Path $LogFile
            continue
        }

        if (Test-Path -Path $blacklistPath) {
            Write-Log -Message "Hash has been blacklisted - Path: $blacklistPath" -Path $LogFile
            continue
        }

        if (Test-Path -Path $unknownPath) {
            Write-Log -Message "Hash is unknown - Path: $unknownPath" -Path $LogFile
            continue
        }

        New-Item -Path $pendingPath -ItemType File -Force | Out-Null
        Write-Log -Message "File created - Path: $pendingPath" -Path $LogFile
    }
}

function Invoke-VirusTotalClassification {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Dirs,
        [Parameter(Mandatory = $true)][int]$DelaySeconds
    )

    if (-not (Get-Command Get-VTFileReport -ErrorAction SilentlyContinue)) {
        throw "Get-VTFileReport command not found. Install the VT module and set your API key with: Set-VTAPIKey -APIKey <API Key>"
    }

    $pendingFiles = Get-ChildItem -Path $Dirs.Root -File | Where-Object { $_.Name -match '^[0-9A-F]{64}$' }
    foreach ($file in $pendingFiles) {
        $sha256 = $file.Name
        $vtReport = Get-VTFileReport $sha256

        if ($vtReport.response_code -eq 0) {
            Write-Host "[?] Hash $sha256 is unknown"
            Rename-Item -Path (Join-Path $Dirs.Root $sha256) -NewName "$sha256.unknown"
            Move-Item -Path (Join-Path $Dirs.Root "$sha256.unknown") -Destination $Dirs.Unknown -Force
        }
        elseif ($vtReport.positives -eq 0) {
            Write-Host "[+] Hash $sha256 is clean"
            Rename-Item -Path (Join-Path $Dirs.Root $sha256) -NewName "$sha256.clean"
            Move-Item -Path (Join-Path $Dirs.Root "$sha256.clean") -Destination $Dirs.Whitelist -Force
        }
        elseif ($vtReport.positives -gt 0) {
            $positives = $vtReport.positives
            Write-Host "[!] Hash $sha256 detected by $positives security vendor(s)"
            if ($positives -eq 1) {
                Write-Host "[!] Only 1 detection, possible false positive; review the report"
            }

            $reportPath = Join-Path $Dirs.Reports "$sha256.$positives.VTReport"
            $vtReport | Out-String | Set-Content -Path $reportPath
            Write-Host "[!] Report saved to $reportPath"

            Rename-Item -Path (Join-Path $Dirs.Root $sha256) -NewName "$sha256.$positives"
            Move-Item -Path (Join-Path $Dirs.Root "$sha256.$positives") -Destination $Dirs.Blacklist -Force
        }
        else {
            Write-Host "[*] Unexpected VirusTotal response for $sha256"
        }

        if ($DelaySeconds -gt 0) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

Write-Host "[>] Starting VTHunter"
$dirs = Ensure-HashDirectories -RootPath $HashDirectory

$rawHashes = [System.Collections.Generic.List[string]]::new()
foreach ($hash in $InputHash) {
    if (-not [string]::IsNullOrWhiteSpace($hash)) {
        $rawHashes.Add($hash)
    }
}

foreach ($hash in $input) {
    if (-not [string]::IsNullOrWhiteSpace($hash)) {
        $rawHashes.Add([string]$hash)
    }
}

$shouldReadInputPath = $PSBoundParameters.ContainsKey("InputPath") -or $rawHashes.Count -eq 0
if ($shouldReadInputPath) {
    if (-not (Test-Path -Path $InputPath)) {
        if ($rawHashes.Count -eq 0) {
            throw "Input file not found: $InputPath"
        }
        else {
            Write-Warning "Input file not found, continuing with direct input hashes only: $InputPath"
        }
    }
    else {
        $resolvedType = Resolve-InputType -Path $InputPath -Type $InputType
        Write-Host "[>] Reading hashes from $InputPath as $resolvedType"
        foreach ($hash in (Get-HashesFromInput -Path $InputPath -Type $resolvedType -Field $HashField)) {
            $rawHashes.Add($hash)
        }
    }
}

$normalizedHashes = @(Get-NormalizedHashes -RawHashes $rawHashes.ToArray())
if ($normalizedHashes.Count -eq 0) {
    Write-Host "[>] No valid SHA256 hashes found."
    return
}

Write-Host "[>] Valid unique hashes found: $($normalizedHashes.Count)"
Initialize-PendingHashes -Hashes $normalizedHashes -Dirs $dirs -LogFile $LogPath

if ($NoVT) {
    Write-Host "[>] Skipping VirusTotal lookups due to -NoVT"
    return
}

Write-Host "[>] Submitting hashes to VirusTotal"
Invoke-VirusTotalClassification -Dirs $dirs -DelaySeconds $ThrottleSeconds
Write-Host "[>] VirusTotal submissions complete"
