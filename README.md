# VTHunter

VTHunter automates SHA256 triage with VirusTotal and organizes results into folders for follow-up analysis.

The script now supports multiple input formats, not only Splunk XML.

## What It Does

1. Reads candidate hashes from one of the supported input sources.
2. Normalizes and validates hashes (accepts upper/lowercase, keeps valid SHA256 only).
3. De-duplicates hashes.
4. Stages pending hashes in a working directory.
5. Optionally queries VirusTotal and moves hashes into classification folders.

## Supported Input Types

1. `SplunkXml`
2. `Text` (one hash per line)
3. `Csv` (hash column configurable)
4. `Json` (array of strings or objects with hash field)
5. `Auto` (detected by file extension)

## Output Structure

Given `-HashDirectory .\Hashes`, the script creates:

1. `.\Hashes` (pending hashes to classify)
2. `.\Hashes\Whitelist` (0 detections)
3. `.\Hashes\Blacklist` (1+ detections)
4. `.\Hashes\Unknown` (hash not found in VirusTotal)
5. `.\Hashes\Reports` (saved VirusTotal report text for positives)

The script also writes activity logs to `.\Hashes.log` by default.

## Requirements

1. PowerShell
2. `Posh-VirusTotal` module for live VT lookups
3. VirusTotal API key configured for the module

Install and configure:

```powershell
Install-Module -Name Posh-VirusTotal -Scope CurrentUser -Force
Set-VTAPIKey -APIKey <API Key>
```

Module repo: https://github.com/darkoperator/Posh-VirusTotal  
VT API docs: https://docs.virustotal.com/reference/overview

## Script Parameters

`VTHunter.ps1` supports:

1. `-InputPath`  
Default: `.\Hashes.xml`
2. `-InputType`  
`Auto|SplunkXml|Text|Csv|Json` (default: `Auto`)
3. `-HashField`  
Field/column for CSV/JSON (default: `SHA256`)
4. `-InputHash`  
Pass hashes directly as an argument
5. `-HashDirectory`  
Default: `.\Hashes`
6. `-LogPath`  
Default: `.\Hashes.log`
7. `-ThrottleSeconds`  
Delay between VT requests (default: `15`)
8. `-NoVT`  
Parse/stage only, skip VirusTotal queries

## Usage Examples

Default (Splunk XML at `.\Hashes.xml`):

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1
```

Splunk XML explicitly:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\Hashes.xml -InputType SplunkXml
```

Text input:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.txt -InputType Text -NoVT
```

CSV input:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.csv -InputType Csv -HashField SHA256 -NoVT
```

JSON input:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.json -InputType Json -HashField SHA256 -NoVT
```

Auto-detect input type:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.csv -NoVT
```

Direct input hashes:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputHash AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,notahash -NoVT
```

## Testing Without VirusTotal

Use `-NoVT` to validate parsing, normalization, and staging only:

```powershell
powershell -ExecutionPolicy Bypass -File .\VTHunter.ps1 -InputPath .\hashes.txt -InputType Text -NoVT -HashDirectory .\Hashes_Test
```

Only valid SHA256 hashes are staged as files in `.\Hashes_Test`.

## Notes

1. Public VirusTotal keys are rate-limited. Keep `-ThrottleSeconds` at an appropriate value.
2. For faster throughput on premium keys, reduce `-ThrottleSeconds`.
3. Existing Splunk workflow remains supported.
