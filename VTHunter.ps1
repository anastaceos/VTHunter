
#
# Command to search for all unique SHA256 hashses from Splunk
# source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by SHA256 
# Then export results as XML with the file name "hashes"
# Export needs to be in the same directory as the script
#
# Command to set VT API key 
# Set-VTAPIKey -APIKey <API Key>
#

Write-Host " "
Write-Host "____   _______________ ___ ___               __                "
Write-Host "\   \ /   /\__    ___//   |   \ __ __  _____/  |_  ___________ "
Write-Host " \   Y   /   |    |  /    ~    \  |  \/    \   __\/ __ \_  __ \"
Write-Host "  \     /    |    |  \    Y    /  |  /   |  \  | \  ___/|  | \/"
Write-Host "   \___/     |____|   \___|___/|____/|___|__/__|  \____>|__|   "
Write-Host " "                                                                                                        
Start-Sleep -s 5                                                                   

# Set variables for directories
$hashdir=".\Hashes"
$whitelistdir=".\Hashes\Whitelist"
$blacklistdir=".\Hashes\Blacklist"
$unknowndir=".\Hashes\Unknown"
$reportdir=".\Hashes\Reports"

# Checks if directories are created, if not create them
Write-Host "[>] Checking for the main hashes directory`r`n"
if(-not (Test-Path "$hashdir")){
	Write-Host "[!] The main hashes directory is not created"
	Write-Host "[+] Creating the main hashes directory"
	$hashdir=New-Item -Name "Hashes" -ItemType "directory"
	if( -not (Test-Path "$whitelistdir") -and -not (Test-Path "$blacklistdir") -and -not (Test-Path "$unknowndir") -and -not (Test-Path "$reportdir")){
		Write-Host "[!] The sub directories are not created"
        Write-Host "[+] Creating all the required sub directories"
        Write-Host "[+] Creating the Whitelist directory"
		$whitelistdir=New-Item -Path $hashdir -Name "Whitelist" -ItemType "directory"
        Write-Host "[+] Creating the Blacklist directory"
		$blacklistdir=New-Item -Path $hashdir -Name "Blacklist" -ItemType "directory"
        Write-Host "[+] Creating the Unknown directory"
        $unknowndir=New-Item -Path $hashdir -Name "Unknown" -ItemType "directory"
        Write-Host "[+] Creating the Reports directory"
		$reportdir=New-Item -Path $hashdir -Name "Reports" -ItemType "directory"
        Write-Host "[>] All the required sub directories have been created`r`n"
		}
	}
else{
	Write-Host "[>] The required directories have already been created`r`n" 
}

# Create hash files by parsing hash XML file exported from Splunk
Write-Host "[>] Analysing the SHA256 hashes from the Hashes.xml file"
Write-Host "[>] Please wait...`r`n"
$hashxml=".\Hashes.xml"
Select-Xml -Path $hashxml -XPath 'results/result/field/value/text' | ForEach-Object {
    $SHA256=$_.Node.InnerXML      
    if ($SHA256 -Match '^[0-9A-F]{64}$'){ # SHA256 hashes are 64 character hex strings
		$date=Get-Date -Format "dd-MM-yyy HH:mm:ss:ff" 
        $hashfile="$hashdir\$SHA256"
		$whitelisthash="$whitelistdir\$SHA256.clean"
		$blacklisthash="$blacklistdir\$SHA256.*"
        $unknownhash="$unknowndir\$SHA256.unknown"
		# Check if hash file already exists
	    if (-not (Test-Path "$hashfile*")){
			# Check if hash has been scanned before
            if((Test-Path "$whitelisthash") -or (Test-Path "$blacklisthash") -or (Test-Path "$unknownhash")){
				# If whitelisted, log it
				if(Test-Path "$whitelisthash"){
					"$date " + "Hash file has been whitelisted - Path: $whitelisthash" | Add-Content -Path .\Hashes.log	
				}
				# If blacklisted, log it
				elseif(Test-Path "$blacklisthash"){
					"$date " + "Hash file has been blacklisted - Path: $blacklisthash" | Add-Content -Path .\Hashes.log
				}
                # If unknown, log it
                elseif(Test-Path "$unknownhash"){
					"$date " + "Hash file is unknown - Path: $unknownhash" | Add-Content -Path .\Hashes.log
				}
			}
			else{
				# Hash file doesn't exist, create it, log the creation of the hash file too
				$path | Set-Content $hashfile
				"$date " + "File has been created - Path: $hashfile" | Add-Content -Path .\Hashes.log	
			}
        }
        else{
			"$date " + "File has been created but not scanned - Path: $hashfile" | Add-Content -Path .\Hashes.log
		}
    }
  }
Write-Host "[>] Analysis of the SHA256 hashes from the Hashes.xml file is complete"
Write-Host "[>] See the Hashes.log file for more detail"

# Starts hash submissions to VirusTotal
Write-Host "`r`n[>] Submitting hashes to VirusTotal`r`n"
# Get the name of each hash file from the directory and submits to VirusTotal
Get-ChildItem $hashdir | Foreach-Object{
    if ($_.Name -Match '^[0-9A-F]{64}$'){ # SHA256 hashes are 64 character hex strings
        $SHA256=$_.Name
            try{
                $VTreport = Get-VTFileReport $SHA256
            }
            catch { # Check for prerequisites for script to submit to VirusTotal
                Write-Host "[*] Failed to execute: Get-VTFileReport $SHA256`r"
    	        Write-Host "[*] Error: " $_.Exception.Message "`n"
                Write-Host "[*] Exiting`n"
                exit
            }
             # File is unknown to Virustotal
            if ($VTreport.response_code -eq 0){
               Write-Host "[?] Hash $SHA256 is unknown"
               Rename-Item -Path "$hashdir\$SHA256" -NewName "$SHA256.unknown"
		       Move-Item -Path "$hashdir\$SHA256.unknown" -Destination "$unknowndir"
            }
            # Results from VirusTotal
            if ($VTreport.positives -eq 0){
                # File is clean
                Write-Host "[+] Hash $SHA256 is clean"
                Rename-Item -Path "$hashdir\$SHA256" -NewName "$SHA256.clean"
				Move-Item -Path "$hashdir\$SHA256.clean" -Destination "$whitelistdir"
            }
            ElseIf ($VTreport.positives -gt 0){
                # File is flagged by Virustotal
                $positives=$VTreport.positives
                Write-Host "`r`n[!] Hash $SHA256 was detected by $positives security vendor(s)"
                if ($positives -eq 1){
                    Write-Host "[!] Only 1 detection, possible false positive"
                    Write-Host "[!] Check the VirusTotal report to verify"
                }
				Write-Host "[!] See $reportdir\$SHA256.$positives.VTReport for details`r`n"
				$VTreport | Set-Content "$reportdir\$SHA256.$positives.VTReport"
				# Rename original hash file, add the Virustotal positive count as a numbered extension
				Rename-Item -Path "$hashdir\$SHA256" -NewName "$SHA256.$positives"
				Move-Item -Path "$hashdir\$SHA256.$positives" -Destination "$blacklistdir"
             }
             # Wait 15 seconds between submissions, for public Virustotal API keys
             Start-Sleep -s 15
    }
}

# Hash submissions finished, no hashes to submit
Write-Host "`r`n[>] Submitting hashes to VirusTotal is complete"
Write-Host "[>] Exiting`r`n"