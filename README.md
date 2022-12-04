# VTHunter

This script parses the SHA256 hashes exported into a XML file from Splunk and submits them to VirusTotal.

Script is based off the Sans Blue Team DeepBlueCLI script and modified to suit requirements.
Please see https://github.com/sans-blue-team/DeepBlueCLI for more info on DeepBlueCLI.

This script requires the Posh-VirusTotal Powershell module, which can be found here: https://github.com/darkoperator/Posh-VirusTotal
This script rrequires a VirusTotal API Key, which can be found here: https://www.virustotal.com/en/documentation/public-api/
