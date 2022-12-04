# VTHunter

VT Hunter is a means to detect and threat hunt unwanted programs or malware in a Windows environment.

This script extracts the hashes created via Sysmon from an XML export directly from Splunk and will submit the hashes to VirusTotal every 15 seconds.
The SHA256 hashes are created from Sysmon being deployed in a Windows environment and the logs being ingested into Splunk. 
The script will create multiple directories to store and sort the hashes based on the analysis returned from VirusTotal.
The script will create the following directories if not already created:

1. Hashes
2. Whitelist
3. Blacklist
4. Reports
5. Unknown

Sorting and storage of the hashes is based of the following conditions:

1. Hashes - root directory for all hashes the script extracts from the XML file. Submissions to VirusTotal will happen from this directory
2. Whitelist - Hash analysis returned from VirusTotal with 0 detections will be moved into this directory
3. Blacklist - Hash analysis returned from VirusTotal with 1 or more detections will be moved into this directory
4. Reports - Positive detections returned from VirusTotal will create a report which will be moved into this directory
5. Unknown - Hash that are not known by VirusTotal will be moved into this directory

Things to remember:
1. The XML export from Splunk needs to be named hashes.xml otherwise the script will not work
2. You need to set the VirusTotal API key before executing the script - Set-VTAPIKey -APIKey <API Key>
3. Script has sleep condition for the use of the free VirusTotal API. Sleep condition needs to be removed if a premium VirusTotal key is used to speed up analysis

Script is based off the Sans Blue Team DeepBlueCLI script and modified to suit my currect requirements.
Please see https://github.com/sans-blue-team/DeepBlueCLI for more info on DeepBlueCLI.

This script requires the Posh-VirusTotal Powershell module, which can be found here: https://github.com/darkoperator/Posh-VirusTotal
This script requires a VirusTotal API Key, which can be found here: https://www.virustotal.com/en/documentation/public-api/
