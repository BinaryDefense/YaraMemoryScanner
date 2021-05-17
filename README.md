# YaraMemoryScanner

This script allows a user to quickly scan all processes in memory on a host using a defined YARA rule. It is intended to be used by a member of a security team to review a host during an incident or during general endpoint threat hunting.

The script is intended for short term use: it downloads and executes YARA using a rule provided by the user; the rule can be provided as a file or as a URL. Since YARA is downloaded and used as part of the script, it can be used without requiring YARA to be previously downloaded and it does not leave YARA on the host.

Example use:
A member of a security team identifies a host that has been infected by malware and the individual is able to identify or create a YARA rule that matches the malware on the host. The individual desires to scan another host so they connect to the second host and execute this script using the YARA rule: in an Administrator Powershell session they execute ".\YaraMemoryScanner.ps1 rule.yar" (where rule.yar is the name of the YARA rule they wrote or identified that matches the malware they identified). A file with the name of the rule and a timestamp will be created in the directory with the Script. If a rule matched a process, the Process ID of the matched process, the name of the matched process, and the path where the process was executed from. If no rules are matched, the file simply states that no rules were matched.

## Getting started

In order to use the script, open a Powershell session as Administrator and execute the script passing it a YARA file or a URL pointing to a YARA file.

For example:
``` 
.\YaraMemoryScanner.ps1 rule.yara
```
or
```
.\YaraMemoryScanner.ps1 https://raw.githubusercontent.com/sbousseaden/YaraHunts/master/mimikatz_memssp_hookfn.yara

```

### Prerequisites
The host requires PowerShell to be accessible and requires PowerShell to be executed as Administrator.
* [PowerShell](https://github.com/PowerShell/PowerShell)
 
### Recommended Resource
In order to use YaraMemoryScanner, a YARA rule is required; the following repository contains rules that can be used with YaraMemoryScanner. 
* [Yara Rules](https://github.com/Yara-Rules/rules)

## Contributing

Send an email to brandon.george at binarydefense dot com

## Authors

* **Brandon George** - *Initial work* - [thehack3r4chan](https://github.com/thehack3r4chan)
* **Squiblydoo**  - *Contributor* 

## License

This project is licensed under GPLv3 

## Future
  * Enable event logging for detections and enable log shipping
