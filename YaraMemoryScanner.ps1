$yarafile = $args[0]
$ProgressPreference = "SilentlyContinue"

<#
This function will gather the permissions of the executiing user and 
return a true or false when called
#>
function Test-Administrator {
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}
<#
    This function handles the scanning of processes according to the yara rule specified.
    1) Will Download Yara 4.0.5 from Github
    2) Expand the zip archive
    3) Gather all of the running processes and pipe the output to yara
    4) Yara will take the passed rule and scan each process against the rule 
    5) Write the output of the scan from stdout to a file and the terminal 
#>
function ScanProcesses{
    if (-not (Test-Path $yarafile)) {
        Write-Host "The rule file could not be found."
    }
    else {
    Clear-Host
    Write-Host "Downloading Yara"
    Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.0.5/yara-v4.0.5-1554-win64.zip" -OutFile ".\yara64.zip"
    Expand-Archive yara64.zip -Force
    Clear-Host
    Write-Host "Scanning Processes"
    $host.UI.RawUI.ForegroundColor = "Red"
    $host.UI.RawUI.BackgroundColor = "Black"
    Get-Process | ForEach-Object {
	    <#
        If a YARA Rule matches, the following will evaluate to "TRUE' and 
        #>
        if (.\yara64\yara64.exe $yarafile $_.ID -D -p 10) {
            <#
            If the a rule matches, it is worth the processing power to scan the process a second time
            The purpose of scanning it a second time is in order to print the name of the Rule that
            was matched in the YARA rule. We will then print additional information about the process which
            matched the rule.
            #>
            .\yara64\yara64.exe $yarafile $_.ID -D -p 10
		    Get-Process -Id $_.ID | Format-Table -Property Id, ProcessName, Path
	    }
    } 2>&1 | Tee-Object -FilePath .\FlaggedProcesses.txt

    $host.UI.RawUI.ForegroundColor = "White"
    $host.UI.RawUI.BackgroundColor = "DarkMagenta"
    if ( -not (Test-Path .\FlaggedProcesses.txt)) {
        Write-Host "No Processes were found matching the provided YARA rule."
    } else {
        Write-Host "Any processes that were flagged are saved in FlaggedProcesses.txt"
    }
    Remove-Item .\yara64, .\yara64.zip -Force -Recurse
    }
}
<#
    This function will execute if the rule being specified is referenced as a URL
    1) Download the rule using Invoke-WebRequest
    2) Call the ScanProcesses function
    3) Remove downloaded rule 
#>
function RuleByURL {
    Invoke-WebRequest -Uri $yarafile -OutFile rule.yar
    $yarafile = ".\rule.yar"
    ScanProcesses
    Remove-Item rule.yar 
}

<#
Confirm that the executing user is in the Administrators group
#>
if (-not (Test-Administrator)) {
    Write-Error "This script must be executed as Administrator."
    break
}
<#
Logic to determine if the rule being passed is a URL or a file on disk
#>
if ($args.Length -lt 1 -or $args.Length -gt 1) {
    Write-Host @"

Invalid arguments passed

.\YaraMemoryScanner.ps1 (URL|Yara Rule File)
e.x. 
    .\YaraMemoryScanner.ps1 rule.yara
    .\YaraMemoryScanner.ps1 https://raw.githubusercontent.com/sbousseaden/YaraHunts/master/mimikatz_memssp_hookfn.yara

"@
}
elseif ($args[0] -match 'http.*\.(yara|yar)') {
    RuleByURL
}
else {
    ScanProcesses
}