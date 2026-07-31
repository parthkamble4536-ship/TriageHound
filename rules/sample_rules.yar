/*
    Sample YARA Rules for Digital Forensics Toolkit
    ================================================
    These are demonstration rules for testing the YARA scanning engine.
    In a real investigation, replace or supplement these with rules from:
      - https://github.com/Yara-Rules/rules
      - https://github.com/Neo23x0/signature-base
*/

rule SuspiciousKeylogger
{
    meta:
        description = "Detects potential keylogger behavior patterns"
        author = "DF_Toolkit"
        severity = "HIGH"

    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetKeyState" ascii wide
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase

    condition:
        2 of ($api*) or any of ($log*)
}

rule SuspiciousReverseShell
{
    meta:
        description = "Detects common reverse shell patterns"
        author = "DF_Toolkit"
        severity = "CRITICAL"

    strings:
        $ps1 = "TCPClient" ascii wide nocase
        $ps2 = "Net.Sockets" ascii wide nocase
        $ps3 = "Invoke-Expression" ascii wide nocase
        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "/bin/bash -i" ascii wide
        $nc = "ncat -e" ascii wide nocase

    condition:
        ($ps1 and $ps2) or ($ps3 and $cmd1) or $cmd2 or $nc
}

rule SuspiciousCredentialHarvester
{
    meta:
        description = "Detects credential harvesting tool indicators"
        author = "DF_Toolkit"
        severity = "HIGH"

    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "sekurlsa" ascii wide nocase
        $dump1 = "procdump" ascii wide nocase
        $dump2 = "lsass" ascii wide nocase
        $cred1 = "credential" ascii wide nocase
        $cred2 = "password" ascii wide nocase
        $cred3 = "SAM database" ascii wide nocase

    condition:
        any of ($mimi*) or ($dump1 and $dump2) or ($cred3) or (2 of ($cred*) and any of ($dump*))
}

rule SuspiciousPersistenceMechanism
{
    meta:
        description = "Detects common persistence mechanism indicators"
        author = "DF_Toolkit"
        severity = "MEDIUM"

    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $schtask = "schtasks /create" ascii wide nocase
        $wmi = "Win32_ProcessStartup" ascii wide nocase
        $service = "sc create" ascii wide nocase

    condition:
        any of them
}
