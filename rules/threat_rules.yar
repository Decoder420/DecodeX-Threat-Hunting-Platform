rule Suspicious_PowerShell_Execution {
    meta:
        description = "Detects common PowerShell obfuscation or download commands"
        severity = "High"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "DownloadString" nocase
    condition:
        $a and ($b or $c)
}

rule Web_Shell_Indicator {
    meta:
        description = "Detects generic web shell upload patterns"
        severity = "Critical"
    strings:
        $a = "cmd.exe" nocase
        $b = "system(" nocase
        $c = "eval(" nocase
    condition:
        $a and ($b or $c)
}

rule Malicious_IP_Traffic {
    meta:
        description = "Detects hardcoded C2 communication strings"
        severity = "Medium"
    strings:
        $a = "45.148.10.12"
        $b = "185.220.101.1"
    condition:
        any of them
}