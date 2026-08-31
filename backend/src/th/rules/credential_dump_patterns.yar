rule Credential_Dumping_Signatures {
    meta:
        description = "Detects credential dumping commands, LSASS memory access, and SAM extraction in logs"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Credential Access"
        technique_id = "T1003"

    strings:
        // Mimikatz Commands
        $mimi1 = "sekurlsa::logonpasswords" ascii nocase
        $mimi2 = "sekurlsa::wdigest" ascii nocase
        $mimi3 = "sekurlsa::pth" ascii nocase
        $mimi4 = "lsadump::sam" ascii nocase
        $mimi5 = "lsadump::secrets" ascii nocase
        $mimi6 = "kerberos::golden" ascii nocase

        // LSASS Dumps & Process Tools
        $dmp1 = "procdump.exe -ma lsass" ascii nocase
        $dmp2 = "comsvcs.dll #24" ascii nocase
        $dmp3 = "comsvcs.dll, MiniDump" ascii nocase
        $dmp4 = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll" ascii nocase
        $dmp5 = "lsass.dmp" ascii nocase

        // SAM / SYSTEM Registry Dumps
        $reg1 = "reg save hklm\\sam" ascii nocase
        $reg2 = "reg save hklm\\system" ascii nocase
        $reg3 = "reg save hklm\\security" ascii nocase
        $reg4 = "vssadmin create shadow /for=c:" ascii nocase

    condition:
        any of ($mimi*) or
        any of ($dmp*) or
        any of ($reg*)
}
