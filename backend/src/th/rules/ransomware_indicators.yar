rule Ransomware_Precursors_And_Destruction {
    meta:
        description = "Detects ransomware precursor activity, shadow copy deletion, and recovery inhibition in logs"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Impact"
        technique_id = "T1486"

    strings:
        // Shadow copy & backup destruction commands
        $cmd1 = "vssadmin.exe delete shadows /all /quiet" ascii nocase
        $cmd2 = "vssadmin delete shadows" ascii nocase
        $cmd3 = "wmic shadowcopy delete" ascii nocase
        $cmd4 = "wbadmin delete catalog -quiet" ascii nocase
        $cmd5 = "wbadmin delete systemstatebackup" ascii nocase

        // Boot and recovery inhibition
        $boot1 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $boot2 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $boot3 = "bcdedit.exe /set {current} recoveryenabled No" ascii nocase

        // Ransomware notes & encryption markers
        $note1 = "HOW_TO_DECRYPT_FILES" ascii nocase
        $note2 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $note3 = "README_FOR_DECRYPT" ascii nocase
        $note4 = ".lockbit" ascii nocase
        $note5 = ".blackcat" ascii nocase
        $note6 = ".akira" ascii nocase

    condition:
        any of ($cmd*) or
        any of ($boot*) or
        any of ($note*)
}
