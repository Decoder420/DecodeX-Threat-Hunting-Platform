rule Remote_Command_Injection_Logs {
    meta:
        description = "Detects OS command injection and reverse shell execution in application logs"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Execution"
        technique_id = "T1059"

    strings:
        // Linux reverse shells
        $rev1 = "/bin/sh -i" ascii
        $rev2 = "/bin/bash -i" ascii
        $rev3 = "/dev/tcp/" ascii
        $rev4 = "mkfifo /tmp/" ascii
        $rev5 = "nc -e /bin/" ascii

        // Download and execute pipes
        $pipe1 = "curl" ascii nocase
        $pipe2 = "wget" ascii nocase
        $pipe3 = "| sh" ascii nocase
        $pipe4 = "| bash" ascii nocase
        $pipe5 = "| python" ascii nocase

        // Suspicious command chaining in query params / logs
        $chain1 = "; id;" ascii
        $chain2 = "; whoami;" ascii
        $chain3 = "; cat /etc/passwd" ascii
        $chain4 = "| whoami" ascii
        $chain5 = "`whoami`" ascii
        $chain6 = "$(whoami)" ascii

    condition:
        any of ($rev*) or
        (($pipe1 or $pipe2) and ($pipe3 or $pipe4 or $pipe5)) or
        any of ($chain*)
}
