rule SQL_Injection_In_Logs {
    meta:
        description = "Detects SQL injection exploitation attempts in web and proxy access logs"
        author = "DecodeX Security Engineering"
        severity = "High"
        tactic = "Initial Access"
        technique_id = "T1190"

    strings:
        // Union based
        $union1 = "UNION SELECT" ascii nocase
        $union2 = "UNION ALL SELECT" ascii nocase
        $union3 = "UNION%20SELECT" ascii nocase
        $union4 = "UNION/**/SELECT" ascii nocase

        // Error and schema discovery
        $schema1 = "information_schema.tables" ascii nocase
        $schema2 = "information_schema.columns" ascii nocase
        $schema3 = "sys.sysobjects" ascii nocase
        $schema4 = "pg_catalog.pg_tables" ascii nocase

        // Blind / Time-based
        $blind1 = "SLEEP(" ascii nocase
        $blind2 = "WAITFOR DELAY" ascii nocase
        $blind3 = "BENCHMARK(" ascii nocase
        $blind4 = "pg_sleep(" ascii nocase

        // SQLMap / Tooling fingerprints
        $tool1 = "sqlmap" ascii nocase
        $tool2 = "HAVING 1=1" ascii nocase
        $tool3 = "AND 1=1" ascii nocase
        $tool4 = "' OR '1'='1" ascii nocase
        $tool5 = "xp_cmdshell" ascii nocase

    condition:
        any of ($union*) or
        any of ($schema*) or
        any of ($blind*) or
        $tool1 or $tool5 or
        (2 of ($tool*))
}
