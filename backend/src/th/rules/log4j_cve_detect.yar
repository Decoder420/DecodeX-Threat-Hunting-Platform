rule Log4j_Spring4Shell_Exploitation {
    meta:
        description = "Detects Log4j (CVE-2021-44228), Spring4Shell (CVE-2022-22965), and OGNL injection in logs"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Initial Access"
        technique_id = "T1190"

    strings:
        // Log4j / JNDI Lookups (Standard & Obfuscated)
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:rmi://" ascii nocase
        $jndi3 = "${jndi:dns://" ascii nocase
        $jndi4 = "${jndi:nis://" ascii nocase
        $jndi5 = "${jndi:iiop://" ascii nocase
        $jndi6 = "${${lower:j}" ascii nocase
        $jndi7 = "${${upper:j}" ascii nocase
        $jndi8 = "${${env:NaN:-j}" ascii nocase

        // Spring4Shell
        $spring1 = "class.module.classLoader" ascii nocase
        $spring2 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern" ascii nocase

        // Apache Struts OGNL
        $ognl1 = "%{#context[" ascii nocase
        $ognl2 = "%{#_memberAccess" ascii nocase
        $ognl3 = "@ognl.OgnlContext@" ascii nocase

    condition:
        any of ($jndi*) or
        any of ($spring*) or
        any of ($ognl*)
}
