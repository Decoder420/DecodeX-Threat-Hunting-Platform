rule WebShell_Generic_Detection {
    meta:
        description = "Detects common web shell patterns and functions"
        author = "Manan Mandal - Threat Hunting Platform"
        severity = "Critical"
        tactic = "Persistence"

    strings:
        // Common PHP Execution functions
        $php_exec = / (system|shell_exec|passthru|exec|popen|proc_open)\(/
        
        // Obfuscation patterns
        $obfus_1 = "eval(base64_decode" nocase
        $obfus_2 = "gzuncompress(base64_decode" nocase
        
        // File upload and manipulation
        $file_1 = "move_uploaded_file"
        $file_2 = "fopen"
        $file_3 = "fwrite"

        // Web shell specific variables
        $var_1 = "$_POST["
        $var_2 = "$_GET["
        $var_3 = "$_REQUEST["

    condition:
        // Trigger if we see an execution function + a web request variable
        (any of ($php_exec) and any of ($var_*)) or 
        (any of ($obfus_*)) or
        (3 of them)
}