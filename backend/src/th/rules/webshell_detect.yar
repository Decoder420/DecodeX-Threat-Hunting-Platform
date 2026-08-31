rule WebShell_PHP_Advanced {
    meta:
        description = "Detects advanced PHP web shells (China Chopper, Weevely, WSO, b374k)"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Persistence"
        category = "Web Application Security"

    strings:
        // Common PHP Execution functions
        $func1 = "system(" ascii nocase
        $func2 = "shell_exec(" ascii nocase
        $func3 = "passthru(" ascii nocase
        $func4 = "exec(" ascii nocase
        $func5 = "popen(" ascii nocase
        $func6 = "proc_open(" ascii nocase
        $func7 = "assert(" ascii nocase
        
        // Obfuscation & Decoding
        $obf1 = "eval(base64_decode" ascii nocase
        $obf2 = "eval(gzinflate" ascii nocase
        $obf3 = "eval(gzuncompress" ascii nocase
        $obf4 = "eval($_POST[" ascii nocase
        $obf5 = "eval($_GET[" ascii nocase
        $obf6 = "eval($_REQUEST[" ascii nocase
        
        // Known Web Shell Signatures
        $sig1 = "b374k" ascii nocase
        $sig2 = "WSOset" ascii
        $sig3 = "c99shell" ascii nocase
        $sig4 = "r57shell" ascii nocase
        $sig5 = "FilesMan" ascii

    condition:
        any of ($obf*) or
        any of ($sig*) or
        (2 of ($func*) and (1 of ($obf*) or $obf4 or $obf5 or $obf6))
}

rule WebShell_JSP_Java {
    meta:
        description = "Detects JSP and Java webshells (Godzilla, Behinder, cmd.jsp)"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Persistence"

    strings:
        $s1 = "Runtime.getRuntime().exec(" ascii
        $s2 = "ProcessBuilder(" ascii
        $s3 = "javax.crypto.Cipher" ascii
        $s4 = "request.getParameter(" ascii
        $s5 = "<%@ page import=" ascii
        $s6 = "ClassLoader.defineClass" ascii

    condition:
        ($s5 and ($s1 or $s2) and $s4) or ($s3 and $s6)
}

rule WebShell_ASPX_DotNet {
    meta:
        description = "Detects ASPX .NET webshells and command dispatchers"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Persistence"

    strings:
        $s1 = "System.Diagnostics.Process" ascii nocase
        $s2 = "ProcessStartInfo" ascii nocase
        $s3 = "Request.Item[" ascii nocase
        $s4 = "Request.QueryString[" ascii nocase
        $s5 = "Request.Form[" ascii nocase
        $s6 = "cmd.exe" ascii nocase
        $s7 = "/bin/sh" ascii nocase

    condition:
        ($s1 or $s2) and ($s3 or $s4 or $s5) and ($s6 or $s7)
}