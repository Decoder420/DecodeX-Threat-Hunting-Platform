rule C2_Framework_Activity_In_Logs {
    meta:
        description = "Detects Cobalt Strike, Sliver, Metasploit, and Havoc C2 activity indicators in logs"
        author = "DecodeX Security Engineering"
        severity = "Critical"
        tactic = "Command and Control"
        technique_id = "T1071"

    strings:
        // Cobalt Strike default beacon URI patterns & malleable C2 markers
        $cs1 = "/pixel.gif" ascii
        $cs2 = "/submit.php?id=" ascii
        $cs3 = "/match" ascii
        $cs4 = "/__utm.gif" ascii
        $cs5 = "ReflectiveLoader" ascii

        // Sliver C2
        $sliver1 = "sliver-client" ascii nocase
        $sliver2 = "bishopfox.com" ascii nocase

        // Metasploit Meterpreter default paths
        $msf1 = "meterpreter" ascii nocase
        $msf2 = "metsrv.dll" ascii nocase
        $msf3 = "reverse_tcp" ascii nocase
        $msf4 = "reverse_https" ascii nocase

        // Chisel / Ngrok / Cloudflared tunnels
        $tun1 = "chisel server" ascii nocase
        $tun2 = "chisel client" ascii nocase
        $tun3 = "ngrok http" ascii nocase
        $tun4 = "ngrok tcp" ascii nocase
        $tun5 = "cloudflared tunnel" ascii nocase

    condition:
        any of ($cs*) or
        any of ($sliver*) or
        any of ($msf*) or
        any of ($tun*)
}
