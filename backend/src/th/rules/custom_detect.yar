rule custom_detect
{
    meta:
        description = "Custom uploaded / created YARA signature"
        author = "SOC Analyst"
    strings:
        $a = "replace_me" ascii nocase
    condition:
        $a
}
