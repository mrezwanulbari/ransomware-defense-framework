rule Ransomware_Encryption_Patterns
{
    meta:
        description = "Detects common ransomware encryption loops"

    strings:
        $loop = "for(i=0;i<" nocase
        $write = "WriteFile" nocase

    condition:
        $loop and $write
}
