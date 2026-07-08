rule Ransomware_Generic
{
    meta:
        description = "Generic ransomware detection"
        author = "Shakil Md. Rezwanul Bari"

    strings:
        $enc1 = "AES" nocase
        $enc2 = "RSA" nocase
        $shadow = "vssadmin delete shadows" nocase

    condition:
        any of ($enc*) or $shadow
}
