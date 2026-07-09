/*
   Generic ransomware-family-agnostic indicator rule.
   Intended as a starting template for building family-specific YARA rules,
   not a standalone high-confidence detection — pair with behavioral
   detection (see ransomware-defense-framework) for production use.
*/

rule Generic_Ransomware_Note_Indicators
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Generic string-based indicators common across ransom notes; template for family-specific tuning"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        $note1 = "your files have been encrypted" nocase
        $note2 = "to decrypt your files" nocase
        $note3 = "bitcoin" nocase
        $note4 = "restore your files" nocase
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase

    condition:
        2 of ($note*) or 1 of ($ext*)
}
