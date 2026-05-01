/*
    YARA Rule: PHP Web Shell Detection
    Author: Shakil Md. Rezwanul Bari
    Date: 2025-02-15
    Description: Detects common PHP web shell patterns including eval/assert
                 execution, base64 obfuscation, and file manipulation functions
                 commonly used in web application compromise.
    MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)
*/

rule PHP_WebShell_Generic
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects generic PHP web shell patterns"
        severity = "critical"
        mitre_attack = "T1505.003"
        date = "2025-02-15"

    strings:
        $php = "<?php" ascii nocase
        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $exec1 = "system(" ascii nocase
        $exec2 = "exec(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase
        $exec4 = "passthru(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $obf1 = "base64_decode(" ascii nocase
        $obf2 = "str_rot13(" ascii nocase
        $obf3 = "gzinflate(" ascii nocase
        $obf4 = "gzuncompress(" ascii nocase
        $file1 = "file_put_contents(" ascii nocase
        $file2 = "fwrite(" ascii nocase
        $net1 = "fsockopen(" ascii nocase
        $net2 = "curl_exec(" ascii nocase
        $input1 = "$_GET" ascii
        $input2 = "$_POST" ascii
        $input3 = "$_REQUEST" ascii
        $input4 = "$_FILES" ascii

    condition:
        $php and (
            (1 of ($eval*) and 1 of ($input*)) or
            (1 of ($exec*) and 1 of ($input*)) or
            (1 of ($obf*) and 1 of ($exec*)) or
            (1 of ($obf*) and 1 of ($eval*) and 1 of ($input*))
        )
}

rule PHP_WebShell_Backdoor_Keywords
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects PHP files with common backdoor keywords"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase
        $kw1 = "c99shell" ascii nocase
        $kw2 = "r57shell" ascii nocase
        $kw3 = "wso shell" ascii nocase
        $kw4 = "b374k" ascii nocase
        $kw5 = "webshell" ascii nocase
        $kw6 = "FilesMan" ascii nocase
        $kw7 = "AnonymousFox" ascii nocase

    condition:
        $php and any of ($kw*)
}
