rule Metasploit_Meterpreter_Payload
{
    meta:
        description = "Detects Metasploit Meterpreter payload in memory"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055"

    strings:
        $meterpreter_1 = "metsrv.dll" nocase
        $meterpreter_2 = "stdapi.dll" nocase
        $meterpreter_3 = "ReflectiveLoader" nocase
        $meterpreter_4 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $meterpreter_sig = "meterpreter" nocase
        $stage_marker = { 00 00 00 00 00 00 00 00 00 00 00 00 4d 65 74 65 72 70 72 65 74 65 72 }

    condition:
        2 of them
}

rule Metasploit_Reverse_TCP_Shellcode
{
    meta:
        description = "Detects Metasploit reverse TCP shellcode patterns"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055.001"

    strings:
        // Windows reverse TCP patterns
        $rev_tcp_1 = { 68 02 00 ?? ?? 89 E6 6A 10 56 57 68 99 A5 74 61 }
        $rev_tcp_2 = { 68 7F 00 00 01 68 02 00 ?? ?? 89 E6 }
        $winsock_2 = "ws2_32" nocase
        $winsock_call = { FF 55 ?? 68 63 6D 64 00 }

    condition:
        any of them
}

rule Metasploit_Shikata_Ga_Nai_Encoder
{
    meta:
        description = "Detects Metasploit Shikata Ga Nai polymorphic encoder"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1027"

    strings:
        // Shikata Ga Nai decoder stub patterns
        $shikata_1 = { D9 74 24 F4 5? B? ?? ?? ?? ?? 31 }
        $shikata_2 = { D9 EE D9 74 24 F4 5? B? }
        $shikata_3 = { D9 ?? D9 74 24 F4 5? ?? ?? ?? ?? ?? 29 C9 }

    condition:
        any of them
}

rule Metasploit_Inline_Egg_Stager
{
    meta:
        description = "Detects Metasploit inline egg stager patterns"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        $egg_tag = { 77 30 30 74 }
        $egg_search = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E }

    condition:
        any of them
}
