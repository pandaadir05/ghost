rule Generic_Shellcode_Patterns
{
    meta:
        description = "Detects generic shellcode patterns in memory"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        // Common shellcode prologue patterns
        $prologue_1 = { EB ?? 5? 31 ?? 64 8B }
        $prologue_2 = { 55 89 E5 83 EC }
        $prologue_3 = { 48 89 5C 24 ?? 48 89 74 24 }

        // PEB/TEB access patterns (x86)
        $peb_access_1 = { 64 A1 30 00 00 00 }
        $peb_access_2 = { 64 8B 15 30 00 00 00 }
        $peb_access_3 = { 64 8B 0D 30 00 00 00 }

        // PEB/TEB access patterns (x64)
        $peb_access_x64_1 = { 65 48 8B 04 25 60 00 00 00 }
        $peb_access_x64_2 = { 65 48 8B 0C 25 60 00 00 00 }

        // API hashing (ROR13)
        $api_hash_ror13 = { C1 C? 0D 03 ?? 83 C? 04 }

        // GetProcAddress pattern
        $getprocaddr = { 8B 40 78 03 C? 8B 58 20 03 D? }

        // LoadLibrary pattern
        $loadlibrary = { 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 }

    condition:
        2 of them
}

rule Windows_API_Call_Shellcode
{
    meta:
        description = "Detects shellcode with Windows API call patterns"
        author = "Ghost Detection Engine"
        threat_level = "medium"
        mitre_attack = "T1106"

    strings:
        $api_1 = "kernel32" nocase
        $api_2 = "ntdll" nocase
        $api_3 = "advapi32" nocase
        $api_call = { FF 5? ?? 85 C0 }
        $stack_align = { 83 E4 F0 }

    condition:
        1 of ($api_*) and 1 of ($api_call, $stack_align)
}

rule Egg_Hunter_Shellcode
{
    meta:
        description = "Detects egg hunter shellcode patterns"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        // 32-bit egg hunter (SEH method)
        $egg_seh_32 = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E }

        // IsBadReadPtr egg hunter
        $egg_isbad = { 8B FB 4F 4F B9 ?? ?? ?? ?? 40 }

        // NtDisplayString egg hunter
        $egg_ntdisplay = { B8 ?? ?? ?? ?? 8D 54 24 04 CD 2E }

    condition:
        any of them
}

rule Position_Independent_Shellcode
{
    meta:
        description = "Detects position-independent shellcode characteristics"
        author = "Ghost Detection Engine"
        threat_level = "medium"
        mitre_attack = "T1027"

    strings:
        // Call/Pop pattern to get EIP
        $call_pop_1 = { E8 00 00 00 00 5? }
        $call_pop_2 = { E8 ?? ?? ?? ?? 5? }

        // FSTENV trick
        $fstenv = { D9 EE D9 74 24 F4 5? }

        // GetPC thunk
        $getpc_thunk = { 8B 0C 24 C3 }

    condition:
        any of them
}

rule Stack_Pivot_Shellcode
{
    meta:
        description = "Detects stack pivot operations common in shellcode"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        $pivot_1 = { 8B EC 81 EC ?? ?? 00 00 }
        $pivot_2 = { 48 81 EC ?? ?? 00 00 }
        $pivot_3 = { 54 5C }
        $pivot_4 = { 94 }

    condition:
        any of them
}

rule NOP_Sled_Detection
{
    meta:
        description = "Detects NOP sleds commonly used in exploits"
        author = "Ghost Detection Engine"
        threat_level = "low"
        mitre_attack = "T1055"

    strings:
        $nop_x86 = { 90 90 90 90 90 90 90 90 90 90 }
        $nop_x64 = { 66 90 66 90 66 90 66 90 66 90 }
        $multi_nop_1 = { 40 40 40 40 40 40 40 40 }
        $multi_nop_2 = { 47 47 47 47 47 47 47 47 }

    condition:
        any of them
}

rule Polymorphic_Decoder_Stub
{
    meta:
        description = "Detects polymorphic decoder stubs"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1027.002"

    strings:
        // XOR decoder
        $xor_decoder_1 = { 30 ?? 40 E2 FA }
        $xor_decoder_2 = { 80 ?? ?? E2 FA }

        // ADD/SUB decoder
        $add_decoder = { 80 ?? ?? 40 3D ?? ?? ?? ?? 75 }

        // Loop-based decoder
        $loop_decoder = { AC 34 ?? AA E2 FA }

    condition:
        any of them
}
