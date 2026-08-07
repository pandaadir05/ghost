rule Generic_Shellcode_Patterns
{
    meta:
        description = "Detects generic shellcode patterns in memory"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        // Shellcode prologue: short jmp / push / xor / fs-relative load.
        // The two generic compiler prologues that used to sit here
        // ({ 55 89 E5 83 EC } and { 48 89 5C 24 ?? 48 89 74 24 }) were
        // removed - they are what MSVC and GCC emit for every function.
        $prologue_1 = { EB ?? 5? 31 ?? 64 8B }

        // PEB/TEB access patterns (x86)
        $peb_access_1 = { 64 A1 30 00 00 00 }
        $peb_access_2 = { 64 8B 15 30 00 00 00 }
        $peb_access_3 = { 64 8B 0D 30 00 00 00 }

        // API hashing (ROR13) - high specificity, low base rate
        $api_hash_ror13 = { C1 C? 0D 03 ?? 83 C? 04 }

        // Export-directory walk used by manual GetProcAddress resolvers
        $getprocaddr = { 8B 40 78 03 C? 8B 58 20 03 D? }

        // LoadLibrary pattern
        $loadlibrary = { 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 }

    condition:
        2 of them
}

// REMOVED: Windows_API_Call_Shellcode.
// The condition was "1 of ($api_*) and 1 of ($api_call, $stack_align)", but
// the $api_* glob also captured $api_call itself, so a single occurrence of
// { FF 5? ?? 85 C0 } ("call [reg+disp8]; test eax,eax" - ubiquitous in
// compiled code) satisfied both halves. The module-name requirement the
// rule was built around was never actually enforced.
//
// NOTE: the x64 PEB access patterns { 65 48 8B 04 25 60 00 00 00 } were also
// removed from Generic_Shellcode_Patterns above. "mov rax, gs:[0x60]" is
// emitted throughout ntdll, kernelbase and the CRT, and since rules are
// scanned against every executable region - including the .text of every
// loaded system DLL - it matched in every process.

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
        description = "Detects position-independent shellcode getPC constructs"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "medium"
        mitre_attack = "T1027"
        scan_context = "memory_region"

    strings:
        // call $+5 ; pop reg - the classic getPC sequence
        $call_pop = { E8 00 00 00 00 5? }

        // FSTENV getPC trick
        $fstenv = { D9 EE D9 74 24 F4 5? }

    condition:
        any of them
}

// REMOVED: Stack_Pivot_Shellcode.
// Its strings were { 8B EC 81 EC ?? ?? 00 00 } and { 48 81 EC ?? ?? 00 00 }
// (the standard x86/x64 stack-frame prologues), { 54 5C } and { 94 } - the
// last a SINGLE byte, which occurs roughly once every 256 bytes of any
// buffer. With "any of them" and threat_level "high" this reported high
// severity on every region of every process.
//
// REMOVED: NOP_Sled_Detection.
// { 40 40 ... } and { 47 47 ... } are the ASCII strings "@@@@@@@@" and
// "GGGGGGGG", which occur in base64 blobs, GUID tables and padding; long
// 0x90 runs are ordinary alignment padding. No signal.

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
