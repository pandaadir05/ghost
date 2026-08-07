/*
 * Syscall-stub tradecraft.
 *
 * These byte sequences are entirely normal *inside* ntdll - that is where
 * they come from. They are only meaningful in memory that is not backed by
 * a mapped image, i.e. a stub that has been copied into a private
 * allocation to avoid calling through a hooked ntdll export.
 *
 * The engine scans every executable region, including the .text of every
 * loaded system DLL, so these rules will also match ntdll itself. Until
 * region-type gating is wired into the scanner (see yara_engine.rs), treat
 * matches as corroborating context rather than a standalone verdict - the
 * detection engine's promotion gate handles that.
 */

rule Syscall_Stub_Copied_To_Memory
{
    meta:
        description = "SysWhispers / Hell's Gate style syscall stub outside ntdll"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1106"
        reference = "https://attack.mitre.org/techniques/T1106/"
        scan_context = "memory_region"

    strings:
        // mov r10,rcx ; mov eax,SSN ; syscall ; ret
        $direct = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

        // Full ntdll-shaped stub including the WoW64 SharedUserData check,
        // copied verbatim by tools that rebuild stubs from a clean ntdll.
        $direct_full = { 4C 8B D1 B8 ?? ?? 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 }

        // Indirect variants: set up the syscall number, then jump to a
        // syscall instruction that lives inside ntdll, so the syscall does
        // not originate from private memory.
        $indirect_jmp_mem = { 4C 8B D1 B8 ?? ?? 00 00 FF 25 }
        $indirect_jmp_reg = { 4C 8B D1 B8 ?? ?? 00 00 41 FF E? }

    condition:
        // Several stubs in one region: a lone match is ntdll itself, a
        // table of them is a generated stub set.
        #direct >= 3 or $direct_full or any of ($indirect*)
}

rule Syscall_Number_Resolver
{
    meta:
        description = "Runtime SSN resolution by scanning ntdll stub prologues (Hell's/Halo's Gate)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1106"
        scan_context = "memory_region"

    strings:
        // Comparison against the 4C 8B D1 B8 stub prologue, as a dword
        $sig_dword = { B8 D1 8B 4C }
        // Byte-wise stub head check
        $bytecmp = { 80 3? 4C ?? ?? 80 7? 01 8B }
        // Neighbour walk by +/-0x20 to recover an SSN when the stub is
        // hooked (Halo's Gate / Tartarus Gate)
        $neighbour = { 8B ?? 20 00 00 00 }

    condition:
        $sig_dword and 1 of ($bytecmp, $neighbour)
}

rule Ntdll_Unhooking_Fresh_Copy
{
    meta:
        description = "Mapping a clean ntdll from KnownDlls or disk to remove inline hooks"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1562.001"
        scan_context = "memory_region"

    strings:
        $k1 = "\\KnownDlls\\ntdll.dll" ascii wide nocase
        $k2 = "\\KnownDlls32\\ntdll.dll" ascii wide nocase
        $p1 = "\\??\\C:\\Windows\\System32\\ntdll.dll" ascii wide nocase
        $p2 = "\\SystemRoot\\System32\\ntdll.dll" ascii wide nocase

        $a1 = "NtOpenSection" ascii
        $a2 = "NtMapViewOfSection" ascii
        $a3 = "NtUnmapViewOfSection" ascii
        $a4 = "NtProtectVirtualMemory" ascii

    condition:
        1 of ($k*, $p*) and 2 of ($a*)
}

rule Sleep_Obfuscation_Timer_Rop
{
    meta:
        description = "Timer/APC-queue ROP sleep obfuscation with RC4 self-encryption (Ekko family)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1027.007"
        scan_context = "memory_region"

    strings:
        // Undocumented RC4 in advapi32/cryptsp, used to encrypt the implant
        // while it sleeps
        $rc4_1 = "SystemFunction032" ascii wide
        $rc4_2 = "SystemFunction033" ascii wide

        $t1 = "CreateTimerQueueTimer" ascii wide
        $t2 = "RtlCaptureContext" ascii wide
        $t3 = "NtQueueApcThreadEx" ascii wide

        $ntcont = "NtContinue" ascii wide

    condition:
        $ntcont and 2 of ($rc4_1, $rc4_2, $t1, $t2, $t3)
}
