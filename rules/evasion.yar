rule Anti_Debug_Techniques
{
    meta:
        description = "Detects anti-debugging techniques in memory"
        author = "Ghost Detection Engine"
        threat_level = "medium"
        mitre_attack = "T1622"

    strings:
        $isdebuggerpresent = "IsDebuggerPresent" nocase
        $checkremotedebuggerpresent = "CheckRemoteDebuggerPresent" nocase
        $ntqueryinformationprocess = "NtQueryInformationProcess" nocase
        $outputdebugstring = "OutputDebugStringA" nocase

        // PEB BeingDebugged check
        $peb_debug_1 = { 64 A1 30 00 00 00 80 78 02 00 }
        $peb_debug_2 = { 65 48 8B 04 25 60 00 00 00 80 78 02 00 }

        // Debug register checks
        $dr_check = { 8B 45 ?? 89 45 ?? 8B 45 ?? 09 45 }

    condition:
        2 of them
}

rule Anti_VM_Techniques
{
    meta:
        description = "Detects anti-VM and sandbox detection techniques"
        author = "Ghost Detection Engine"
        threat_level = "medium"
        mitre_attack = "T1497.001"

    strings:
        // VM detection strings
        $vmware_1 = "VMware" nocase
        $vmware_2 = "vmtoolsd" nocase
        $virtualbox = "VirtualBox" nocase
        $vbox = "VBOX" nocase
        $qemu = "QEMU" nocase
        $kvm = "KVMKVMKVM" nocase

        // Registry keys for VM detection
        $reg_vm_1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port" nocase
        $reg_vm_2 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase

        // CPUID VM detection
        $cpuid_check = { 0F A2 81 FB ?? ?? ?? ?? }

        // Red Pill technique
        $redpill = { 0F 01 0D 00 00 00 00 }

    condition:
        2 of them
}

// REMOVED: Timing_Attacks.
// $rdtsc = { 0F 31 } is two bytes, and "Sleep" nocase substring-matches
// SleepEx, SleepConditionVariableCS and the word "sleep" in any text. With
// "2 of them" this was satisfied by essentially every binary that measures
// elapsed time - i.e. all of them.

rule API_Hashing_Obfuscation
{
    meta:
        description = "Detects API hashing for obfuscation"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1027"

    strings:
        // ROR13 hash algorithm
        $ror13 = { C1 C? 0D 03 ?? }

        // CRC32 hashing
        $crc32 = { F7 D1 33 C8 C1 E? 08 }

        // DJB2 hash
        $djb2 = { C1 E0 05 03 C? }

        // GetProcAddress via hash
        $hash_resolve = { 8B 40 78 03 C? 8B 58 20 }

    condition:
        2 of them
}

// REMOVED: Memory_Evasion_Techniques.
// "any of them" over the string "VirtualProtect" matched every PE import
// table in every process. Calling VirtualProtect is capability, not malice.
//
// REMOVED: Heaven_Gate_Technique (superseded by Wow64_Transition below).
// It required "2 of them" where two of the four strings were { 33 C0 }
// ("xor eax,eax") and { 0F 05 } ("syscall"), both of which appear thousands
// of times in ntdll's .text - and rules are scanned against ntdll in every
// process. Only the far-jump string carried any signal.

rule Wow64_Transition_Far_Jump
{
    meta:
        description = "Far jump to selector 0x33 (Heaven's Gate WoW64 transition)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1055"
        scan_context = "memory_region"

    strings:
        // jmp far 0033:xxxxxxxx
        $far_jump = { EA ?? ?? ?? ?? 33 00 }
        // push 0x33 ; call - the retf-based variant
        $push_33_call = { 6A 33 E8 }

    condition:
        any of them
}

rule AMSI_ETW_Inline_Patch_Stub
{
    meta:
        description = "In-memory AMSI/ETW patch stub together with the corresponding API names"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1562.001"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        scan_context = "memory_region"

    strings:
        // Patch stubs. The old rule also carried { 31 C0 C3 } ("xor eax,eax;
        // ret"), which is ordinary compiler output and made the rule fire on
        // every .NET and Office process at critical severity.
        $amsi_x64 = { B8 57 00 07 80 C3 }        // mov eax,0x80070057 ; ret
        $amsi_x86 = { B8 57 00 07 80 C2 18 00 }  // mov eax,0x80070057 ; ret 0x18
        $etw_x64  = { 48 33 C0 C3 }              // xor rax,rax ; ret  (the x64 form,
                                                 // which the old x86-only rule missed)
        $etw_x86  = { 33 C0 C2 14 00 }           // xor eax,eax ; ret 0x14

        $n1 = "AmsiScanBuffer" ascii
        $n2 = "AmsiOpenSession" ascii
        $n3 = "EtwEventWrite" ascii
        $n4 = "NtTraceEvent" ascii
        $n5 = "amsi.dll" ascii wide nocase

    condition:
        // A patch stub alone is compiler-ordinary; the API names alone are
        // present in every instrumented binary. Requiring both, plus two
        // independent name references, is what makes this specific.
        2 of ($n*) and 1 of ($amsi_x64, $amsi_x86, $etw_x64, $etw_x86)
}
