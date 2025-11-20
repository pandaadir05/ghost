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

rule Timing_Attacks
{
    meta:
        description = "Detects timing-based anti-analysis techniques"
        author = "Ghost Detection Engine"
        threat_level = "low"
        mitre_attack = "T1497.003"

    strings:
        $rdtsc = { 0F 31 }
        $queryperformancecounter = "QueryPerformanceCounter" nocase
        $gettickcount = "GetTickCount" nocase
        $sleep = "Sleep" nocase
        $timegettime = "timeGetTime" nocase

    condition:
        2 of them
}

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

rule Memory_Evasion_Techniques
{
    meta:
        description = "Detects memory-based evasion techniques"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1562.001"

    strings:
        $virtualprotect = "VirtualProtect" nocase
        $virtualprotectex = "VirtualProtectEx" nocase
        $ntprotectvirtualmemory = "NtProtectVirtualMemory" nocase

        // Memory permission changes
        $mem_perm_1 = { 6A 40 68 00 30 00 00 }
        $mem_perm_2 = { 68 00 00 40 00 }

    condition:
        any of them
}

rule Heaven_Gate_Technique
{
    meta:
        description = "Detects Heaven's Gate (WoW64 bypass) technique"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"

    strings:
        $heavens_gate_1 = { 33 C0 }
        $far_jump = { EA ?? ?? ?? ?? 33 00 }
        $segment_switch = { 48 89 E5 48 83 EC ?? }
        $wow64_syscall = { 0F 05 }

    condition:
        2 of them
}

rule AMSI_Bypass_Attempt
{
    meta:
        description = "Detects AMSI bypass techniques"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1562.001"

    strings:
        $amsi_string = "AmsiScanBuffer" nocase
        $amsi_context = "AmsiInitialize" nocase
        $amsi_patch_1 = { B8 57 00 07 80 C3 }
        $amsi_patch_2 = { 31 C0 C3 }
        $amsi_bypass = "amsi.dll" nocase

    condition:
        2 of them
}

rule ETW_Bypass_Attempt
{
    meta:
        description = "Detects ETW bypass techniques"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1562.001"

    strings:
        $etw_string = "EtwEventWrite" nocase
        $etw_provider = "EtwEventRegister" nocase
        $etw_patch = { 33 C0 C2 14 00 }

    condition:
        any of them
}
