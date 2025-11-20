rule Process_Hollowing_Indicators
{
    meta:
        description = "Detects process hollowing technique indicators"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055.012"

    strings:
        // Common API sequences for process hollowing
        $api_1 = "NtUnmapViewOfSection" nocase
        $api_2 = "ZwUnmapViewOfSection" nocase
        $api_3 = "VirtualAllocEx" nocase
        $api_4 = "WriteProcessMemory" nocase
        $api_5 = "SetThreadContext" nocase
        $api_6 = "ResumeThread" nocase

        // Suspended process creation
        $create_suspended = { 6A 04 5? 6A 00 }

    condition:
        ($api_1 or $api_2) and 2 of ($api_3, $api_4, $api_5, $api_6)
}

rule DLL_Injection_Classic
{
    meta:
        description = "Detects classic DLL injection techniques"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055.001"

    strings:
        $api_1 = "CreateRemoteThread" nocase
        $api_2 = "LoadLibraryA" nocase
        $api_3 = "LoadLibraryW" nocase
        $api_4 = "VirtualAllocEx" nocase
        $api_5 = "WriteProcessMemory" nocase

    condition:
        $api_1 and ($api_2 or $api_3) and ($api_4 or $api_5)
}

rule Reflective_DLL_Injection
{
    meta:
        description = "Detects reflective DLL injection patterns"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055.001"

    strings:
        $reflective_1 = "ReflectiveLoader" nocase
        $reflective_2 = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 }
        $reflective_3 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $custom_loader = { 8B 45 3C 8B 54 05 78 03 D5 8B 4A 20 }

    condition:
        any of them
}

rule APC_Injection_Technique
{
    meta:
        description = "Detects APC queue injection technique"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055.004"

    strings:
        $api_1 = "QueueUserAPC" nocase
        $api_2 = "NtQueueApcThread" nocase
        $api_3 = "ZwQueueApcThread" nocase
        $api_4 = "OpenThread" nocase
        $api_5 = "VirtualAllocEx" nocase

    condition:
        ($api_1 or $api_2 or $api_3) and ($api_4 or $api_5)
}

rule Thread_Execution_Hijacking
{
    meta:
        description = "Detects thread execution hijacking"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055.003"

    strings:
        $api_1 = "SuspendThread" nocase
        $api_2 = "GetThreadContext" nocase
        $api_3 = "SetThreadContext" nocase
        $api_4 = "ResumeThread" nocase
        $api_5 = "VirtualAllocEx" nocase

    condition:
        $api_1 and $api_2 and $api_3 and $api_4
}

rule AtomBombing_Technique
{
    meta:
        description = "Detects AtomBombing injection technique"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055"
        reference = "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows"

    strings:
        $api_1 = "GlobalAddAtomA" nocase
        $api_2 = "GlobalAddAtomW" nocase
        $api_3 = "GlobalGetAtomNameA" nocase
        $api_4 = "GlobalGetAtomNameW" nocase
        $api_5 = "NtQueueApcThread" nocase

    condition:
        ($api_1 or $api_2) and ($api_3 or $api_4) and $api_5
}

rule Process_Doppelganging
{
    meta:
        description = "Detects process doppelganging technique"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055.013"

    strings:
        $api_1 = "NtCreateTransaction" nocase
        $api_2 = "NtCreateSection" nocase
        $api_3 = "NtRollbackTransaction" nocase
        $api_4 = "RtlSetCurrentTransaction" nocase

    condition:
        3 of them
}

rule PROPagate_Injection
{
    meta:
        description = "Detects PROPagate injection using window properties"
        author = "Ghost Detection Engine"
        threat_level = "medium"
        mitre_attack = "T1055"

    strings:
        $api_1 = "SetPropA" nocase
        $api_2 = "SetPropW" nocase
        $api_3 = "EnumPropsA" nocase
        $api_4 = "EnumPropsW" nocase
        $api_5 = "CallWindowProcA" nocase
        $api_6 = "CallWindowProcW" nocase

    condition:
        ($api_1 or $api_2) and ($api_5 or $api_6)
}

rule Early_Bird_Injection
{
    meta:
        description = "Detects Early Bird APC injection technique"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1055.004"

    strings:
        $api_1 = "CreateProcessA" nocase
        $api_2 = "CreateProcessW" nocase
        $api_3 = "QueueUserAPC" nocase
        $api_4 = "ResumeThread" nocase
        $create_suspended = { 00 00 00 04 }

    condition:
        ($api_1 or $api_2) and $api_3 and $api_4
}
