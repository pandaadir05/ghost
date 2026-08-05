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

        // Suspended process creation: push CREATE_SUSPENDED
        $create_suspended = { 6A 04 5? 6A 00 }

    condition:
        ($api_1 or $api_2)
        and 2 of ($api_3, $api_4, $api_5, $api_6)
        // Referenced so the string is not dead; unreferenced strings are a
        // fatal compile error that takes the whole ruleset down with them.
        and ($create_suspended or $api_6)
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
        description = "Detects reflective DLL loading (manual PE mapping)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        // T1620 is the technique for loading code without the OS loader;
        // T1055.001 describes injecting into another process, which is a
        // different (and often unrelated) step.
        mitre_attack = "T1620"
        scan_context = "memory_region"

    strings:
        $loader_export = "ReflectiveLoader" nocase

        // Manual PE header walk: e_lfanew -> section table -> AddressOfNames.
        // This is the loader logic itself, not an artefact of being a PE.
        $header_walk_x86 = { 8B 45 3C 8B 54 05 78 03 D5 8B 4A 20 }
        $header_walk_x64 = { 48 63 ?? 3C 48 03 ?? 8B ?? 88 00 00 00 }

    condition:
        // Two strings were removed here. One was { 4D 5A 90 00 03 00 ... },
        // the stock DOS header emitted by every Windows PE ever built, and
        // the other was a generic MSVC x64 prologue. With "any of them" and
        // critical severity, this rule fired on essentially every module in
        // every process. A PE image in unbacked memory is the real signal
        // and belongs in the engine, which knows a region's backing type.
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
        // The suspend/get/set/resume sequence is the hijack itself; the
        // allocation is what the hijacked context is pointed at. Referencing
        // $api_5 also keeps it from being a fatal unreferenced string.
        $api_1 and $api_2 and $api_3 and ($api_4 or $api_5)
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
        // Enumerating window properties before overwriting the subclass
        // callback is what distinguishes PROPagate from ordinary window
        // property use, so require it rather than leaving it unreferenced.
        ($api_1 or $api_2) and ($api_3 or $api_4) and ($api_5 or $api_6)
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
        // NtTestAlert is what an early-bird payload uses to drain the APC
        // queue in its own thread; it is far more specific than the
        // CreateProcess/ResumeThread pair.
        $api_5 = "NtTestAlert" nocase

    condition:
        // An unreferenced string used to sit here ({ 00 00 00 04 }, also the
        // wrong byte order for CREATE_SUSPENDED). Unreferenced strings are a
        // FATAL YARA compile error, and because one bad file aborts the whole
        // compile, it silently disabled the entire ruleset.
        ($api_1 or $api_2) and $api_3 and ($api_4 or $api_5)
}
