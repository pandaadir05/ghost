/*
 * Post-2020 C2 implants.
 *
 * The pre-existing ruleset covered Cobalt Strike and Metasploit only. These
 * frameworks are the ones that have displaced them in practice, and their
 * identifiers are specific enough to stand on their own.
 */

rule C2_Implant_Sliver
{
    meta:
        description = "Sliver implant protobuf and package identifiers"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1071.001"
        reference = "https://github.com/BishopFox/sliver"
        scan_context = "memory_region"

    strings:
        $g1 = "github.com/bishopfox/sliver" ascii nocase
        $g2 = "*sliverpb.Envelope" ascii
        $g3 = "sliverpb." ascii

    condition:
        $g1 or $g2 or #g3 > 5
}

rule C2_Implant_Havoc_Demon
{
    meta:
        description = "Havoc C2 Demon agent and KaynLdr reflective loader"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1071.001"
        reference = "https://github.com/HavocFramework/Havoc"
        scan_context = "memory_region"

    strings:
        $k1 = "KaynLdr" ascii
        $k2 = "Demon.x64.dll" ascii nocase
        $k3 = "demon.x64.bin" ascii nocase
        $k4 = "DemonMain" ascii

    condition:
        $k1 or 2 of them
}

rule C2_Implant_Mythic_Http_Tasking
{
    meta:
        description = "Mythic agent HTTP tasking JSON held in memory"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1071.001"
        reference = "https://github.com/its-a-feature/Mythic"
        scan_context = "memory_region"

    strings:
        $j1 = "\"action\":\"checkin\"" ascii
        $j2 = "\"action\":\"get_tasking\"" ascii
        $j3 = "\"payload_uuid\"" ascii
        $j4 = "\"tasking_size\"" ascii

    condition:
        2 of them
}

rule Loader_Donut_Style
{
    meta:
        description = "Donut-style loader: patches WLDP and AMSI, hosts the CLR from memory"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1620"
        reference = "https://github.com/TheWover/donut"
        scan_context = "memory_region"

    strings:
        $w1 = "WldpQueryDynamicCodeTrust" ascii
        $w2 = "WldpIsClassInApprovedList" ascii
        $a1 = "AmsiScanBuffer" ascii
        $a2 = "AmsiInitialize" ascii
        $m1 = "wldp.dll" ascii nocase
        $m2 = "amsi.dll" ascii nocase
        $m3 = "clr.dll" ascii nocase

    condition:
        // The WLDP + AMSI pairing is what makes this specific; either alone
        // is ordinary for a security-aware host process.
        1 of ($w*) and 1 of ($a*) and 1 of ($m*)
}

rule CLR_Injection_Unmanaged_Host
{
    meta:
        description = "Unmanaged CLR hosting (.NET assembly injection / execute-assembly)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1620"
        scan_context = "memory_region"

    strings:
        $i1 = "CLRCreateInstance" ascii
        $i2 = "ICLRMetaHost" ascii wide
        $i3 = "ICLRRuntimeInfo" ascii wide
        $i4 = "ICorRuntimeHost" ascii wide
        $i5 = "ExecuteInDefaultAppDomain" ascii
        $v = "v4.0.30319" ascii wide
        $m = "mscoree.dll" ascii wide nocase

    condition:
        $m and 2 of ($i*, $v)
}

rule Process_Ghosting_Herpaderping
{
    meta:
        description = "Image-file tampering process creation: ghosting and herpaderping"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1055.012"
        reference = "https://github.com/jxy-s/herpaderping"
        scan_context = "memory_region"

    strings:
        $a1 = "NtCreateProcessEx" ascii
        $a2 = "NtCreateSection" ascii
        $a3 = "NtSetInformationFile" ascii
        $a4 = "FileDispositionInformation" ascii wide
        $a5 = "RtlCreateProcessParametersEx" ascii
        $a6 = "NtCreateThreadEx" ascii

    condition:
        $a1 and $a2 and 2 of ($a3, $a4, $a5, $a6)
}
