rule CobaltStrike_Beacon_Memory
{
    meta:
        description = "Detects Cobalt Strike Beacon in process memory"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055"
        reference = "https://www.cobaltstrike.com/"

    strings:
        $beacon_1 = "%s as %s\\%s: %d" wide
        $beacon_2 = "beacon.dll" nocase
        $beacon_3 = "beacon.x64.dll" nocase
        $beacon_4 = { 69 68 69 68 69 6B ?? 69 6B 69 68 69 6B }
        $config_marker = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
        $sleep_mask = { 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 33 FF }

    condition:
        2 of them
}

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Detects Cobalt Strike Beacon configuration structure"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1071"

    strings:
        $config_1 = { 00 01 00 01 00 02 }
        $config_2 = { 00 02 00 01 00 02 }
        $config_3 = { 00 03 00 02 }
        $http_header = "MZ" wide
        $named_pipe = "\\\\.\\pipe\\" wide

    condition:
        2 of ($config_*) or ($config_1 and ($http_header or $named_pipe))
}

rule CobaltStrike_Named_Pipe_Beacon
{
    meta:
        description = "Detects Cobalt Strike named pipe beacon patterns"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1090"

    strings:
        $pipe_1 = "\\\\.\\pipe\\MSSE-" wide
        $pipe_2 = "\\\\.\\pipe\\postex_" wide
        $pipe_3 = "\\\\.\\pipe\\msagent_" wide
        $pipe_4 = "\\\\.\\pipe\\status_" wide

    condition:
        any of them
}

rule CobaltStrike_Artifact_Kit_Payload
{
    meta:
        description = "Detects Cobalt Strike Artifact Kit generated payloads"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055.002"

    strings:
        $artifact_1 = { 48 8D 05 ?? ?? 00 00 48 89 44 24 ?? 48 8D 05 }
        $artifact_2 = { 48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 }
        $reflective_loader = "ReflectiveLoader"

    condition:
        any of them
}

rule CobaltStrike_Malleable_C2_Profile
{
    meta:
        description = "Detects Cobalt Strike malleable C2 profile indicators"
        author = "Ghost Detection Engine"
        threat_level = "high"
        mitre_attack = "T1071.001"

    strings:
        $header_1 = "Cookie: " nocase
        $header_2 = "Accept: */*" nocase
        $header_3 = "User-Agent: Mozilla/" nocase
        $uri_pattern = /\/[a-z]{4,12}\/[a-z]{4,12}/

    condition:
        3 of them
}
