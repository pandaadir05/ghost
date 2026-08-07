rule CobaltStrike_Beacon_Memory
{
    meta:
        description = "Detects Cobalt Strike Beacon in process memory"
        author = "Ghost Detection Engine"
        threat_level = "critical"
        mitre_attack = "T1055"
        reference = "https://www.cobaltstrike.com/"

    strings:
        // Beacon format strings are ASCII in memory; "wide" alone made these
        // UTF-16-only and therefore unmatchable against real samples.
        $beacon_1 = "%s as %s\\%s: %d" ascii wide
        $beacon_2 = "beacon.dll" ascii wide nocase
        $beacon_3 = "beacon.x64.dll" ascii wide nocase
        $beacon_4 = "Could not connect to pipe (%s): %d" ascii wide

    condition:
        2 of them
}

rule CobaltStrike_Beacon_Config_Block
{
    meta:
        description = "Cobalt Strike beacon config TLV header (plaintext, XOR 0x2e v3.x, XOR 0x69 v4.x)"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "critical"
        mitre_attack = "T1055.001"
        scan_context = "memory_region"

    strings:
        // The config header encodes 16-bit values, so each field needs TWO
        // wildcard bytes. The previous XOR-0x69 pattern had a single wildcard
        // and was therefore misaligned by one byte - it could never match a
        // real beacon. The plaintext and XOR-0x2e (3.x) variants were missing.
        $plain = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 }
        $xor2e = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D 2E 2C }
        $xor69 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B }

    condition:
        any of them
}

rule CobaltStrike_Named_Pipe_Beacon
{
    meta:
        description = "Detects Cobalt Strike default post-exploitation pipe names"
        author = "Ghost Detection Engine"
        date = "2026-08-05"
        threat_level = "high"
        mitre_attack = "T1090"

    strings:
        // Pipe names are ASCII in memory - "wide" alone never matched.
        $pipe_1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe_2 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe_3 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe_4 = "\\\\.\\pipe\\status_" ascii wide

    condition:
        any of them
}

// REMOVED: CobaltStrike_Artifact_Kit_Payload.
// $artifact_2 = { 48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 } is the
// canonical MSVC x64 function prologue, present thousands of times in every
// Microsoft DLL. With "any of them" and threat_level "critical", this rule
// reported critical Cobalt Strike on every process on the machine.
// "ReflectiveLoader" survives in process_injection.yar.
//
// REMOVED: CobaltStrike_Malleable_C2_Profile.
// "Cookie: ", "Accept: */*", "User-Agent: Mozilla/" and a generic
// /word/word URI regex with "3 of them" matches every browser, every HTTP
// client, every updater and curl. Malleable profiles are designed to look
// exactly like ordinary traffic, so profile mimicry is not detectable this
// way; beacon config structure (above) is the reliable signal.
//
// REMOVED: $sleep_mask from CobaltStrike_Beacon_Memory - it was another
// generic MSVC prologue, mislabelled as a sleep-mask signature.
