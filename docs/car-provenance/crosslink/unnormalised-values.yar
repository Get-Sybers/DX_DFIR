/*
   ============================================================================
   unnormalised-values.yar  —  DX_DFIR CAR cross-link "value hunt" ruleset
   ============================================================================

   Purpose
   -------
   Operationalises the user goal "use YARA to limit missing non-normalised
   data". Run over ANY processed dataset, these rules flag distinctive,
   forensically-valuable values that are present in raw/native evidence but
   that the pipeline has NOT (yet) lifted into a normalised MITRE CAR field —
   so normalisation gaps get caught systematically instead of by eye.

   Each rule's meta block names, in `car_gap`, the CAR field/object the value
   *should* feed. A hit is a lead: "this record carries an identity/linkage key
   that no CAR column normalises". Rules are triage-grade — several also match
   benign strings; tune before any blocking use.

   Provenance
   ----------
   Consolidated from the ~30 rule stubs and the value-classes described across
   docs/car-provenance/crosslink/{guids,identity,host_ip,ports_serials,
   cmdlines,SUMMARY}.md. Grounded in real values from data_store/processed/
   (a multi-host, multi-scenario evidence tree).

   How to run
   ----------
   The signatures YARA lane loads every *.yar / *.yara under
   data_store/dependencies/yara-rules/ (see docs/Signature-Rules.md). To use
   this ruleset, drop a copy (or symlink) there and run the lane:

       cp docs/car-provenance/crosslink/unnormalised-values.yar \
          data_store/dependencies/yara-rules/
       ansible-playbook playbooks/dxdfir-process-signatures.yml \
          -e '{"dxdfir_signatures_lanes":["yara"]}'

   Matches land in data_store/processed/signatures/yara/{matches,disk,memory}.jsonl.
   Scan targets that carry the most yield: the plaso JSONL timelines, EvtxECmd /
   hayabusa JSON, Volatility piiat.* plugin JSONL, and raw registry/LNK text.

   Compile-checked with YARA 4.5.2 (the dxdfir/yara image). Rule identifiers
   are globally unique (the lane merges every file into one include index).

   Noise classes — intentionally NOT ruled (documented linkage noise)
   ------------------------------------------------------------------
   The crosslink hunt (guids.md) established these GUID families as ubiquitous
   Windows background noise that pollute linkage; they are deliberately omitted,
   and the v1-GUID rule below carries a post-filter note for the last two:
     * COM CLSID / interface IID / TypeLib / AppID GUIDs (e.g. the 118k-hit
       f750e6c3-38ee-11d1-85e5-00c04fc295ee interface IID) — tool/version
       fingerprinting only, never cross-artefact identity.
     * The OLE family  xxxxxxxx-xxxx-xxxx-c000-000000000046  (1,623 distinct).
     * The synthetic-MAC placeholder node  806e6f6e6963  (ASCII "onic") that
       appears in machine-less v1 GUIDs — it is NOT a real NIC MAC.
   Do NOT add rules for these; a hit on any of them is linkage noise, not a gap.

   ============================================================================
   SECTION 1 — GENERAL, REUSABLE RULES  (run against any future dataset)
   ============================================================================
*/

/* ---------------------------------------------------------------------------
   Group A — Host-identity & examiner GUIDs
   (canonical {8-4-4-4-12} GUIDs that CAR keeps only in native text; the CAR
   `guid` join key holds synthetic ids only — 0 canonical of 44,327 values)
   --------------------------------------------------------------------------- */

rule Gap_GUID_MachineGuid_HostIdentity
{
    meta:
        description = "HKLM\\Software\\Microsoft\\Cryptography MachineGuid — the per-host identity join key, present in registry/evtx/filename text but not lifted"
        author      = "dxdfir car-crosslink"
        category    = "host-identity-guid"
        car_gap     = "host.id (per-host anchor; should stamp every CAR row of the image)"
    strings:
        $k  = "Microsoft\\Cryptography" nocase ascii wide
        $v  = "MachineGuid" nocase ascii wide
        $re = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ ascii wide
    condition:
        $k and $v and $re
}

rule Gap_GUID_NetworkInterface_Identity
{
    meta:
        description = "Tcpip\\Parameters\\Interfaces\\{GUID} / NetworkList profile GUID — binds a NIC to its IP/DHCP-lease/SSID profile"
        author      = "dxdfir car-crosslink"
        category    = "host-identity-guid"
        car_gap     = "flow / socket NIC identity (network-identity join key; unmapped)"
    strings:
        $if = "Tcpip\\Parameters\\Interfaces" nocase ascii wide
        $nl = "NetworkList\\Profiles" nocase ascii wide
        $g  = /\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ ascii wide
    condition:
        ($if or $nl) and $g
}

rule Gap_GUID_Sysmon_ProcessLineage
{
    meta:
        description = "Sysmon ProcessGuid / ParentProcessGuid / LogonGuid — native process+logon lineage that never reaches CAR (hayabusa drops it entirely)"
        author      = "dxdfir car-crosslink"
        category    = "host-identity-guid"
        car_gap     = "process.entity_id / parent_guid / user_session login (map from the evtx->CAR projection)"
    strings:
        $pg  = "ProcessGuid" nocase ascii wide
        $ppg = "ParentProcessGuid" nocase ascii wide
        $lg  = "LogonGuid" nocase ascii wide
        $re  = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ ascii wide
    condition:
        any of ($pg, $ppg, $lg) and $re
}

rule Gap_GUID_ScheduledTask_Persistence
{
    meta:
        description = "TaskCache\\Tasks|Tree {GUID} — links a scheduled task's definition, tree entry and action (persistence linkage)"
        author      = "dxdfir car-crosslink"
        category    = "host-identity-guid"
        car_gap     = "service / scheduled-task object (persistence; unmapped)"
    strings:
        $tc = "TaskCache" nocase ascii wide
        $g  = /\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ ascii wide
    condition:
        $tc and $g
}

rule Gap_GUID_AntiForensic_ImagingTool
{
    meta:
        description = "Forensic/imaging-tool activity (FTK Imager temp {GUID} dir, AccessData) — examiner/anti-forensic marker"
        author      = "dxdfir car-crosslink"
        category    = "host-identity-guid"
        car_gap     = "flag-only marker (exclude from evidentiary linkage; not a CAR field)"
    strings:
        $ftk = "FTK Imager" nocase ascii wide
        $ftk2= "FTK_Imager" nocase ascii wide
        $ad  = "AccessData" nocase ascii wide
        $tmp = /Temp\\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ nocase ascii wide
    condition:
        ($ftk or $ftk2 or $ad) and $tmp
}

/* ---------------------------------------------------------------------------
   Group B — Volume / mount identity
   --------------------------------------------------------------------------- */

rule Gap_GUID_Volume_MountKey
{
    meta:
        description = "\\?\\Volume{GUID} / MountPoints2 / MountedDevices volume identity — best cross-source key on a disk (USN<->evtx<->registry<->cloud-sync<->mount)"
        author      = "dxdfir car-crosslink"
        category    = "volume-mount"
        car_gap     = "volume id join key (should be a first-class CAR field; converges 6 data_types on real data)"
    strings:
        $vol = /Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/ nocase ascii wide
        $mp2 = "MountPoints2" nocase ascii wide
        $md  = "MountedDevices" nocase ascii wide
    condition:
        $vol and ($mp2 or $md or #vol > 1)
}

rule Gap_Volume_Serial_Field
{
    meta:
        description = "Volume/drive serial carried in a native field (LNK drive_serial_number, VolumeSerialNumber) — the only field that names the physical device"
        author      = "dxdfir car-crosslink"
        category    = "volume-mount"
        car_gap     = "device/volume serial (no serial column exists on CAR file/registry)"
    strings:
        $f1 = "drive_serial_number" nocase ascii wide
        $f2 = "VolumeSerialNumber" nocase ascii wide
        $f3 = "volume_serial" nocase ascii wide
    condition:
        any of ($f*)
}

/* ---------------------------------------------------------------------------
   Group C — MAC-bearing version-1 GUIDs
   --------------------------------------------------------------------------- */

rule Gap_GUID_V1_MAC_Embedded
{
    meta:
        description = "Version-1 (time/MAC) GUID — trailing node bytes leak the originating NIC MAC (DLT birth-droids, v1 volume/interface GUIDs)"
        author      = "dxdfir car-crosslink"
        category    = "mac-bearing-v1-guid"
        car_gap     = "mac_address (decode the v1 node into a MAC field)"
        post_filter = "YARA regex has no lookaround; DROP the OLE family node 000000000046 and the synthetic placeholder node 806e6f6e6963 downstream — they are NOT real NIC MACs (see noise note)"
    strings:
        // 3rd group starts with '1' => RFC-4122 version 1 (time/MAC based).
        $v1 = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-1[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ ascii wide
    condition:
        $v1
}

/* ---------------------------------------------------------------------------
   Group D — Network 5-tuple (IPv4 / IPv6 / MAC / hostname / port)
   CAR has flow/socket/http columns but nothing populates them here; every
   IP/MAC/domain/port in the tree survives only in raw/native form.
   The GENERIC_* rules are high-noise un-anchored discovery rules — enable
   deliberately for triage; validate hits downstream.
   --------------------------------------------------------------------------- */

rule Gap_Net_IPv4_Address
{
    meta:
        description = "Any dotted-quad IPv4 (octet-validated). High-noise discovery rule — validate hits"
        author      = "dxdfir car-crosslink"
        category    = "network-5tuple"
        car_gap     = "flow.src_ip/dest_ip, socket local/remote (CAR IP columns unpopulated)"
    strings:
        $ipv4 = /\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b/ ascii wide
    condition:
        $ipv4
}

rule Gap_Net_IPv6_Address
{
    meta:
        description = "IPv6 incl. compressed :: forms. High-noise discovery rule — validate hits"
        author      = "dxdfir car-crosslink"
        category    = "network-5tuple"
        car_gap     = "flow.src_ip/dest_ip (CAR IP columns unpopulated)"
    strings:
        $ipv6 = /([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,4}/ ascii wide
    condition:
        $ipv6
}

rule Gap_Net_MAC_Address
{
    meta:
        description = "48-bit MAC, colon or hyphen separated. Guard against date-like FPs (e.g. 24-02-14-06-36-46) downstream"
        author      = "dxdfir car-crosslink"
        category    = "network-5tuple"
        car_gap     = "mac_address (no MAC column exists anywhere in CAR)"
    strings:
        $mac = /\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/ ascii wide
    condition:
        $mac
}

rule Gap_Net_Windows_Hostname_NetBIOS
{
    meta:
        description = "DESKTOP-/WIN-/WS-/SRV-/BGP-style NetBIOS names for host discovery"
        author      = "dxdfir car-crosslink"
        category    = "network-5tuple"
        car_gap     = "host.name (per-host anchor; unmapped for disk/log/zeek lanes)"
    strings:
        $nb = /\b(DESKTOP|WIN|WS|SRV|BGP)-[A-Z0-9]{3,15}\b/ ascii wide nocase
    condition:
        $nb
}

rule Gap_Net_Firewall_And_Flow_Ports
{
    meta:
        description = "Ports buried in FirewallPolicy REG_SZ rule strings (|LPort=/|RPort=) and notable flow ports — invisible to any structured port field"
        author      = "dxdfir car-crosslink"
        category    = "network-5tuple"
        car_gap     = "socket.local_port/remote_port, flow.src_port/dest_port (columns empty)"
    strings:
        $fw_l = /\|LPort=(3702|1900|2177|2869|135|445|3540|5355|5357|5358|23554|23555|23556|9955)\b/ ascii wide
        $fw_r = /\|RPort=(1900|2177|2869|3702|137|138|547|67)\b/ ascii wide
        // SSH on an IPv4 endpoint (x.x.x.x:22) — reuses the octet-validated
        // IPv4 pattern from Gap_Net_IPv4_Address (0-255 per octet) with a leading
        // \b, so it is NOT a bare ":22" substring of an IPv6 address (::22), a
        // larger port (:220) or a timestamp (12:22), and never matches an invalid
        // dotted-quad like 999.999.999.999
        $ssh  = /\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}:22\b/ ascii wide
    condition:
        $fw_l or $fw_r or $ssh
}

/* ---------------------------------------------------------------------------
   Group E — Device serials (USB / removable media)
   --------------------------------------------------------------------------- */

rule Gap_Device_USB_Serial
{
    meta:
        description = "USB iSerialNumber via USBSTOR / setupapi / DeviceClasses (Ven_/Prod_ instance key) — the physical-device key tying insert-timeline to enumeration"
        author      = "dxdfir car-crosslink"
        category    = "device-serial"
        car_gap     = "device serial (no CAR device/serial field)"
    strings:
        $usbstor = "USBSTOR" nocase ascii wide
        $ven     = /Ven_[A-Za-z0-9]+&Prod_/ nocase ascii wide
        $inst    = /USBSTOR#Disk&Ven_[^#\x00]+#[A-Za-z0-9]{8,}/ nocase ascii wide
    condition:
        $usbstor and ($ven or $inst)
}

/* ---------------------------------------------------------------------------
   Group F — Account / SID identity
   Disk plaso native `username` is "-" on 99.999% of rows, yet SIDs and
   \Users\<name>\ paths are everywhere; CAR file/registry rows carry no identity.
   --------------------------------------------------------------------------- */

rule Gap_Windows_SID_Any
{
    meta:
        description = "Any Windows SID (well-known + domain/machine with RID) buried in evtx <strings>/xml, registry key_paths (HKU\\<SID>, BAM UserSettings\\<SID>), fs:stat security descriptors, app logs"
        author      = "dxdfir car-crosslink"
        category    = "account-sid-identity"
        car_gap     = "user / uid / sid (null on CAR file+registry rows; absent for disk/evtx lanes)"
    strings:
        $sid_domain    = /S-1-5-21(-[0-9]{1,10}){3}-[0-9]{1,7}/ ascii wide
        $sid_wellknown = /S-1-5-(18|19|20)\b/ ascii wide
    condition:
        $sid_domain or $sid_wellknown
}

rule Gap_Windows_UserProfilePath
{
    meta:
        description = "\\Users\\<name>\\ profile paths — the disk-side identity convergence key (shellbags, LNK, jumplists, chrome, drive-sync, fs:stat). Excludes Public/Default/All Users"
        author      = "dxdfir car-crosslink"
        category    = "account-sid-identity"
        car_gap     = "user (account-in-path; unmapped on disk)"
    strings:
        $any_user   = /[\\\/]Users[\\\/][A-Za-z][A-Za-z0-9_.\- ]{1,32}[\\\/]/ nocase ascii wide
        $not_public = /[\\\/]Users[\\\/](Public|Default|Default User|All Users)[\\\/]/ nocase ascii wide
    condition:
        $any_user and not $not_public
}

rule Gap_Linux_Identity_Present
{
    meta:
        description = "Linux login identity (utmp/wtmp/ssh) — usernames present in native records but no Linux->CAR lane exists, so 100% unmined"
        author      = "dxdfir car-crosslink"
        category    = "account-sid-identity"
        car_gap     = "user / user_session (no Linux CAR lane)"
    strings:
        $ssh  = "syslog:ssh:login" ascii wide
        $utmp = "linux:utmp:event" ascii wide
    condition:
        $ssh or $utmp
}

/* ---------------------------------------------------------------------------
   Group G — Command-line obfuscation / C2 / LOLBin
   CAR command_line holds argv for memory-host processes only; services(634),
   LNK(350), Run(31), .job(4), RunMRU(65) and every Sysmon EID1 argv are stranded.
   [O] = grounded in an observed hit; [P] = proactive class stub. Triage-grade.
   --------------------------------------------------------------------------- */

rule Gap_CMD_EnvVar_CharSub_Obfuscation
{
    meta:
        description = "[O] DOSfuscation: mass single-char SET-var alphabet builder then %var%%var% expansion (observed decoding to a flag{...} on DESKTOP-M913391 Sysmon EID1)"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line (Sysmon-host argv absent from CAR)"
    strings:
        $set_run = /(&&set [A-Za-z]{6,12}=.){20,}/ ascii wide
        $cmd     = "cmd /c" nocase ascii wide
        $expand  = /(%%?[A-Za-z]{6,12}%%?){15,}/ ascii wide
    condition:
        $cmd and ($set_run or $expand)
}

rule Gap_CMD_MissingSpace_TokenConcat
{
    meta:
        description = "[O] cmd.exe missing-space / caret / token-concatenation anomaly (mirrors Hayabusa 'Cmd.EXE Missing Space Characters Execution Anomaly')"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line"
    strings:
        $a = /cmd(\.exe)?["' ]{0,2}\/c["' ]{0,2}[%^]/ nocase ascii wide
        $b = "&&set " nocase ascii wide
        $c = /\^[a-z]/ nocase ascii wide
    condition:
        $a and ($b or #c > 5)
}

rule Gap_CMD_Exec_From_User_Temp_Or_Downloads
{
    meta:
        description = "[O] Executable/script run from user-writable Downloads or Temp (observed: s3browser installer from Downloads->Temp\\IS-*.TMP, GoogleUpdate from Temp\\GUME*.tmp)"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line / file (LNK args + prefetch/amcache paths, unmapped)"
    strings:
        $p1 = /\\Users\\[^\\]+\\Downloads\\[^\\"]+\.(exe|tmp|scr|com|ps1|bat|cmd)/ nocase ascii wide
        $p2 = /\\Users\\[^\\]+\\AppData\\Local\\Temp\\[^"]+\.(exe|tmp|dll|scr)/ nocase ascii wide
        $p3 = /\\Windows\\TEMP\\[^"]+\.(exe|tmp)/ nocase ascii wide
    condition:
        any of them
}

rule Gap_CMD_Svchost_Missing_ServiceGroup
{
    meta:
        description = "[P/O] svchost.exe with no -k <group> argument — legit svchost here always carries -k <group>; a bare svchost is suspect (evaluate per command-line record)"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line / service.command_line"
    strings:
        $svc    = /svchost\.exe/ nocase ascii wide
        $dash_k = /svchost\.exe"?\s+-k\s+[A-Za-z]/ nocase ascii wide
    condition:
        $svc and not $dash_k
}

rule Gap_CMD_Suspicious_Flags
{
    meta:
        description = "[P] Known-bad command flags: encoded/hidden PowerShell, in-memory download, LOLBin remote fetch (proactive class stub — benign PS in this dataset)"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line"
    strings:
        $enc1 = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ nocase ascii wide
        $enc2 = "-w hidden" nocase ascii wide
        $enc3 = "FromBase64String" nocase ascii wide
        $dl1  = "DownloadString" nocase ascii wide
        $dl2  = "DownloadFile" nocase ascii wide
        $dl3  = /Invoke-(Expression|WebRequest)/ nocase ascii wide
        $lol1 = /(certutil|bitsadmin|mshta|regsvr32|rundll32)\b.{0,80}(http|\\\\|\/urlcache|javascript:)/ nocase ascii wide
    condition:
        any of them
}

rule Gap_CMD_Silent_RecursiveDelete
{
    meta:
        description = "[O] silent recursive-delete cmd wrapper (observed autoruns Run key cmd /q /c rmdir /s /q ...; benign here but a common wiper/cleanup idiom)"
        author      = "dxdfir car-crosslink"
        category    = "cmdline-obfuscation-c2-lolbin"
        car_gap     = "process.command_line (Run/RunOnce argv, unmapped)"
    strings:
        $a = /cmd(\.exe)?\s+\/q\s+\/c\s+rmdir\s+\/s\s+\/q/ nocase ascii wide
        $b = /cmd(\.exe)?\s+\/c\s+del\s+\/f\s+\/q/ nocase ascii wide
    condition:
        any of them
}

/*
   ============================================================================
   SECTION 2 — CASE-SPECIFIC HUNT  (EXAMPLE — REPLACE PER CASE)
   ============================================================================
   The concrete constants below are the anchors of THIS worked dataset (the
   LoneWolf / memory / Sysmon / 5g-webui / Zeek grab-bag). They are kept as a
   worked example of how to pin a case's identity/linkage constants for a
   retro-sweep across any future acquisition. DELETE or REPLACE this whole
   section per engagement — the Section 1 rules above are the reusable part.
   ============================================================================
*/

rule HUNT_Case_LoneWolf_DESKTOP_PM6C56D
{
    meta:
        description = "LoneWolf host DESKTOP-PM6C56D / jcloudy identity constants (MachineGuid, main volume GUID, DLT droid, NIC MAC, hostname)"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "host.id / volume id / mac_address (example constants)"
    strings:
        $machine = "8b9b9f31-6016-4b10-83ef-324b62a37898" nocase ascii wide
        $vol     = "09931f21-7faf-44a9-81d8-1e73c14b9eaf" nocase ascii wide
        $droid   = "5c2307d9-3369-11e2-be70-001cc42df40b" nocase ascii wide
        $mac_txt = "00:1c:c4:2d:f4:0b" nocase ascii wide
        $mac_raw = { 00 1C C4 2D F4 0B }
        $host    = "DESKTOP-PM6C56D" nocase ascii wide
    condition:
        any of them
}

rule HUNT_Case_MachineSIDs
{
    meta:
        description = "The dataset's per-host machine SIDs — pin an artefact to a specific host"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "user/uid/sid + host anchor (example constants)"
    strings:
        $h_pm6c56d = "S-1-5-21-2734969515-1644526556-1039763013" ascii wide   // LoneWolf disk (jcloudy)
        $h_memdump = "S-1-5-21-2899045035-919344695-3383792992"  ascii wide   // memory host
        $h_m913391 = "S-1-5-21-3081547798-3199192215-1922722758" ascii wide   // Sysmon host (JDH)
    condition:
        any of them
}

rule HUNT_Case_Hostnames
{
    meta:
        description = "The four named hosts across disk/memory/log artefacts"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "host.name (example constants)"
    strings:
        $h1 = "DESKTOP-PM6C56D" ascii wide nocase   // LoneWolf disk
        $h2 = "5g-webui"        ascii wide nocase   // Linux disk
        $h3 = "BGP-WS1-CONF"    ascii wide nocase   // memory dump
        $h4 = "DESKTOP-M913391" ascii wide nocase   // Sysmon logs
    condition:
        any of them
}

rule HUNT_Case_Berylia_C2_Domains
{
    meta:
        description = "berylia.org exercise domains — disk<->network bridge & C2 (scoring-c2)"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "http.host / ssl SNI / x509 subject (example constants)"
    strings:
        $d1 = "berylia.org"                     ascii wide nocase
        $d2 = "scoring-c2.berylia.org"          ascii wide nocase   // C2
        $d3 = "dfir-rt-web02.berylia.org"       ascii wide nocase
        $d4 = "5g-webui.sac.baf.10.berylia.org" ascii wide nocase
        $d5 = "confidential.baf.27.berylia.org" ascii wide nocase
    condition:
        any of them
}

rule HUNT_Case_Network_IP_Anchors
{
    meta:
        description = "Convergence IPv4/IPv6: DNS 100.95.95.4 / 2a07:1181:95:95::4 link memory<->zeek; BGP-WS1-CONF static IP/GW; zeek C2 client & uploader"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "flow.src_ip/dest_ip (example constants)"
    strings:
        $ip_dns  = "100.95.95.4"          ascii wide            // DNS: memory reg + zeek
        $ip_bgp  = "10.27.32.51"          ascii wide            // BGP-WS1-CONF static IP
        $ip_gw   = "10.27.32.1"           ascii wide            // BGP-WS1-CONF gateway
        $ip_cli  = "10.27.33.61"          ascii wide            // zeek C2-beacon client
        $ip_c2   = "100.101.0.42"         ascii wide            // scoring-c2 resolved IP
        $ip_up   = "100.100.250.37"       ascii wide            // ME_FOR_1308 uploader
        $v6_dns  = "2a07:1181:95:95::4"   ascii wide nocase     // DNS memory+zeek
        $v6_cli  = "2a07:1182:27:33::61"  ascii wide nocase     // zeek client
    condition:
        any of them
}

rule HUNT_Case_MAC_Anchors
{
    meta:
        description = "Creator/gateway/VMware NIC MACs recovered from DLT ObjectIDs, volume-GUID nodes, NetworkList gateway and zeek IPv6 EUI-64 link-locals"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "mac_address (example constants)"
    strings:
        $m1_txt  = "ec:f4:bb:48:7f:ed" nocase ascii wide   // DLT + volume-GUID node
        $m1_raw  = { EC F4 BB 48 7F ED }
        $m2_txt  = "28:e3:47:01:77:77" nocase ascii wide
        $m2_raw  = { 28 E3 47 01 77 77 }
        $m3_txt  = "00:1c:c4:2d:f4:0b" nocase ascii wide   // PowerShell.lnk creator
        $m3_raw  = { 00 1C C4 2D F4 0B }
        $m4_txt  = "ec:0e:c4:20:7f:0e" nocase ascii wide
        $m4_raw  = { EC 0E C4 20 7F 0E }
        $gw_txt  = "5c:8f:e0:2a:1c:68" nocase ascii wide   // NetworkList gateway
        $gw_raw  = { 5C 8F E0 2A 1C 68 }
        $vm1     = "00:50:56:89:a2:69" nocase ascii wide                                      // VMware vNIC (zeek)
        $vm2     = "00:50:56:89:ab:90" nocase ascii wide
        $vm3     = "00:50:56:89:b3:ff" nocase ascii wide                                      // 5g-webui vNIC
        $vm4     = "00:50:56:89:34:cf" nocase ascii wide
        $volguid = "3869c27a-31b8-11e8-9b12-ecf4bb487fed" ascii wide nocase                   // node = ec:f4:bb:48:7f:ed
    condition:
        any of them
}

rule HUNT_Case_Volume_Serials
{
    meta:
        description = "LoneWolf volume serials: removable 'CloudLog' 4C36-F4AC (holds key.txt), fixed C: AA92-0881, OSDisk 74EE-2D73"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "device/volume serial (example constants)"
    strings:
        // CloudLog (removable)
        $cl_le  = { AC F4 36 4C }
        $cl_a   = "4C36-F4AC" nocase ascii wide
        $cl_d   = "1278669996" ascii wide
        // C:
        $c_le   = { 81 08 92 AA }
        $c_a    = "AA92-0881" nocase ascii wide
        $c_d    = "2861697153" ascii wide
        // OSDisk
        $os_le  = { 73 2D EE 74 }
        $os_a   = "74EE-2D73" nocase ascii wide
        $os_d   = "1961766259" ascii wide
        $label  = "CloudLog" ascii wide nocase
    condition:
        any of them
}

rule HUNT_Case_USB_SanDisk_Serials
{
    meta:
        description = "SanDisk Extreme USB iSerialNumbers — USBSTOR / setupapi / DeviceClasses (2,470x refs)"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "device serial (example constants)"
    strings:
        $u1  = "AA010215170355310594" ascii wide nocase
        $u2  = "AA010603160707470215" ascii wide nocase
        $ven = "Ven_SanDisk&Prod_Extreme" ascii wide nocase
    condition:
        any of them
}

rule HUNT_Case_Named_Accounts
{
    meta:
        description = "Distinctive named accounts in this dataset; 'gt' is the cross-host pivot (memory Windows host RID 1000 <-> 5g-webui Linux utmp)"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "user (example constants)"
    strings:
        $a1 = /\bjcloudy\b/ nocase ascii wide
        $a2 = /\bdefaultuser0\b/ nocase ascii wide
        $a3 = /\bscoringbot\b/ nocase ascii wide
        $a4 = /\bJDH\b/ ascii wide
        $a5 = /\bLS23_BT10\b/ ascii wide
        $a6 = /\bgt\b/ ascii wide                 // cross-host pivot
    condition:
        any of them
}

rule HUNT_Case_AntiForensic_FTK_GUID
{
    meta:
        description = "FTK Imager 4.7.1 temp dir GUID on the memory host (examiner activity marker)"
        author      = "dxdfir car-crosslink"
        category    = "case-specific-hunt"
        car_gap     = "flag-only marker (example constant)"
    strings:
        $g = "787A8B0F-B810-41D6-BA41-4289DB167E05" nocase ascii wide
    condition:
        $g
}
