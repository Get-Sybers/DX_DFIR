"""Suricata lane — replay each PCAP (IDS mode, offline) into EVE JSON.

EVE is already newline-delimited JSON, one event per line. We add ``source_pcap`` +
``tool`` to each line and keep the alert-bearing event types (alert plus the protocol
records that give an alert its context); SURICATA_EVE_ALL keeps the full stream.

Every Suricata ``vars.*`` variable the stock suricata.yaml defines is
CONSOLIDATED in :data:`SURICATA_VARS` — kind, stock default, and whether the
probe pass can automate it. The tuning template is generated from that registry,
so the operator sees the full set in one place, and :func:`derive_vars` fills in
everything automatable from a capture's own traffic.

Tuning comes from an operator-editable TEMPLATE file (default
``data_store/dependencies/suricata-tuning.conf``, INI format — one section per
capture, or ``[global]``). The flow:

  missing file          -> the template is written, then treated as below
  template-only/invalid -> the automatable vars are AUTO-DETECTED per capture
                           (a cheap default-vars pass first) and the derived
                           values are RECORDED into the file for the operator
  real entries          -> used as-is; captures without an entry still
                           auto-detect and get recorded

Tuning is rebuilt from scratch for EVERY capture — a value derived from (or
configured for) one pcap is never carried into the next.
"""
from __future__ import annotations

import configparser
import ipaddress
import json
import os
import subprocess
import tempfile

from .. import container
from . import clean_name

_SURICATA_IMAGE = "dxdfir/suricata:latest"
_WANTED = {"alert", "anomaly", "http", "dns", "tls", "fileinfo", "flow"}

# Ranges that count as "home" when auto-deriving HOME_NET: RFC1918 + CGNAT +
# link-local. EXTERNAL_NET is then the complement (!$HOME_NET).
_PRIVATE_SUPERNETS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16",
]
# Suricata's own default HOME_NET, used as the fallback when a capture shows no
# private address at all (e.g. a public-to-public capture).
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def derive_home_net(ips) -> str:
    """Recommended HOME_NET for a capture, as a Suricata address-group literal
    ``[a,b,...]`` — the private supernets actually observed among ``ips`` (falls back
    to the RFC1918 set when none appear). Pure, so it is unit-testable without a PCAP.

    HOME_NET is Suricata's primary tuning variable: ET/Sigma-style rules key their
    direction off ``$HOME_NET`` / ``$EXTERNAL_NET``, so a HOME_NET that matches the
    capture's real internal range is what makes directional rules fire correctly.
    """
    nets = [ipaddress.ip_network(n) for n in _PRIVATE_SUPERNETS]
    parsed = []
    for ip in ips:
        try:
            parsed.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    seen = [str(net) for net in nets if any(a in net for a in parsed)]
    return "[" + ",".join(seen or _DEFAULT_HOME_NET) + "]"


def var_sets(home_net=None, external_net=None, extra_sets=None) -> list[str]:
    """Suricata ``--set`` values for address-group tuning + any operator passthroughs.
    HOME_NET implies EXTERNAL_NET=!$HOME_NET unless one is given explicitly. Pure."""
    sets: list[str] = []
    if home_net:
        sets.append(f"vars.address-groups.HOME_NET={home_net}")
        sets.append(f"vars.address-groups.EXTERNAL_NET={external_net or '!' + home_net}")
    elif external_net:
        sets.append(f"vars.address-groups.EXTERNAL_NET={external_net}")
    sets.extend(extra_sets or [])
    return sets


# ---- consolidated Suricata variables ---------------------------------------
# Every vars.* entry the stock suricata.yaml defines — the set the bundled/ET
# rules key off — consolidated in ONE place: kind, stock default, and how the
# probe pass automates it (None = operator-only). The tuning template is
# generated from this registry so the operator always sees the full list, and
# derive_vars() fills in everything with an "auto" strategy.
SURICATA_VARS: dict[str, dict] = {
    # address groups
    "HOME_NET":       {"kind": "address", "default": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
                       "auto": "private supernets observed in the capture"},
    "EXTERNAL_NET":   {"kind": "address", "default": "!$HOME_NET",
                       "auto": "complement of the derived HOME_NET"},
    "HTTP_SERVERS":   {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs seen serving HTTP"},
    "SMTP_SERVERS":   {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs seen serving SMTP"},
    "DNS_SERVERS":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs seen answering DNS"},
    "SQL_SERVERS":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving SQL traffic (parser or ports)"},
    "TELNET_SERVERS": {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving telnet traffic"},
    "AIM_SERVERS":    {"kind": "address", "default": "$EXTERNAL_NET",
                       "auto": "external IPs receiving AIM-port traffic (5190)"},
    "DC_SERVERS":     {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving Kerberos traffic"},
    "DNP3_SERVER":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving DNP3 traffic"},
    "DNP3_CLIENT":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs initiating DNP3 traffic"},
    "MODBUS_SERVER":  {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving Modbus traffic"},
    "MODBUS_CLIENT":  {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs initiating Modbus traffic"},
    "ENIP_SERVER":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs receiving ENIP traffic"},
    "ENIP_CLIENT":    {"kind": "address", "default": "$HOME_NET",
                       "auto": "home-side IPs initiating ENIP traffic"},
    # port groups
    "HTTP_PORTS":      {"kind": "port", "default": "80",
                        "auto": "ports where HTTP was actually spoken"},
    "SHELLCODE_PORTS": {"kind": "port", "default": "!80",
                        "auto": "!$HTTP_PORTS once HTTP_PORTS is derived"},
    "SSH_PORTS":       {"kind": "port", "default": "22",
                        "auto": "ports where SSH was actually spoken"},
    "FTP_PORTS":       {"kind": "port", "default": "21",
                        "auto": "ports where FTP was actually spoken"},
    "MODBUS_PORTS":    {"kind": "port", "default": "502",
                        "auto": "ports where Modbus was actually spoken"},
    "DNP3_PORTS":      {"kind": "port", "default": "20000",
                        "auto": "ports where DNP3 was actually spoken"},
    "FILE_DATA_PORTS": {"kind": "port", "default": "[$HTTP_PORTS,110,143]",
                        "auto": "follows the derived HTTP_PORTS by reference"},
    "ORACLE_PORTS":    {"kind": "port", "default": "1521",
                       "auto": "observed traffic on well-known Oracle ports"},
    "GENEVE_PORTS":    {"kind": "port", "default": "6081",
                       "auto": "observed traffic on the well-known port"},
    "VXLAN_PORTS":     {"kind": "port", "default": "4789",
                       "auto": "observed traffic on the well-known port"},
    "TEREDO_PORTS":    {"kind": "port", "default": "3544",
                       "auto": "observed traffic on the well-known port"},
}

# Evidence tables for the derivation engine. Two kinds of evidence per service:
#   apps   Suricata app-layer protocols that positively identify it — seen in
#          protocol events (http/dns/smtp/...) AND flow records' app_proto, so
#          detection is port-independent (HTTP on 8080 is still http)
#   ports  the service's well-known ports, accepted as evidence where no parser
#          exists — traffic a host sends/receives on the port counts
# Address vars take the matching flow's endpoint: the RECEIVING side (dest_ip)
# for *_SERVERS/_SERVER, the INITIATING side (src_ip) for *_CLIENT — filtered
# by scope (home/external) to match the var's stock default.
_SERVER_ADDR_VARS = {
    "HTTP_SERVERS":   {"apps": {"http"}, "ports": set(), "scope": "home"},
    "SMTP_SERVERS":   {"apps": {"smtp"}, "ports": {25, 465, 587}, "scope": "home"},
    "DNS_SERVERS":    {"apps": {"dns"}, "ports": {53}, "scope": "home"},
    "SQL_SERVERS":    {"apps": {"pgsql", "mysql", "tds", "tns"},
                       "ports": {1433, 1434, 3306, 5432, 1521}, "scope": "home"},
    "TELNET_SERVERS": {"apps": {"telnet"}, "ports": {23}, "scope": "home"},
    "AIM_SERVERS":    {"apps": set(), "ports": {5190}, "scope": "external"},
    "DC_SERVERS":     {"apps": {"krb5"}, "ports": {88, 464}, "scope": "home"},
    "DNP3_SERVER":    {"apps": {"dnp3"}, "ports": {20000}, "scope": "home"},
    "MODBUS_SERVER":  {"apps": {"modbus"}, "ports": {502}, "scope": "home"},
    "ENIP_SERVER":    {"apps": {"enip"}, "ports": {44818}, "scope": "home"},
}
_CLIENT_ADDR_VARS = {
    "DNP3_CLIENT":   {"apps": {"dnp3"}, "ports": {20000}, "scope": "home"},
    "MODBUS_CLIENT": {"apps": {"modbus"}, "ports": {502}, "scope": "home"},
    "ENIP_CLIENT":   {"apps": {"enip"}, "ports": {44818}, "scope": "home"},
}
# Port vars derived from where a parsed protocol was actually spoken.
_APP_PORT_VARS = {"http": "HTTP_PORTS", "ssh": "SSH_PORTS", "ftp": "FTP_PORTS",
                  "modbus": "MODBUS_PORTS", "dnp3": "DNP3_PORTS"}
# Port vars with no parser: record the well-known ports that actually carried
# traffic (the observed subset), so rules only watch ports that exist here.
_KNOWN_PORT_VARS = {
    "ORACLE_PORTS": {1521, 1522, 1525, 1529},
    "GENEVE_PORTS": {6081},
    "VXLAN_PORTS": {4789},
    "TEREDO_PORTS": {3544},
}
# Caps: a derivation that would enumerate half the capture is worse than the
# $HOME_NET / stock default it replaces — past these, the var is left unset.
_MAX_SERVER_IPS = 32
_MAX_PORTS = 16


def _port_group(ports: list[int]) -> str:
    return str(ports[0]) if len(ports) == 1 else "[" + ",".join(map(str, ports)) + "]"


def derive_vars(eve_text: str) -> dict[str, str]:
    """Every consolidated Suricata var, derived from one capture's default-vars
    EVE stream — the traffic each host sends and receives, per port:

    - HOME_NET/EXTERNAL_NET from the observed private supernets;
    - address vars from the flow endpoint playing that role (receiver for
      *_SERVERS/_SERVER, initiator for *_CLIENT), where the flow shows parser
      evidence (its app-layer protocol) or well-known-port evidence, filtered
      to the var's home/external scope;
    - *_PORTS from the ports a parsed protocol was actually spoken on (flow
      ``app_proto`` included, so non-standard ports are caught), or — where no
      parser exists — the well-known ports that actually carried traffic.

    Returns {VAR: literal}; a var with nothing observed (or past the caps) is
    omitted so the stock default stands. Pure.
    """
    events = []
    for line in eve_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    ips = {v for ev in events for k in ("src_ip", "dest_ip") if (v := ev.get(k))}
    home = derive_home_net(ips)
    home_nets = [ipaddress.ip_network(n) for n in home[1:-1].split(",")]

    def _is_home(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in home_nets)

    def _in_scope(ip: str, scope: str) -> bool:
        return _is_home(ip) if scope == "home" else not _is_home(ip)

    ports_seen: dict[str, set] = {}
    addrs_seen: dict[str, set] = {}
    for ev in events:
        app = ev.get("event_type")
        if app == "flow":
            app = ev.get("app_proto")
        dport, dip, sip = ev.get("dest_port"), ev.get("dest_ip"), ev.get("src_ip")

        var = _APP_PORT_VARS.get(app)
        if var and isinstance(dport, int):
            ports_seen.setdefault(var, set()).add(dport)
        for var, known in _KNOWN_PORT_VARS.items():
            if dport in known:
                ports_seen.setdefault(var, set()).add(dport)

        for table, endpoint in ((_SERVER_ADDR_VARS, dip), (_CLIENT_ADDR_VARS, sip)):
            for var, spec in table.items():
                if (app in spec["apps"] or dport in spec["ports"]) \
                        and endpoint and _in_scope(endpoint, spec["scope"]):
                    addrs_seen.setdefault(var, set()).add(endpoint)

    out = {"HOME_NET": home, "EXTERNAL_NET": "!$HOME_NET"}
    for var, ports in ports_seen.items():
        if 0 < len(ports) <= _MAX_PORTS:
            out[var] = _port_group(sorted(ports))
    if "HTTP_PORTS" in out:
        # rule convention; FILE_DATA_PORTS follows via its $HTTP_PORTS reference
        out["SHELLCODE_PORTS"] = "!$HTTP_PORTS"
    for var, addrs in addrs_seen.items():
        if 0 < len(addrs) <= _MAX_SERVER_IPS:
            ordered = sorted(addrs, key=lambda ip: (ipaddress.ip_address(ip).version,
                                                    int(ipaddress.ip_address(ip))))
            out[var] = "[" + ",".join(ordered) + "]"
    return out


def vars_to_sets(pinned: dict[str, str]) -> list[str]:
    """{VAR: literal} -> Suricata ``--set`` entries, routed to address-groups or
    port-groups by the registry, in registry order. Pure."""
    sets = []
    for name, meta in SURICATA_VARS.items():
        if name in pinned:
            group = "address-groups" if meta["kind"] == "address" else "port-groups"
            sets.append(f"vars.{group}.{name}={pinned[name]}")
    return sets


# ---- per-pcap tuning file (operator-editable template) ---------------------
_TUNING_KEYS = {name.lower() for name in SURICATA_VARS} | {"sets"}


def template_text() -> str:
    """The pristine tuning template (comments only — no active sections),
    generated from :data:`SURICATA_VARS` so the consolidated variable list in the
    file can never drift from the code."""
    lines = [
        "# Suricata per-PCAP tuning — operator-editable.",
        "#",
        "# One section per capture, named by the capture's path relative to the",
        "# pcap dir with '/' and ' ' folded to '_' (the same key the lane's JSON",
        "# summary uses). A [global] section applies to every capture without its",
        "# own section.",
        "#",
        "# Consolidated variables — every vars.* entry the stock suricata.yaml",
        "# defines. Each is derived ('auto:') from the capture's own traffic —",
        "# parser or well-known-port evidence — when no section pins it, and the",
        "# derived value is recorded below. A section here always wins.",
        "#",
        f"#   {'key':<17} {'stock default':<40} how it is set",
    ]
    for name, meta in SURICATA_VARS.items():
        how = f"auto: {meta['auto']}" if meta["auto"] else "manual"
        lines.append(f"#   {name.lower():<17} {meta['default']:<40} {how}")
    lines += [
        "#",
        "# Any other --set entry goes under 'sets', one per indented line.",
        "#",
        "# Example (delete the leading '# ' to activate):",
        "#   [case1_capture.pcap]",
        "#   home_net = [192.168.0.0/16]",
        "#   http_ports = [80,8080]",
        "#   sets =",
        "#       stream.reassembly.depth=3mb",
        "#",
        "# While a capture has no section here, its auto-derivable vars are",
        "# detected and RECORDED below — edit them and re-run with --force to",
        "# apply. Delete the file to re-detect fresh.",
        "",
    ]
    return "\n".join(lines)


def parse_tuning(text: str) -> dict | None:
    """Parse a tuning file -> {section: {<var>?, ..., extra_sets?}} where <var> is
    any :data:`SURICATA_VARS` name, lowercased.

    Returns ``None`` when the file is not valid — unparseable INI, a key that is
    not a consolidated var (a typo would otherwise be silently ignored), or a
    group value containing whitespace. The caller then falls back to
    auto-detection. A template-only/commented file parses to ``{}``. Pure.
    """
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return None
    entries: dict = {}
    for sec in cp.sections():
        entry: dict = {}
        for key, raw in cp.items(sec):
            if key not in _TUNING_KEYS:
                return None                # unknown key = typo, not a var
            if key == "sets":
                sets = [s.strip() for s in raw.splitlines() if s.strip()]
                if sets:
                    entry["extra_sets"] = sets
            else:
                val = raw.strip()
                if not val or any(c.isspace() for c in val):
                    return None            # a group with whitespace is a typo
                entry[key] = val
        if entry:
            entries[sec] = entry
    return entries


def render_tuning(entries: dict) -> str:
    """Serialize tuning entries back into the template file (header kept, one
    section per capture sorted for a stable diff, vars in registry order). Pure —
    round-trips through :func:`parse_tuning`."""
    lines = [template_text()]
    for sec in sorted(entries):
        entry = entries[sec]
        lines.append(f"[{sec}]")
        for name in SURICATA_VARS:
            key = name.lower()
            if entry.get(key):
                lines.append(f"{key} = {entry[key]}")
        if entry.get("extra_sets"):
            lines.append("sets =")
            lines.extend(f"    {s}" for s in entry["extra_sets"])
        lines.append("")
    return "\n".join(lines)


def _load_tuning(path: str) -> tuple[dict, str]:
    """Read (creating the template if absent) the tuning file.

    Returns (entries, status) with status one of ``created`` (template written),
    ``template`` (no active sections), ``invalid`` (unparseable — entries empty),
    ``ok`` (real entries loaded).
    """
    if not os.path.isfile(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(template_text())
        return {}, "created"
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    entries = parse_tuning(text)
    if entries is None:
        return {}, "invalid"
    return entries, ("template" if not entries else "ok")


def collect_ips(eve_text: str) -> list[str]:
    """Every src_ip/dest_ip seen in an EVE JSON stream — the input to derive_home_net
    for a first (default-vars) pass. Pure."""
    ips = set()
    for line in eve_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        for k in ("src_ip", "dest_ip"):
            v = ev.get(k)
            if v:
                ips.add(v)
    return sorted(ips)


def filter_eve(text: str, source_pcap: str, keep_all: bool = False) -> list[dict]:
    """Filter/annotate an EVE JSON stream. Pure — mirrors the shell's inline PY."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not keep_all and ev.get("event_type") not in _WANTED:
            continue
        ev["source_pcap"] = source_pcap
        ev["tool"] = "suricata"
        out.append(ev)
    return out


def discover(pcap_dir: str) -> list[str]:
    """Every capture under pcap_dir, sorted. Magic bytes first, extension as
    fallback — the zeek processor's own test, so the detection lane replays
    exactly the captures the processor parses (odd extensions included)."""
    from ..zeek import is_pcap
    found = []
    for cur, _dirs, files in os.walk(pcap_dir):
        for name in files:
            p = os.path.join(cur, name)
            if is_pcap(p):
                found.append(p)
    return sorted(found)


def suricata_argv(pcap, out_dir, rules_dir, rules_file, image, sets=None):
    """The ``docker run`` argv for one offline Suricata pass on the hardened
    dxdfir/suricata image (ansible-only execution, allow-listed argv, no caps, no
    network — offline replay needs none). ``sets`` are Suricata ``--set
    key=value`` tuning entries (HOME_NET etc. from ``var_sets``). Pure."""
    args = ["-r", f"/pcaps/{os.path.basename(pcap)}", "-l", "/out", "-k", "none"]
    if rules_file:
        args += ["-S", f"/rules/{os.path.basename(rules_file)}"]
    for entry in (sets or []):
        args += ["--set", entry]
    # suricata (the ENTRYPOINT) writes eve.json to the mounted -l /out; under the
    # read-only rootfs it also touches /var/{run,log}/suricata -> tmpfs.
    return container.run(
        image, args,
        mounts=[f"{os.path.dirname(pcap)}:/pcaps:ro",
                f"{os.path.realpath(rules_dir)}:/rules:ro",
                f"{out_dir}:/out"],
        tmpfs=["/var/run/suricata:rw,nosuid,nodev",
               "/var/log/suricata:rw,nosuid,nodev"],
    )


def _run_suricata(pcap, out_dir, rules_dir, rules_file, image, sets=None):
    subprocess.run(suricata_argv(pcap, out_dir, rules_dir, rules_file, image, sets),
                   capture_output=True, check=False)


def _suricata_pass(pcap, rules_dir, rules_file, image, sets):
    """One Suricata pass into a fresh temp dir; return its raw EVE text ('' on no output)."""
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o777)
        _run_suricata(pcap, tmp, rules_dir, rules_file, image, sets)
        eve = os.path.join(tmp, "eve.json")
        if os.path.isfile(eve) and os.path.getsize(eve) > 0:
            with open(eve, encoding="utf-8", errors="replace") as fh:
                return fh.read()
    return ""


def run(*, output_dir, repo_root, fetch=False, force=False,
        pcap_dir=None, rules_dir=None, image=_SURICATA_IMAGE, keep_all=False,
        home_net=None, external_net=None, extra_sets=None, auto_home_net=False,
        tuning_file=None, **_ignored) -> dict:
    ds = os.path.join(repo_root, "data_store")
    pcap_dir = pcap_dir or os.path.join(ds, "raw", "pcaps")
    rules_dir = rules_dir or os.path.join(ds, "dependencies", "suricata-rules")
    tuning_file = tuning_file or os.path.join(ds, "dependencies", "suricata-tuning.conf")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)

    res = {"lane": "suricata", "produced": 0, "skipped": 0, "failed": 0, "note": None,
           "tuning": {}}

    # --fetch (online only) provisions the ET Open ruleset when the dir has none,
    # the Suricata analogue of the yara lane's DetectRaptor fetch. Best-effort: a
    # failed fetch (air-gapped / upstream down) is a note, never a lane failure —
    # suricata still runs on any bundled rules.
    if fetch:
        from . import suricata_rules
        try:
            res["rules_fetch"] = suricata_rules.fetch(rules_dir)
        except Exception as exc:                       # noqa: BLE001 — best-effort provisioning
            res["rules_fetch"] = {"tool": "et-open", "error": str(exc)}

    rules_file = None
    for cur, _dirs, files in os.walk(rules_dir):
        if "suricata.rules" in files:
            rules_file = os.path.join(cur, "suricata.rules")
            break
    if not rules_file:
        res["note"] = "no suricata.rules — using the image's bundled rules " \
                      "(run with --fetch online to provision ET Open)"

    pcaps = discover(pcap_dir)
    if not pcaps:
        res["note"] = f"no pcaps under {pcap_dir}"
        return res

    # Tuning file (see module docstring): the template is written on first run;
    # a template-only or invalid file means auto-detect + record.
    entries, tstatus = _load_tuning(tuning_file)
    res["tuning_file"] = {"path": tuning_file, "status": tstatus}
    if tstatus == "invalid":
        res["note"] = (f"tuning file {tuning_file} is not valid — auto-detecting; "
                       "the old file is kept beside it as .invalid")
    recorded: dict = {}

    for pcap in pcaps:
        key = clean_name(pcap, pcap_dir)
        out = os.path.join(output_dir, key + ".eve.jsonl")
        if not force and os.path.exists(out) and os.path.getsize(out) > 0:
            res["skipped"] += 1
            continue

        # Tuning is resolved FRESH for every capture — nothing derived from (or
        # configured for) a previous pcap carries over. Precedence: explicit
        # role/CLI home_net > this pcap's file section > [global] > auto-detect
        # (recorded back into the file).
        entry = entries.get(key) or entries.get("global")
        if home_net:
            sets = var_sets(home_net, external_net, extra_sets)
            res["tuning"][key] = {"HOME_NET": home_net, "auto": False, "source": "cli"}
        elif entry:
            pinned = {k.upper(): v for k, v in entry.items() if k != "extra_sets"}
            sets = (vars_to_sets(pinned) + (entry.get("extra_sets") or [])
                    + (extra_sets or []))
            res["tuning"][key] = {"HOME_NET": entry.get("home_net"), "auto": False,
                                  "source": "file", "vars": pinned}
        else:
            probe = _suricata_pass(pcap, rules_dir, rules_file, image,
                                   var_sets(None, external_net, extra_sets))
            derived = derive_vars(probe)
            if external_net:
                derived["EXTERNAL_NET"] = external_net
            sets = vars_to_sets(derived) + (extra_sets or [])
            res["tuning"][key] = {"HOME_NET": derived.get("HOME_NET"), "auto": True,
                                  "source": "auto", "vars": derived}
            recorded[key] = {name.lower(): val for name, val in derived.items()}

        eve_text = _suricata_pass(pcap, rules_dir, rules_file, image, sets)
        if eve_text:
            events = filter_eve(eve_text, os.path.relpath(pcap, repo_root), keep_all)
            with open(out, "w") as w:
                for ev in events:
                    w.write(json.dumps(ev) + "\n")
            res["produced"] += 1
        else:
            res["failed"] += 1

    # Record what auto-detection derived so the operator can inspect/edit it and
    # re-run. An invalid file is preserved beside the fresh one, never lost.
    if recorded:
        if tstatus == "invalid":
            try:
                os.replace(tuning_file, tuning_file + ".invalid")
            except OSError:
                pass
        with open(tuning_file, "w") as fh:
            fh.write(render_tuning({**entries, **recorded}))
        res["tuning_file"]["recorded"] = sorted(recorded)
    return res
