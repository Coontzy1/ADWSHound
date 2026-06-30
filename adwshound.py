#!/usr/bin/env python3
"""ADWSHound — BloodHound data collector using ADWS instead of LDAP.

Usage examples:
  python3 adwshound.py -c All -d domain.local -u user -p pass --domaincontroller 10.0.0.1
  python3 adwshound.py --CollectionMethods Default -d domain.local -u user --hashes :NTHASH
  python3 adwshound.py -c DCOnly -d domain.local -u user -p pass
"""
from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import sys
from pathlib import Path
from typing import Optional

# ─── Logging setup ────────────────────────────────────────────────────────────

def _setup_logging(verbosity: int) -> None:
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, len(levels) - 1)]
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )
    # impacket logs struct-unpack failures (malformed SAMR/LSA replies from
    # flaky hosts) at ERROR on its own logger; we already catch those per-host,
    # so suppress the duplicate spam.
    logging.getLogger("impacket").setLevel(logging.CRITICAL)

log = logging.getLogger("adwshound")


def _say(msg: str) -> None:
    """Always-on status line (shown regardless of -v level)."""
    print(msg, flush=True)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adwshound",
        description="BloodHound AD collector via ADWS (port 9389) — no LDAP required",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Collection methods (comma-separated, case-insensitive):
  All              Everything
  Default          Group,LocalGroup,GPOLocalGroup,Session,LoggedOn,Trusts,ACL,
                   Container,ObjectProps,UserRights
  DCOnly           Group,LocalGroup,GPOLocalGroup,LoggedOn,Trusts,ACL,
                   Container,ObjectProps,UserRights  (no remote computer connections)
  ComputerOnly     Session,LocalAdmin,RDP,DCOM,PSRemote

  Object collection:
    Group            Group memberships
    LocalGroup       Local groups via SAMR (all: Admins/RDP/DCOM/PSRemote)
    LocalAdmin       Alias for LocalGroup
    GPOLocalGroup    Local groups from GPO XML on SYSVOL (DC only)
    Session          Active sessions via NetSessionEnum
    LoggedOn         Logged-on users via registry + NetWkstaUserEnum
    Trusts           Domain trust relationships
    ACL              Access control entries from nTSecurityDescriptor
    Container        OUs, containers, GPO links, DN hierarchy
    ObjectProps      Extended object properties
    SPNTargets       Kerberoastable accounts + SPN-to-computer mapping
    RDP              Remote Desktop Users local group
    DCOM             DCOM Users local group
    PSRemote         PowerShell Remote Users local group
    UserRights       LSA privilege assignments (SeTcbPrivilege etc.)

  Certificate Services (ADCS):
    CertServices     All ADCS objects: RootCA, AIACA, EnterpriseCA, NTAuthStore,
                     CertTemplate, IssuancePolicy
    CARegistry       EnterpriseCA registry: ManageCA/ManageCerts ACEs, ESC6 flag,
                     role separation, enrollment agent restrictions
    DCRegistry       DC registry: cert mapping, Netlogon SD (Zerologon check)
    LdapServices     LDAP signing + channel binding (DC only)

  Host checks (require remote connectivity):
    SmbInfo          SMB signing + SMBv1 status
    WebClientService WebClient service running status
    NTLMRegistry     NTLM LM compat level + hash policy

OPSEC tiers (least to most noisy):
  1. -c Group,Trusts,ACL,Container,ObjectProps --opsec
       ADWS port 9389 only. No SMB. No remote computer connections.
       Collects: Groups, Users, Computers (ADWS), OUs, Containers, GPOs, Trusts, ACLs.

  2. -c DCOnly --stealth --opsec
       Adds SMB port 445 to DC (reads GPO XML from SYSVOL).
       GPOLocalGroup added by --stealth. LoggedOn/UserRights stripped by --stealth.

  3. -c Default --opsec
       Adds connections to ALL domain computers:
         Session (NetSessionEnum), LoggedOn (registry + NetWkstaUserEnum),
         UserRights (LSA), LocalGroup (SAMR).

  4. -c All --opsec
       Maximum data. Adds RDP/DCOM/PSRemote SAMR, ADCS CA registry,
       WebClientService, SmbInfo, NTLMRegistry, LdapServices (DCs).

Note: --stealth strips Session, LoggedOn, LocalGroup, RDP, DCOM, PSRemote from
any mask — it does NOT add LoggedOn/UserRights; it removes them.

Auth / logon footprint:
  By default ADWS reuses ONE authenticated connection for the whole run (one NTLM
  logon instead of one per query) — this avoids account lockout from logon volume.
  Use --no-reuse to revert to one connection per query.
  -k / --kerberos makes the remote SMB/MSRPC collectors authenticate via Kerberos
  (no NTLM 4776 events on hosts; blends with normal AD traffic). The ADWS transport
  itself still uses NTLM (a single logon thanks to reuse), so a password or --hashes
  is still required even with -k. Kerberos needs the target reachable by FQDN and a
  KDC (--dc-host); for member hosts ADWSHound already targets dNSHostName.

--opsec rewrites LDAP filters before transmission:
  Attribute names  → left as-is (ADWS requires readable names; OIDs return empty)
  Alpha values     → LDAP hex escape, * wildcards preserved
                     computer  → \\63\\6f\\6d\\70\\75\\74\\65\\72
  Numeric values   → left as-is (e.g. sAMAccountType=805306368); ADWS won't match
                     hex-escaped digits, and a bare number is a weak signature
  Extensible-match (attr:oid:=N) values left intact.
""",
    )

    # Connection
    conn = p.add_argument_group("Connection")
    conn.add_argument("-d", "--domain", metavar="DOMAIN",
                      help="Target domain FQDN (auto-detected from local host FQDN if omitted)")
    conn.add_argument("--domaincontroller", "--dc", metavar="IP/FQDN",
                      help="Domain controller IP or FQDN (auto-resolved via SRV DNS if omitted)")
    conn.add_argument("-u", "--ldapusername", metavar="USER",
                      help="Username for ADWS authentication")
    conn.add_argument("-p", "--ldappassword", metavar="PASS",
                      help="Password (prompted interactively if omitted and no --hashes)")
    conn.add_argument("--hashes", metavar="LM:NT",
                      help="Pass-the-hash authentication (format: LM:NT or :NT)")
    conn.add_argument("-k", "--kerberos", action="store_true",
                      help="Use Kerberos end-to-end (ADWS transport + remote SMB/MSRPC collectors); "
                           "no NTLM. TGT from $KRB5CCNAME (kinit/getTGT.py); use --dc-host FQDN.")
    conn.add_argument("--aesKey", dest="aes_key", metavar="HEX", default="",
                      help="AES128/256 key for Kerberos (implies -k)")
    conn.add_argument("--dc-host", dest="dc_host", metavar="FQDN",
                      help="KDC / DC hostname (FQDN) for Kerberos ticket requests")
    conn.add_argument("--nameserver", "--dns-server", dest="nameserver", metavar="IP",
                      help="DNS server for resolving target hostnames "
                           "(default: the domain controller). Use when the host "
                           "is not configured to use the AD DNS.")

    # Collection
    col = p.add_argument_group("Collection")
    col.add_argument("-c", "--CollectionMethods",
                     default="Default", metavar="METHODS",
                     help="Comma-separated collection methods (default: Default)")
    col.add_argument("--stealth", action="store_true",
                     help="Strip all remote computer methods; DC-only ADWS + GPOLocalGroup")
    col.add_argument("--searchforest", action="store_true",
                     help="Discover and enumerate all domains in the forest via crossRef")
    col.add_argument("--recursedomains", action="store_true",
                     help="Follow domain trusts recursively, collecting each reachable trusted domain")
    col.add_argument("--excludedcs", action="store_true",
                     help="Exclude domain controllers from computer-targeted collection")
    col.add_argument("--computerfile", metavar="FILE",
                     help="Restrict remote collection to computers listed in FILE (one per line)")
    col.add_argument("--collectallproperties", action="store_true",
                     help="Request all LDAP attributes (*) instead of the curated set")
    col.add_argument("--skipportcheck", action="store_true",
                     help="Skip TCP:445 connectivity probe before remote computer collection")
    col.add_argument("--skipregistryloggedon", action="store_true",
                     help="Skip registry-based logged-on session enumeration (reduces noise)")
    col.add_argument("--opsec", action="store_true",
                     help="Obfuscate LDAP filters: alpha values hex-escaped (names/numbers unchanged)")
    col.add_argument("--no-reuse", dest="no_reuse", action="store_true",
                     help="Open a fresh ADWS connection per query (default: reuse one — far fewer logons)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--outputdirectory", metavar="DIR", default=".",
                     help="Directory for output files (default: current directory)")
    out.add_argument("--outputprefix", metavar="PREFIX", default="",
                     help="String prepended to all output filenames")
    out.add_argument("--nozip", action="store_true",
                     help="Write JSON files only, skip ZIP creation")
    out.add_argument("--zippassword", metavar="PASS",
                     help="AES-encrypt the output ZIP with this password (requires pyzipper)")
    out.add_argument("--prettyprint", action="store_true",
                     help="Indent JSON output (larger files, easier to read)")

    # Performance
    perf = p.add_argument_group("Performance")
    perf.add_argument("-t", "--threads", type=int, default=10,
                      help="Threads for remote (non-ADWS) collection (default: 10)")
    perf.add_argument("--throttle", type=int, default=0, metavar="MS",
                      help="Sleep N milliseconds between ADWS pull batches")
    perf.add_argument("--jitter", type=int, default=0, metavar="PCT",
                      help="Add up to PCT%% random jitter on top of --throttle delay")

    # Misc
    p.add_argument("-v", "--verbosity", action="count", default=0,
                   help="Increase verbosity: -v = INFO, -vv = DEBUG")
    p.add_argument("--version", action="version", version="ADWSHound 1.0.0")

    return p


# ─── Collection logic ─────────────────────────────────────────────────────────

def _resolve_dc(domain: str) -> str:
    """Resolve domain name to a DC IP via DNS SRV record."""
    import socket
    try:
        # Try _ldap._tcp SRV record
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(f"_ldap._tcp.{domain}", "SRV")
        return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    # Fall back to simple hostname resolution
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return domain


def _looks_like_ip(host: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def _ensure_kerberos_ccache(username, domain, password, hashes, aes_key, kdc_host) -> bool:
    """For -k: if no usable ccache, request a TGT from creds and stage it in $KRB5CCNAME.

    Returns True if a ccache is available (pre-existing or freshly obtained). With a
    valid KRB5CCNAME already set we leave it alone (user did kinit/getTGT.py).
    """
    import os
    existing = os.environ.get("KRB5CCNAME")
    if existing and os.path.exists(existing):
        log.info("Using existing Kerberos ccache: %s", existing)
        return True

    # No ccache → derive a TGT from password / NT hash / AES key
    if not (password or hashes or aes_key):
        log.error("Kerberos: no $KRB5CCNAME and no credentials to request a TGT "
                  "(provide -p / --hashes / --aesKey, or run kinit/getTGT.py)")
        return False

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        from impacket.krb5.ccache import CCache
    except Exception as exc:
        log.error("Kerberos libs unavailable: %s", exc)
        return False

    lm, nt = "", ""
    if hashes:
        parts = hashes.split(":")
        nt = parts[-1]
        lm = parts[0] if len(parts) == 2 and parts[0] else ""

    try:
        principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            principal, password or "", domain, lm, nt, aes_key or "", kdc_host
        )
        ccache = CCache()
        ccache.fromTGT(tgt, oldSessionKey, sessionKey)
        path = os.path.join(os.getcwd(), f"{username}_{domain}.ccache")
        ccache.saveFile(path)
        os.environ["KRB5CCNAME"] = path
        _say(f"[+] TGT obtained → {path}")
        return True
    except Exception as exc:
        log.error("Failed to obtain TGT: %s", exc)
        return False


def _auto_domain() -> Optional[str]:
    """Try to determine current domain from /etc/resolv.conf or hostname."""
    try:
        import socket
        fqdn = socket.getfqdn()
        parts = fqdn.split(".", 1)
        if len(parts) > 1:
            return parts[1]
    except Exception:
        pass
    return None


def _parse_collection_methods(methods_str: str) -> int:
    from adwshound.schema.types import CollectionMethod
    return CollectionMethod.parse(methods_str)


def run_collection(args: argparse.Namespace) -> int:
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache
    from adwshound.collectors.acls import load_guid_caches
    from adwshound.collectors.groups import GroupCollector
    from adwshound.collectors.users import UserCollector
    from adwshound.collectors.computers import ComputerCollector
    from adwshound.collectors.domains import DomainCollector
    from adwshound.collectors.ous import OUCollector
    from adwshound.collectors.containers import ContainerCollector
    from adwshound.collectors.gpos import GPOCollector
    from adwshound.collectors.trusts import TrustCollector
    from adwshound.collectors.sessions import SessionCollector
    from adwshound.collectors.local_groups import LocalGroupCollector
    from adwshound.collectors.adcs import ADCSCollector
    from adwshound.collectors.logged_on import LoggedOnCollector
    from adwshound.collectors.user_rights import UserRightsCollector
    from adwshound.collectors.computer_extras import ComputerExtrasCollector
    from adwshound.output.writer import JsonDataWriter
    from adwshound.output.zipper import create_zip
    from adwshound.schema.types import CollectionMethod

    # ── Resolve target ────────────────────────────────────────────────────────
    domain = args.domain or _auto_domain()
    if not domain:
        log.error("Could not determine domain. Use -d / --domain")
        return 1

    dc = args.domaincontroller or _resolve_dc(domain)
    do_kerberos = bool(args.kerberos or args.aes_key)
    kdc_host = args.dc_host or (dc if not _looks_like_ip(dc) else None)

    # Route target hostname resolution through the chosen DNS (default: the DC),
    # so collectors work even when the host's resolv.conf can't resolve AD names.
    dns_server = args.nameserver or (dc if _looks_like_ip(dc) else None)
    if dns_server:
        from adwshound.collectors.base import install_dns_override
        install_dns_override(dns_server)
        _say(f"[*] DNS via {dns_server}" + ("  (DC default)" if not args.nameserver else ""))
    elif not args.nameserver:
        _say("[*] DNS: system resolver (DC given as FQDN; pass --nameserver IP to override)")

    _say(f"[*] ADWSHound 1.0.0 — target {domain} via DC {dc} (ADWS 9389) — auth="
         + ("kerberos" if do_kerberos else "ntlm"))
    if do_kerberos:
        _say("[*] Kerberos end-to-end (ADWS + remote collectors) — TGT from $KRB5CCNAME")
    log.info("Target: domain=%s, DC=%s", domain, dc)

    if not args.ldapusername:
        log.error("Username required (-u / --ldapusername)")
        return 1

    if not do_kerberos and not args.ldappassword and not args.hashes:
        import getpass
        try:
            args.ldappassword = getpass.getpass(f"Password for {args.ldapusername}: ")
        except (KeyboardInterrupt, EOFError):
            return 1

    # Kerberos: ensure a ccache exists (auto-request a TGT from creds if needed)
    if do_kerberos:
        if not _ensure_kerberos_ccache(args.ldapusername, domain, args.ldappassword,
                                       args.hashes, args.aes_key, kdc_host):
            return 1

    # ── Build client ─────────────────────────────────────────────────────────
    if args.opsec:
        _say("[*] OPSEC mode on — LDAP filter values hex-escaped")
        log.info("OPSEC mode: LDAP filters will be hex-encoded")

    try:
        client = ADWSClient(
            dc_ip=dc,
            domain=domain,
            username=args.ldapusername,
            password=args.ldappassword,
            hashes=args.hashes,
            opsec=args.opsec,
            throttle_ms=args.throttle,
            jitter_pct=args.jitter,
            reuse=not args.no_reuse,
            kerberos=do_kerberos,
            kdc_host=kdc_host,
        )
    except ValueError as exc:
        log.error("Auth error: %s", exc)
        return 1

    log.info("Testing ADWS connection to %s:9389 …", dc)
    if not client.test_connection():
        _say("[!] ADWS connection failed — check port 9389 reachable and credentials")
        log.error("ADWS connection failed. Ensure port 9389 is reachable and credentials are correct.")
        return 1
    _say(f"[+] Connected as {args.ldapusername}")
    log.info("Connection OK")

    # Resolve naming contexts from RootDSE (robust against non-standard DNs)
    client.discover_contexts()

    # ── Collection method bitmask ─────────────────────────────────────────────
    try:
        coll_mask = _parse_collection_methods(args.CollectionMethods)
    except ValueError as exc:
        log.error("Invalid collection method: %s", exc)
        return 1

    if args.stealth:
        # Strip remote-only methods
        strip = (CollectionMethod.Session | CollectionMethod.LoggedOn |
                 CollectionMethod.LocalGroup | CollectionMethod.RDP |
                 CollectionMethod.DCOM | CollectionMethod.PSRemote)
        coll_mask &= ~strip
        coll_mask |= CollectionMethod.GPOLocalGroup

    _say(f"[*] Methods: {args.CollectionMethods}" + ("  (stealth)" if args.stealth else ""))

    collect_acls    = bool(coll_mask & CollectionMethod.ACL)
    collect_sessions = bool(coll_mask & (CollectionMethod.Session | CollectionMethod.LoggedOn))
    collect_local        = bool(coll_mask & (CollectionMethod.LocalGroup | CollectionMethod.GPOLocalGroup |
                                              CollectionMethod.RDP | CollectionMethod.DCOM | CollectionMethod.PSRemote))
    collect_local_remote = bool(coll_mask & (CollectionMethod.LocalGroup | CollectionMethod.RDP |
                                              CollectionMethod.DCOM | CollectionMethod.PSRemote))
    collect_groups  = bool(coll_mask & CollectionMethod.Group)
    collect_objects = bool(coll_mask & CollectionMethod.ObjectProps)
    collect_trusts  = bool(coll_mask & CollectionMethod.Trusts)
    collect_containers  = bool(coll_mask & CollectionMethod.Container)
    collect_certs       = bool(coll_mask & CollectionMethod.CertServices)
    collect_loggedon    = bool(coll_mask & CollectionMethod.LoggedOn)
    collect_userrights  = bool(coll_mask & CollectionMethod.UserRights)
    collect_dcregistry  = bool(coll_mask & CollectionMethod.DCRegistry)
    collect_webclient   = bool(coll_mask & CollectionMethod.WebClientService)
    collect_smbinfo     = bool(coll_mask & CollectionMethod.SmbInfo)
    collect_ntlmreg     = bool(coll_mask & CollectionMethod.NTLMRegistry)
    collect_ldap        = bool(coll_mask & CollectionMethod.LdapServices)

    output_dir = Path(args.outputdirectory)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Domain SID ───────────────────────────────────────────────────────────
    domain_sid = client.get_domain_sid() or ""
    _say(f"[*] Domain SID: {domain_sid or 'unknown'}")
    log.info("Domain SID: %s", domain_sid)

    # ── Pre-load resolver cache ───────────────────────────────────────────────
    cache = ResolverCache(domain=domain)
    cache.preload(client)

    # ── Load ACL GUID maps ────────────────────────────────────────────────────
    if collect_acls:
        load_guid_caches(client)

    # ── AdminSDHolder ACE hash (for accurate adminsdholderprotected) ──────────
    adminsdholder_hash: str | None = None
    if collect_acls:
        adminsdholder_hash = _compute_adminsdholder_hash(client, cache, domain)

    # ── Common collector constructor kwargs ───────────────────────────────────
    base_kwargs = dict(
        client=client,
        cache=cache,
        domain=domain,
        domain_sid=domain_sid,
        collect_acls=collect_acls,
        collect_all_props=args.collectallproperties,
        adminsdholder_hash=adminsdholder_hash,
    )

    json_files: list[Path] = []
    # These may stay empty if their collector is skipped or fails
    groups: list = []
    users: list  = []
    computers: list = []
    ous: list    = []
    containers: list = []
    gpos: list   = []
    domains: list = []

    def _writer(data_type: str) -> JsonDataWriter:
        return JsonDataWriter(
            data_type=data_type,
            collection_methods=coll_mask,
            output_dir=str(output_dir),
            prefix=args.outputprefix,
            pretty=args.prettyprint,
        )

    def _run(label: str, fn):
        """Run a collector function, log errors, never crash the run."""
        try:
            return fn()
        except Exception as exc:
            log.error("%s collection failed: %s", label, exc, exc_info=True)
            return []

    # ── Groups ───────────────────────────────────────────────────────────────
    if collect_groups:
        groups = _run("Groups", lambda: GroupCollector(**base_kwargs).collect())
        _say(f"[+] Groups: {len(groups)}")

    # WKP always emitted regardless of collect_groups (SharpHound behavior)

    # ── Users (always collected) ──────────────────────────────────────────────
    users = _run("Users", lambda: UserCollector(**base_kwargs).collect())
    _say(f"[+] Users: {len(users)}")

    # ── SPN Targets ───────────────────────────────────────────────────────────
    if coll_mask & CollectionMethod.SPNTargets:
        from adwshound.collectors.spns import SPNCollector
        spn_data = _run("SPNTargets", lambda: SPNCollector(**base_kwargs).collect())
        if spn_data:
            sid_to_user = {u.ObjectIdentifier: u for u in users}
            for entry in spn_data:
                u = sid_to_user.get(entry["user_sid"])
                if u:
                    u.SPNTargets = entry["spn_targets"]

    # Build groups + WKP stubs now; written later (after containment is wired)
    wkp = _emit_wellknown_principals(cache, domain, domain_sid)
    all_groups = list(groups) + wkp

    # ── Computers (always collected) ──────────────────────────────────────────
    computers = _run("Computers", lambda: ComputerCollector(**base_kwargs).collect())
    _say(f"[+] Computers: {len(computers)}")

    # Apply --excludedcs filter
    if args.excludedcs:
        computers = [c for c in computers if not c.Properties.get("isdc", False)]

    # Apply --computerfile filter
    if args.computerfile:
        try:
            with open(args.computerfile) as fh:
                targets = {line.strip().lower() for line in fh if line.strip()}
            computers = [
                c for c in computers
                if (c.Properties.get("name", "").lower() in targets
                    or c.Properties.get("samaccountname", "").lower().rstrip("$") in targets)
            ]
            log.info("Targeting %d computers from --computerfile", len(computers))
        except OSError as exc:
            log.error("Could not read --computerfile: %s", exc)

    # ── Connectivity check (TCP:445) — sets Status.Connectable per computer ──
    if not args.stealth and not args.skipportcheck:
        def _do_connectivity():
            from adwshound.collectors.base import check_tcp
            from adwshound.schema.types import ComputerStatus
            import concurrent.futures as _cf
            def _check(comp):
                dns = comp.Properties.get("name", "")
                ok  = bool(dns) and check_tcp(dns)
                comp.Status = ComputerStatus(Connectable=ok,
                                             Error=None if ok else "NotActive")
            with _cf.ThreadPoolExecutor(max_workers=args.threads) as pool:
                list(pool.map(_check, computers))
        _run("Connectivity", _do_connectivity)
        reachable = sum(1 for c in computers if c.Status.Connectable)
        _say(f"[*] Reachable computers (TCP 445): {reachable}/{len(computers)}")

    # Remote collectors only target hosts that passed the TCP:445 precheck.
    # Connectable defaults to False, so only filter when the precheck actually
    # ran; otherwise (stealth / --skipportcheck) keep all computers.
    did_portcheck = (not args.stealth and not args.skipportcheck)
    remote_targets = [c for c in computers if c.Status.Connectable] if did_portcheck else computers

    # ── Sessions ─────────────────────────────────────────────────────────────
    if collect_sessions:
        def _do_sessions():
            sam_cache = {
                u.Properties.get("samaccountname", "").lower(): u.ObjectIdentifier
                for u in users
                if u.Properties.get("samaccountname")
            }
            sc = SessionCollector(
                client=client, cache=cache, domain=domain,
                username=args.ldapusername, password=args.ldappassword,
                hashes=args.hashes, dc_only=args.stealth, threads=args.threads,
                sam_cache=sam_cache,
                allowed_sids=({c.ObjectIdentifier.upper() for c in remote_targets}
                              if did_portcheck else None),
                do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
            )
            session_map = sc.collect()
            for comp in computers:
                if comp.ObjectIdentifier in session_map:
                    comp.Sessions = session_map[comp.ObjectIdentifier]
        _run("Sessions", _do_sessions)

    # ── Local groups ─────────────────────────────────────────────────────────
    gpo_lg_entries: list = []
    if collect_local:
        def _do_local_groups():
            from adwshound.schema.types import LocalGroupResult
            lg = LocalGroupCollector(
                client=client, cache=cache, domain=domain,
                domain_sid=domain_sid,
                username=args.ldapusername, password=args.ldappassword,
                hashes=args.hashes, dc_ip=dc,
                gpo_only=not collect_local_remote or args.stealth,
                threads=args.threads,
                do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
            )
            # GPO-based — always run when local collection is enabled
            gpo_entries = lg.collect_gpo()
            gpo_lg_entries.extend(gpo_entries)

            if collect_local_remote and not args.stealth:
                lg_map = lg.collect_remote([c.ObjectIdentifier for c in remote_targets])
                for comp in computers:
                    grp_data = lg_map.get(comp.ObjectIdentifier, {})
                    # Build LocalGroups list from collected results
                    comp.LocalGroups = [
                        v for v in grp_data.values()
                        if isinstance(v, LocalGroupResult)
                    ]
        _run("LocalGroups", _do_local_groups)

    # ── LoggedOn (remote registry) ────────────────────────────────────────────
    if collect_loggedon and not args.stealth and not args.skipregistryloggedon:
        def _do_loggedon():
            sam_cache = {
                u.Properties.get("samaccountname", "").lower(): u.ObjectIdentifier
                for u in users if u.Properties.get("samaccountname")
            }
            comp_attrs = [
                {"objectSid": c.ObjectIdentifier,
                 "dNSHostName": c.Properties.get("name", ""),
                 "sAMAccountName": c.Properties.get("samaccountname", "")}
                for c in remote_targets
            ]
            lo = LoggedOnCollector(
                domain=domain, username=args.ldapusername,
                password=args.ldappassword, hashes=args.hashes,
                threads=args.threads, sam_cache=sam_cache,
                do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
            )
            lo_map = lo.collect(comp_attrs)
            for comp in computers:
                result = lo_map.get(comp.ObjectIdentifier)
                if result:
                    reg_cr, priv_cr = result
                    comp.RegistrySessions  = reg_cr
                    comp.PrivilegedSessions = priv_cr
        _run("LoggedOn", _do_loggedon)

    # ── UserRights (LSA) ──────────────────────────────────────────────────────
    if collect_userrights and not args.stealth:
        def _do_userrights():
            comp_attrs = [
                {"objectSid": c.ObjectIdentifier,
                 "dNSHostName": c.Properties.get("name", ""),
                 "sAMAccountName": c.Properties.get("samaccountname", "")}
                for c in remote_targets
            ]
            ur = UserRightsCollector(
                domain=domain, username=args.ldapusername,
                password=args.ldappassword, hashes=args.hashes,
                cache=cache, threads=args.threads,
                do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
            )
            ur_map = ur.collect(comp_attrs)
            for comp in computers:
                cr = ur_map.get(comp.ObjectIdentifier)
                if cr and cr.Collected:
                    comp.UserRights = cr.Results
        _run("UserRights", _do_userrights)

    # ── Computer extras: WebClient, SmbInfo, NTLMRegistry, DCRegistry ─────────
    _need_extras = any([collect_webclient, collect_smbinfo, collect_ntlmreg,
                        collect_dcregistry, collect_ldap])
    if _need_extras and not args.stealth:
        def _do_extras():
            comp_attrs = [
                {"objectSid": c.ObjectIdentifier,
                 "dNSHostName": c.Properties.get("name", ""),
                 "sAMAccountName": c.Properties.get("samaccountname", ""),
                 "_is_dc": c.Properties.get("isdc", False),
                 "_os_version": c.Properties.get("operatingsystem")}
                for c in remote_targets
            ]
            ex = ComputerExtrasCollector(
                domain=domain, username=args.ldapusername,
                password=args.ldappassword, hashes=args.hashes,
                threads=args.threads,
                collect_webclient=collect_webclient,
                collect_smb=collect_smbinfo,
                collect_ntlm=collect_ntlmreg,
                collect_dc_reg=collect_dcregistry,
                collect_ldap=collect_ldap,
                do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
            )
            ex_map = ex.collect(comp_attrs)
            for comp in computers:
                extras = ex_map.get(comp.ObjectIdentifier, {})
                if "webclient" in extras:
                    comp.IsWebClientRunning = extras["webclient"]
                if "smbinfo" in extras:
                    comp.SmbInfo = extras["smbinfo"]
                if "ntlm" in extras:
                    comp.NTLMRegistryData = extras["ntlm"]
                if "dcregistry" in extras:
                    comp.DCRegistryData = extras["dcregistry"]
                if "ldapservices" in extras:
                    lds = extras["ldapservices"]
                    comp.LdapServicesData = lds
                    if lds:
                        # Add ldap port availability via TCP probe
                        from adwshound.collectors.base import check_tcp
                        dns = comp.Properties.get("name", "")
                        if dns:
                            comp.Properties["ldapavailable"]  = check_tcp(dns, 389, 2.0)
                            comp.Properties["ldapsavailable"] = check_tcp(dns, 636, 2.0)
                        # Signing / channel binding derived from registry values
                        comp.Properties["ldapsigning"] = (lds.LdapSigning == 2)
                        comp.Properties["ldapsepa"]    = (lds.LdapChannelBinding == 2)
        _run("ComputerExtras", _do_extras)

    # ── Domains ───────────────────────────────────────────────────────────────
    domains = _run("Domains", lambda: DomainCollector(**base_kwargs).collect())

    # ── Trusts ────────────────────────────────────────────────────────────────
    # Collected when requested, OR when --recursedomains needs trust targets to walk.
    primary_trust_targets: list[str] = []
    if collect_trusts or args.recursedomains:
        def _do_trusts():
            trusts = TrustCollector(**base_kwargs).collect()
            primary_trust_targets.extend(
                t.TargetDomainName for t in trusts if t.TargetDomainName
            )
            if collect_trusts:
                for dom in domains:
                    dom.Trusts = trusts
        _run("Trusts", _do_trusts)

    _say(f"[+] Domains: {len(domains)}")

    # ── Container / OU / GPO ─────────────────────────────────────────────────
    if collect_containers:
        ous        = _run("OUs",        lambda: OUCollector(**base_kwargs).collect())
        containers = _run("Containers", lambda: ContainerCollector(**base_kwargs).collect())
        gpos       = _run("GPOs",       lambda: GPOCollector(**base_kwargs).collect())
        _say(f"[+] OUs: {len(ous)}  Containers: {len(containers)}  GPOs: {len(gpos)}")

    # ── ADCS (Certificate Services) ───────────────────────────────────────────
    if collect_certs:
        adcs = ADCSCollector(
            client=client, cache=cache, domain=domain,
            domain_sid=domain_sid, collect_acls=collect_acls,
            username=args.ldapusername,
            password=args.ldappassword,
            hashes=args.hashes,
            do_kerberos=do_kerberos, aes_key=args.aes_key, kdc_host=kdc_host,
        )
        rootcas  = _run("RootCAs",         lambda: adcs.collect_rootcas())
        aiacas   = _run("AIACAs",          lambda: adcs.collect_aiacas())
        ntauths  = _run("NTAuthStores",    lambda: adcs.collect_ntauthstores())
        ecas     = _run("EnterpriseCAs",   lambda: adcs.collect_enterprisecas())
        ctpls    = _run("CertTemplates",   lambda: adcs.collect_certtemplates())
        ipols    = _run("IssuancePolicies", lambda: adcs.collect_issuancepolicies())

        if rootcas:  json_files.append(_writer("rootcas").write(rootcas))
        if aiacas:   json_files.append(_writer("aiacas").write(aiacas))
        if ntauths:  json_files.append(_writer("ntauthstores").write(ntauths))
        if ecas:     json_files.append(_writer("enterprisecas").write(ecas))
        if ctpls:    json_files.append(_writer("certtemplates").write(ctpls))
        if ipols:    json_files.append(_writer("issuancepolicies").write(ipols))

        _say(f"[+] ADCS: {len(ecas)} CAs, {len(ctpls)} templates, "
             f"{len(ipols)} issuance policies")

    # Always wire DN hierarchy regardless of whether Container collection ran
    _run("ChildLink", lambda: _link_children(
        domains, ous, containers, users, groups, computers, cache, gpos
    ))

    # Populate GPOChanges.AffectedComputers now that ChildObjects are wired
    _run("GPOAffected", lambda: _set_gpo_affected_computers(domains, ous, computers))

    # Wire GPO-based local group memberships to Domain/OU GPOChanges slots
    if gpo_lg_entries:
        _run("GPOLocalGroups", lambda: _wire_gpo_local_groups(gpo_lg_entries, domains, ous))

    # Diagnostic: ACLs requested but nothing parsed → SD not returned by ADWS
    # (control not honored or insufficient rights). Surface it instead of silent 0.
    if collect_acls:
        _ace_total = sum(len(o.Aces or []) for o in (list(users) + list(groups) + list(computers)))
        if _ace_total == 0:
            _say("[!] ACL requested but 0 ACEs parsed — DC returned no nTSecurityDescriptor "
                 "(SD_FLAGS control not honored or no read rights). DCSync/ObjectControl will be empty.")

    # ── Write all object files (AFTER containment/GPO wiring so ContainedBy,
    #    ChildObjects, GPOChanges and Links are present in the output) ──────────
    for obj_list, dtype in (
        (users, "users"), (all_groups, "groups"), (computers, "computers"),
        (ous, "ous"), (containers, "containers"), (gpos, "gpos"), (domains, "domains"),
    ):
        if obj_list:
            json_files.append(_writer(dtype).write(obj_list))

    # ── Additional domains: --searchforest (crossRef) and/or --recursedomains ──
    # BFS worklist with a visited set (lowercased FQDNs) prevents re-collecting a
    # domain and prevents infinite loops on bidirectional trusts. --searchforest
    # seeds the forest's domains (one crossRef query); --recursedomains seeds the
    # primary domain's trusts and then keeps following each collected domain's
    # trusts outward.
    if args.searchforest or args.recursedomains:
        visited: set[str] = {domain.lower()}
        worklist: list[tuple[str, str]] = []

        def _enqueue(fqdn: str, dc_: str | None = None) -> None:
            if not fqdn or fqdn.lower() in visited:
                return
            if any(fqdn.lower() == w[0].lower() for w in worklist):
                return
            worklist.append((fqdn, dc_ or _resolve_dc(fqdn)))

        if args.searchforest:
            for fdom, fdc in (_run("ForestDiscover",
                                   lambda: _discover_forest_domains(client, domain)) or []):
                _enqueue(fdom, fdc)
        if args.recursedomains:
            for tgt in primary_trust_targets:
                _enqueue(tgt)

        while worklist:
            fdomain, fdc = worklist.pop(0)
            if fdomain.lower() in visited:
                continue
            visited.add(fdomain.lower())
            _say(f"[*] Additional domain: {fdomain} (DC {fdc})")
            result = _run(
                f"Domain:{fdomain}",
                lambda fd=fdomain, dc_=fdc: _collect_forest_domain(
                    fd, dc_, args, coll_mask, output_dir, adminsdholder_hash
                ),
            )
            extra, trust_targets = result if result else ([], [])
            if extra:
                json_files.extend(extra)
            # Keep walking trusts outward only in recursedomains mode
            if args.recursedomains:
                for tgt in trust_targets:
                    _enqueue(tgt)

    # ── Write ZIP ────────────────────────────────────────────────────────────
    if not args.nozip and json_files:
        zip_path = create_zip(
            json_files,
            output_dir=output_dir,
            prefix=args.outputprefix,
            password=args.zippassword,
        )
        print(f"[+] Output: {zip_path}")
    else:
        for jf in json_files:
            print(f"[+] Output: {jf}")

    client.close()
    return 0


def _discover_forest_domains(client, current_domain: str) -> list[tuple[str, str]]:
    """Query Configuration NC crossRef objects to find all forest domain FQDNs.

    Returns list of (domain_fqdn, dc_hostname) tuples, excluding current domain.
    systemFlags & 0x2 = ADS_SYSTEMFLAG_CR_NTDS_NC (domain naming context crossRef).
    """
    results = []
    try:
        refs = client.search_config_nc(
            "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
            ["dnsRoot", "nCName"],
        )
    except Exception as exc:
        log.warning("Forest domain discovery failed: %s", exc)
        return results

    for ref in refs:
        dns_root = ref.get("dnsRoot")
        if not dns_root:
            continue
        if isinstance(dns_root, list):
            dns_root = dns_root[0]
        if dns_root.lower() == current_domain.lower():
            continue
        dc = _resolve_dc(dns_root)
        results.append((dns_root, dc))
        log.info("Discovered forest domain: %s → DC %s", dns_root, dc)

    return results


def _collect_forest_domain(
    domain: str,
    dc: str,
    args,
    coll_mask: int,
    output_dir,
    adminsdholder_hash: "str | None",
) -> "tuple[list, list[str]]":
    """Run base collection for a single additional (forest/trusted) domain.

    Returns (json_file_paths, trust_target_fqdns). The trust targets let the
    caller keep walking trusts outward under --recursedomains.
    """
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache
    from adwshound.collectors.acls import load_guid_caches
    from adwshound.collectors.groups import GroupCollector
    from adwshound.collectors.users import UserCollector
    from adwshound.collectors.computers import ComputerCollector
    from adwshound.collectors.domains import DomainCollector
    from adwshound.collectors.ous import OUCollector
    from adwshound.collectors.containers import ContainerCollector
    from adwshound.collectors.gpos import GPOCollector
    from adwshound.collectors.trusts import TrustCollector
    from adwshound.output.writer import JsonDataWriter
    from adwshound.schema.types import CollectionMethod

    log.info("Collecting forest domain: %s (DC=%s)", domain, dc)

    try:
        fclient = ADWSClient(
            dc_ip=dc, domain=domain,
            username=args.ldapusername, password=args.ldappassword,
            hashes=args.hashes, opsec=args.opsec,
            throttle_ms=args.throttle, jitter_pct=args.jitter,
            reuse=not args.no_reuse,
            kerberos=bool(args.kerberos or args.aes_key),
            kdc_host=(args.dc_host or (dc if not _looks_like_ip(dc) else None)),
        )
        if not fclient.test_connection():
            log.warning("ADWS connection failed for forest domain %s — skipping", domain)
            return [], []
        fclient.discover_contexts()
    except Exception as exc:
        log.warning("Cannot connect to forest domain %s: %s — skipping", domain, exc)
        return [], []

    domain_sid = fclient.get_domain_sid() or ""
    fcache = ResolverCache(domain=domain)
    fcache.preload(fclient)

    collect_acls     = bool(coll_mask & CollectionMethod.ACL)
    collect_groups   = bool(coll_mask & CollectionMethod.Group)
    collect_trusts   = bool(coll_mask & CollectionMethod.Trusts)
    collect_containers = bool(coll_mask & CollectionMethod.Container)

    if collect_acls:
        load_guid_caches(fclient)

    fkwargs = dict(
        client=fclient, cache=fcache, domain=domain, domain_sid=domain_sid,
        collect_acls=collect_acls, collect_all_props=args.collectallproperties,
        adminsdholder_hash=adminsdholder_hash,
    )

    def _fwriter(data_type: str):
        return JsonDataWriter(
            data_type=data_type, collection_methods=coll_mask,
            output_dir=str(output_dir), prefix=args.outputprefix,
            pretty=args.prettyprint,
        )

    def _frun(label, fn):
        try:
            return fn()
        except Exception as exc:
            log.error("[%s] %s failed: %s", domain, label, exc, exc_info=True)
            return []

    json_files: list = []
    fgroups = fcomps = fusers = fdomains = fous = fcontainers = fgpos = []

    if collect_groups:
        fgroups = _frun("Groups", lambda: GroupCollector(**fkwargs).collect())
    fusers     = _frun("Users",     lambda: UserCollector(**fkwargs).collect())
    fcomps     = _frun("Computers", lambda: ComputerCollector(**fkwargs).collect())
    fdomains   = _frun("Domains",   lambda: DomainCollector(**fkwargs).collect())

    # Collect trusts when requested, or when recursing (need targets to keep walking)
    trust_targets: list[str] = []
    if collect_trusts or args.recursedomains:
        trusts = _frun("Trusts", lambda: TrustCollector(**fkwargs).collect()) or []
        trust_targets = [t.TargetDomainName for t in trusts if t.TargetDomainName]
        if collect_trusts:
            for dom in fdomains:
                dom.Trusts = trusts

    if collect_containers:
        fous        = _frun("OUs",        lambda: OUCollector(**fkwargs).collect())
        fcontainers = _frun("Containers", lambda: ContainerCollector(**fkwargs).collect())
        fgpos       = _frun("GPOs",       lambda: GPOCollector(**fkwargs).collect())

    _link_children(fdomains, fous, fcontainers, fusers, fgroups, fcomps, fcache, fgpos)
    _set_gpo_affected_computers(fdomains, fous, fcomps)

    for obj, dtype in (
        (fgroups, "groups"), (fusers, "users"), (fcomps, "computers"),
        (fdomains, "domains"), (fous, "ous"), (fcontainers, "containers"), (fgpos, "gpos"),
    ):
        if obj:
            json_files.append(_fwriter(dtype).write(obj))

    fclient.close()
    return json_files, trust_targets


def _compute_adminsdholder_hash(client, cache, domain: str) -> str | None:
    """Compute a canonical hash of the AdminSDHolder container's DACL.

    Used to detect objects whose ACL matches the AdminSDHolder template
    (more accurate than using adminCount as a proxy).
    """
    import hashlib
    from adwshound.collectors.acls import parse_acl
    try:
        base_dn = getattr(client, "base_dn", None) or _domain_to_dn(domain)
        dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
        objs = client.search(f"(distinguishedName={dn})", ["nTSecurityDescriptor"])
        if not objs:
            return None
        sd_bytes = objs[0].get("nTSecurityDescriptor")
        if not sd_bytes or not isinstance(sd_bytes, bytes):
            return None
        aces, _ = parse_acl(sd_bytes, cache, "adminsdholder")
        # Build canonical representation: sorted SID+right pairs
        canonical = "|".join(
            sorted(f"{a.PrincipalSID}:{a.RightName}" for a in aces)
        )
        return hashlib.sha1(canonical.encode()).hexdigest().upper()
    except Exception:
        return None


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.lower().split("."))


def _set_gpo_affected_computers(domains, ous, computers) -> None:
    """Populate GPOChanges.AffectedComputers on Domain and OU objects."""
    from adwshound.schema.types import TypedPrincipal

    all_computer_tps = [
        TypedPrincipal(ObjectIdentifier=c.ObjectIdentifier, ObjectType="Computer")
        for c in computers
    ]

    # Domain scope = all computers in the domain
    for dom in domains:
        dom.GPOChanges.AffectedComputers = all_computer_tps

    # Build OU GUID → OU object map for recursive traversal
    ou_by_id: dict[str, object] = {ou.ObjectIdentifier: ou for ou in ous}

    def _collect_computers(obj) -> list:
        """Recursively collect Computer TypedPrincipals from ChildObjects."""
        result = []
        for child in getattr(obj, "ChildObjects", []):
            if child.ObjectType == "Computer":
                result.append(child)
            elif child.ObjectType == "OU" and child.ObjectIdentifier in ou_by_id:
                result.extend(_collect_computers(ou_by_id[child.ObjectIdentifier]))
        return result

    for ou in ous:
        ou.GPOChanges.AffectedComputers = _collect_computers(ou)


def _link_children(domains, ous, containers, users, groups, computers, cache, gpos=None) -> None:
    """Populate ChildObjects and ContainedBy based on DN hierarchy."""
    from adwshound.schema.types import TypedPrincipal

    if gpos is None:
        gpos = []

    def parent_dn(dn: str) -> str:
        idx = dn.find(",")
        return dn[idx + 1:] if idx != -1 else ""

    dn_map: dict[str, tuple[str, object]] = {}

    for u in users:
        dn = u.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("User", u)

    for g in groups:
        dn = g.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("Group", g)

    for c in computers:
        dn = c.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("Computer", c)

    for ou in ous:
        dn = ou.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("OU", ou)

    for ct in containers:
        dn = ct.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("Container", ct)

    for dom in domains:
        dn = dom.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("Domain", dom)

    # GPOs live in CN=Policies,CN=System,<domain> — a Container/Domain
    for gpo in gpos:
        dn = gpo.Properties.get("distinguishedname", "")
        if dn:
            dn_map[dn.upper()] = ("GPO", gpo)

    all_objects = (list(ous) + list(containers) + list(users) +
                   list(groups) + list(computers) + list(gpos))

    for obj in all_objects:
        dn = obj.Properties.get("distinguishedname", "")
        if not dn:
            continue
        p = parent_dn(dn).upper()
        if not p:
            continue

        entry = dn_map.get(p)
        if not entry:
            continue

        parent_type, parent_obj = entry
        identifier = obj.ObjectIdentifier
        tp = TypedPrincipal(ObjectIdentifier=identifier, ObjectType=_obj_type_name(obj))

        if hasattr(parent_obj, "ChildObjects"):
            parent_obj.ChildObjects.append(tp)

        obj.ContainedBy = TypedPrincipal(
            ObjectIdentifier=parent_obj.ObjectIdentifier,
            ObjectType=parent_type,
        )


def _obj_type_name(obj) -> str:
    cls = type(obj).__name__
    return cls.replace("Output", "")


def _emit_wellknown_principals(cache, domain: str, domain_sid: str) -> list:
    """Build stub GroupOutput objects for well-known principals.

    Mirrors SharpHound CollectionTask.cs lines 88-100:
    - Non-EnterpriseDC WKPs: emitted with Properties["reconcile"] = False
    - EnterpriseDC group (S-1-5-9): emitted only if it has members (no reconcile=false)
    - reconcile=False means BH CE will not overwrite existing data for that node
    """
    from adwshound.schema.types import GroupOutput

    _ENTERPRISE_DC_SUFFIX = "S-1-5-9"
    results = []

    # Use public resolve_sid interface; iterate the well-known SID set from cache module
    from adwshound.resolvers.cache import _WELL_KNOWN_GROUP_SIDS
    for raw_sid in _WELL_KNOWN_GROUP_SIDS:
        qualified = cache.qualify_sid(raw_sid)
        tp = cache.resolve_sid(raw_sid)
        if not tp:
            from adwshound.schema.types import TypedPrincipal
            tp = TypedPrincipal(ObjectIdentifier=qualified, ObjectType="Group")

        is_enterprise_dc = raw_sid.upper().endswith(_ENTERPRISE_DC_SUFFIX)

        props = {
            "domain":          domain.upper(),
            "name":            qualified,
            "distinguishedname": "",
            "domainsid":       domain_sid,
            "samaccountname":  "",
            "adminsdholderprotected": False,
            "description":     None,
            "whencreated":     -1,
            "admincount":      False,
            "groupscope":      "Global",
            "sidhistory":      [],
            "isaclprotected":  False,
            "doesanyacegrantownerrights":          False,
            "doesanyinheritedacegrantownerrights": False,
        }

        # Non-Enterprise-DC WKPs get reconcile=false (SharpHound behavior)
        if not is_enterprise_dc:
            props["reconcile"] = False

        results.append(GroupOutput(
            Properties=props,
            Members=[],
            HasSIDHistory=[],
            DomainSID=domain_sid,
            Aces=[],
            ObjectIdentifier=tp.ObjectIdentifier,
        ))

    return results


def _wire_gpo_local_groups(gpo_entries: list, domains: list, ous: list) -> None:
    """Populate GPOChanges local group slots from GPO XML entries.

    Matches GPO GUIDs in each Domain/OU's Links list and merges members into
    the appropriate GPOChanges slot (LocalAdmins, RemoteDesktopUsers, etc.).
    """
    # Build GUID → {group_type: [TypedPrincipal]}
    gpo_map: dict[str, dict[str, list]] = {}
    for entry in gpo_entries:
        guid  = entry.get("gpo_guid", "")
        gtype = entry.get("group_type", "")
        if not guid or not gtype:
            continue
        gpo_map.setdefault(guid, {}).setdefault(gtype, []).extend(entry.get("members", []))

    def _apply(obj) -> None:
        for link in getattr(obj, "Links", []):
            slot_data = gpo_map.get(link.GUID, {})
            for gtype, members in slot_data.items():
                cur = getattr(obj.GPOChanges, gtype, None)
                if cur is None:
                    continue
                existing = {tp.ObjectIdentifier for tp in cur}
                cur.extend(m for m in members if m.ObjectIdentifier not in existing)

    for dom in domains:
        _apply(dom)
    for ou in ous:
        _apply(ou)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbosity)

    try:
        return run_collection(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 130
    except Exception as exc:
        log.exception("Unhandled error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
