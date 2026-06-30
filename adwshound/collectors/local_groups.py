"""Local group enumeration collector.

Two approaches:
1. GPO-based (default, DC-safe): parse GPO XML files from SYSVOL to find
   RestrictedGroups / Groups policy that adds members to local groups.
2. Remote SAMR (full): enumerate local groups on each computer via SAMR.

Results map computer_sid → CollectionResult for each local group type:
  LocalAdmins, RemoteDesktopUsers, DcomUsers, PSRemoteUsers
"""
from __future__ import annotations

import logging
import re
import concurrent.futures
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import CollectionResult, LocalGroupResult, TypedPrincipal

if TYPE_CHECKING:
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)

# Local group well-known RIDs → (BloodHound result slot, local group name).
# The name mirrors the built-in Windows group name SharpHound emits.
_LOCAL_GROUP_RIDS = {
    544: ("LocalAdmins",        "ADMINISTRATORS"),
    555: ("RemoteDesktopUsers", "REMOTE DESKTOP USERS"),
    562: ("DcomUsers",          "DISTRIBUTED COM USERS"),
    580: ("PSRemoteUsers",      "REMOTE MANAGEMENT USERS"),
}

_GPO_FILTER = "(objectClass=groupPolicyContainer)"
_GPO_ATTRS  = ["objectGUID", "cn", "gpcFileSysPath", "distinguishedName"]


class LocalGroupCollector:

    def __init__(
        self,
        client: "ADWSClient",
        cache: "ResolverCache",
        domain: str,
        domain_sid: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        dc_ip: str,
        gpo_only: bool = True,
        threads: int = 10,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.client = client
        self.cache = cache
        self.domain = domain
        self.domain_sid = domain_sid
        self.username = username
        self.password = password
        self.hashes = hashes
        self.dc_ip = dc_ip
        self.gpo_only = gpo_only
        self.threads = threads
        self.do_kerberos = do_kerberos
        self.aes_key = aes_key
        self.kdc_host = kdc_host

    def collect_gpo(self) -> list[dict]:
        """Parse GPOs for RestrictedGroups/Groups policy entries.

        Returns list of dicts:
          {"computer_sid": ..., "group_type": "LocalAdmins", "members": [TypedPrincipal]}

        Note: GPO-based collection returns policy-derived membership, not
        actual membership.  Covers cases where explicit local admin policy is set.
        """
        log.info("Collecting local group memberships from GPOs …")

        gpos = self.client.search(_GPO_FILTER, _GPO_ATTRS)
        results = []

        for gpo in gpos:
            sysvol_path = gpo.get("gpcFileSysPath")
            gpo_guid    = str(gpo.get("objectGUID") or "").upper()
            if not sysvol_path:
                continue
            try:
                entries = self._parse_gpo_groups_xml(sysvol_path)
                for e in entries:
                    e["gpo_guid"] = gpo_guid
                results.extend(entries)
            except Exception as exc:
                log.debug("GPO parse failed for %s: %s", sysvol_path, exc)

        log.info("GPO local-group collection complete: %d entries", len(results))
        return results

    def _parse_gpo_groups_xml(self, sysvol_path: str) -> list[dict]:
        """Read Groups.xml from SYSVOL and extract local admin assignments."""
        from impacket.smbconnection import SMBConnection

        # Convert SYSVOL UNC path to SMB share/path
        # e.g. \\domain.local\SYSVOL\domain.local\Policies\{GUID}
        path = sysvol_path.replace("\\", "/")
        parts = path.strip("/").split("/", 2)
        if len(parts) < 3:
            return []

        _dc, share, rel_path = parts
        groups_xml_path = rel_path.rstrip("/") + "/Machine/Preferences/Groups/Groups.xml"

        from adwshound.collectors.base import smb_login
        # Kerberos SMB needs the DC's SPN → connect by name, not IP, when -k is set.
        smb_host = self.kdc_host or self.dc_ip if self.do_kerberos else self.dc_ip
        conn = SMBConnection(smb_host, smb_host, timeout=10)
        smb_login(conn, self.username, self.password, self.domain, self.hashes,
                  self.aes_key, self.do_kerberos, self.kdc_host)

        try:
            buf = []
            conn.getFile(share, groups_xml_path, buf.append)
            xml_data = b"".join(buf).decode("utf-8", errors="replace")
        except Exception:
            return []
        finally:
            conn.logoff()

        return _parse_groups_xml_content(xml_data, self.cache)

    def collect_remote(self, computer_sids: list[str]) -> dict[str, dict[str, CollectionResult]]:
        """Enumerate local groups on each computer via SAMR.

        Returns: {computer_sid: {group_type: CollectionResult}}
        """
        log.info("Collecting local group memberships via SAMR (%d computers) …", len(computer_sids))
        results: dict[str, dict[str, CollectionResult]] = {}

        # Build hostname map
        comp_map = {}
        for sid in computer_sids:
            tp = self.cache.resolve_sid(sid)
            if tp:
                objs = self.client.search(f"(objectSid={sid})", ["dNSHostName", "sAMAccountName"])
                if objs:
                    host = objs[0].get("dNSHostName") or objs[0].get("sAMAccountName", "").rstrip("$")
                    comp_map[sid] = host

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._enum_local_groups, sid, host): sid
                for sid, host in comp_map.items()
            }
            for fut in concurrent.futures.as_completed(future_map):
                sid = future_map[fut]
                try:
                    results[sid] = fut.result()
                except Exception as exc:
                    log.debug("Local group enum failed for %s: %s", sid, exc)
                    host_upper = comp_map.get(sid, "").upper()
                    results[sid] = {
                        slot: LocalGroupResult(
                            ObjectIdentifier=f"{sid}-{rid}",
                            Name=f"{gname}@{host_upper}",
                            Results=[], Collected=False, FailureReason=str(exc),
                        )
                        for rid, (slot, gname) in _LOCAL_GROUP_RIDS.items()
                    }

        return results

    def _enum_local_groups(
        self, comp_sid: str, hostname: str
    ) -> dict[str, CollectionResult]:
        from impacket.dcerpc.v5 import transport, samr
        from adwshound.collectors.base import set_dcerpc_creds

        binding = f"ncacn_np:{hostname}[\\pipe\\samr]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        set_dcerpc_creds(rpctransport, self.username, self.password, self.domain,
                         self.hashes, self.aes_key, self.do_kerberos, self.kdc_host)
        rpctransport.set_connect_timeout(10)

        dce = rpctransport.get_dce_rpc()
        group_results: dict[str, CollectionResult] = {}

        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            for domain_info in resp["Buffer"]["Buffer"]:
                if domain_info["Name"].upper() == "BUILTIN":
                    break

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, "BUILTIN")
            domain_sid_obj = resp["DomainId"]

            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid_obj)
            domain_handle = resp["DomainHandle"]

            host_upper = hostname.upper()
            for rid, (group_type, gname) in _LOCAL_GROUP_RIDS.items():
                oid  = f"{comp_sid}-{rid}"
                name = f"{gname}@{host_upper}"
                try:
                    resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=rid)
                    alias_handle = resp["AliasHandle"]

                    resp = samr.hSamrGetMembersInAlias(dce, alias_handle)
                    members = []
                    for sid_info in resp["Members"]["Sids"]:
                        member_sid = sid_info["SidPointer"].formatCanonical()
                        tp = self.cache.resolve_sid(member_sid)
                        if not tp:
                            tp = TypedPrincipal(
                                ObjectIdentifier=member_sid.upper(),
                                ObjectType="Base",
                            )
                        members.append(tp)

                    samr.hSamrCloseHandle(dce, alias_handle)
                    group_results[group_type] = LocalGroupResult(
                        ObjectIdentifier=oid, Name=name,
                        Results=members, Collected=True,
                    )
                except Exception as exc:
                    group_results[group_type] = LocalGroupResult(
                        ObjectIdentifier=oid, Name=name,
                        Results=[], Collected=False, FailureReason=str(exc),
                    )

        finally:
            try:
                dce.disconnect()
            except Exception:
                pass

        return group_results


def _resolve_group_type(group_sid: str, group_name: str) -> str | None:
    """Map a GPO group entry to a BloodHound local group slot via SID or name."""
    # Prefer SID-based match (e.g. "S-1-5-32-544")
    if group_sid:
        try:
            rid = int(group_sid.rsplit("-", 1)[-1])
            if rid in _LOCAL_GROUP_RIDS:
                return _LOCAL_GROUP_RIDS[rid]
        except (ValueError, IndexError):
            pass
    # Fallback: match RID number or known English name in groupName
    _NAME_MAP = {
        "administrators": 544,
        "remote desktop users": 555,
        "distributed com users": 562,
        "remote management users": 580,
    }
    lower = group_name.lower()
    for name_key, rid in _NAME_MAP.items():
        if name_key in lower or str(rid) in lower:
            return _LOCAL_GROUP_RIDS[rid]
    return None


def _parse_groups_xml_content(xml_data: str, cache: "ResolverCache") -> list[dict]:
    """Parse Groups.xml GPO preference content for local admin entries."""
    from xml.etree import ElementTree

    results = []
    try:
        root = ElementTree.fromstring(xml_data)
    except ElementTree.ParseError:
        return []

    for group_elem in root.findall(".//Group"):
        props = group_elem.find("Properties")
        if props is None:
            continue

        group_name = props.get("groupName", "")
        group_sid  = props.get("groupSid", "")

        # Resolve group type from SID (reliable) or name/number fallback
        group_type = _resolve_group_type(group_sid, group_name)
        if group_type is None:
            continue

        members_elem = props.find("Members")
        if members_elem is None:
            continue

        members = []
        for member in members_elem.findall("Member"):
            sid = member.get("sid")
            action = member.get("action", "ADD")

            if action.upper() != "ADD":
                continue

            if sid:
                tp = cache.resolve_sid(sid)
                if not tp:
                    tp = TypedPrincipal(ObjectIdentifier=sid.upper(), ObjectType="Base")
                members.append(tp)

        if members:
            results.append({
                "group_type": group_type,
                "members": members,
                "source": "GPO",
            })

    return results
