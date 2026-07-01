"""LoggedOn session collection.

Two approaches:
1. RegistrySessions: reads HKLM\\...\\ProfileList for loaded user profiles.
2. PrivilegedSessions: NetWkstaUserEnum (wkssvc pipe) for interactive sessions.
"""
from __future__ import annotations

import logging
import concurrent.futures
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import SessionResult, CollectionResult

if TYPE_CHECKING:
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)

_PROFILE_LIST_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

# Profiles with these SID prefixes are service/system accounts — skip them
_SKIP_SID_PREFIXES = ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-17")


class LoggedOnCollector:

    def __init__(
        self,
        domain: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        threads: int = 10,
        sam_cache: Optional[dict] = None,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.domain    = domain
        self.username  = username
        self.password  = password
        self.hashes    = hashes
        self.threads   = threads
        self.do_kerberos = do_kerberos
        self.aes_key   = aes_key
        self.kdc_host  = kdc_host
        self._sam_cache: dict[str, str] = sam_cache or {}

    def collect(self, computers: list) -> dict[str, tuple[CollectionResult, CollectionResult]]:
        """Return {comp_sid: (registry_cr, privileged_cr)} for each computer."""
        results: dict[str, tuple[CollectionResult, CollectionResult]] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._collect_one, comp): comp
                for comp in computers
            }
            for fut in concurrent.futures.as_completed(future_map):
                comp = future_map[fut]
                sid = comp.get("objectSid", "")
                if not sid:
                    continue
                try:
                    reg_cr, priv_cr = fut.result()
                    results[sid.upper()] = (reg_cr, priv_cr)
                except Exception as exc:
                    log.debug("LoggedOn failed for %s: %s",
                              comp.get("dNSHostName", "?"), exc)
                    fail = CollectionResult(Results=[], Collected=False, FailureReason=str(exc))
                    results[sid.upper()] = (fail, fail)

        return results

    def _collect_one(self, comp: dict) -> tuple[CollectionResult, CollectionResult]:
        hostname = comp.get("dNSHostName") or comp.get("sAMAccountName", "").rstrip("$")
        if not hostname:
            err = CollectionResult(Results=[], Collected=False, FailureReason="No hostname")
            return err, err

        comp_sid = (comp.get("objectSid") or "").upper()
        reg_cr   = self._registry_sessions(hostname, comp_sid)
        priv_cr  = self._privileged_sessions(hostname, comp_sid)
        return reg_cr, priv_cr

    # ── Registry sessions (ProfileList) ─────────────────────────────────────

    def _registry_sessions(self, hostname: str, comp_sid: str = "") -> CollectionResult:
        from adwshound.collectors.registry_utils import open_registry, open_hklm, read_dword, enum_subkeys

        try:
            with open_registry(hostname, self.domain, self.username,
                               self.password, self.hashes,
                               self.do_kerberos, self.aes_key, self.kdc_host) as dce:
                h_root = open_hklm(dce)
                profile_sids = enum_subkeys(dce, h_root, _PROFILE_LIST_KEY)
                results = []
                for sid_str in profile_sids:
                    # Skip machine/service account SIDs
                    if any(sid_str.startswith(p) for p in _SKIP_SID_PREFIXES):
                        continue
                    if not sid_str.startswith("S-1-5-21-"):
                        continue

                    # Check if profile is currently loaded (State bit 0x100 or RefCount)
                    state = read_dword(dce, h_root,
                                       f"{_PROFILE_LIST_KEY}\\{sid_str}", "State", 0)
                    ref   = read_dword(dce, h_root,
                                       f"{_PROFILE_LIST_KEY}\\{sid_str}", "RefCount", 0)
                    if not (state and (state & 0x100)) and not ref:
                        continue

                    user_sid = sid_str.upper()
                    results.append(SessionResult(UserSID=user_sid, ComputerSID=comp_sid))

            return CollectionResult(Results=results, Collected=True)
        except Exception as exc:
            return CollectionResult(Results=[], Collected=False, FailureReason=str(exc))

    # ── Privileged sessions (NetWkstaUserEnum) ───────────────────────────────

    def _privileged_sessions(self, hostname: str, comp_sid: str = "") -> CollectionResult:
        from impacket.dcerpc.v5 import transport, wkst
        from adwshound.collectors.base import set_dcerpc_creds

        try:
            binding = rf"ncacn_np:{hostname}[\pipe\wkssvc]"
            trans = transport.DCERPCTransportFactory(binding)
            set_dcerpc_creds(trans, self.username, self.password, self.domain,
                             self.hashes, self.aes_key, self.do_kerberos, self.kdc_host)
            trans.set_connect_timeout(5)
            dce = trans.get_dce_rpc()

            try:
                dce.connect()
                dce.bind(wkst.MSRPC_UUID_WKST)

                resp = wkst.hNetrWkstaUserEnum(dce, 1)
            finally:
                try:
                    dce.disconnect()
                except Exception:
                    pass

            results = []
            for entry in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
                username = entry["wkui1_username"][:-1]  # strip null
                domain   = entry["wkui1_logon_domain"][:-1]
                if not username or username.endswith("$"):
                    continue

                # Resolve to SID using sam_cache first
                user_sid = self._sam_cache.get(username.lower())
                if not user_sid:
                    # Try domain\username lookup in cache
                    user_sid = self._sam_cache.get(f"{domain}\\{username}".lower())

                if user_sid:
                    results.append(SessionResult(UserSID=user_sid.upper(), ComputerSID=comp_sid))

            return CollectionResult(Results=results, Collected=True)
        except Exception as exc:
            return CollectionResult(Results=[], Collected=False, FailureReason=str(exc))
