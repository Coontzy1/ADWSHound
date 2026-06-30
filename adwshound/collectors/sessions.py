"""Session enumeration collector.

Two modes:
1. DC-only (safe/default): query ADWS for domain controllers, then call
   NetSessionEnum over SMB/MSRPC via impacket to retrieve logged-on sessions.
2. All computers: same NetSessionEnum but against every computer.

Sessions are stored in ComputerOutput.Sessions.Results.
"""
from __future__ import annotations

import logging
import concurrent.futures
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import SessionResult, CollectionResult

if TYPE_CHECKING:
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)

# DC filter: SERVER_TRUST_ACCOUNT bit set
_DC_FILTER = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
_ALL_COMPUTERS_FILTER = "(objectClass=computer)"

_COMPUTER_ATTRS = ["objectSid", "dNSHostName", "sAMAccountName"]


class SessionCollector:
    def __init__(
        self,
        client: "ADWSClient",
        cache: "ResolverCache",
        domain: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        dc_only: bool = True,
        threads: int = 10,
        sam_cache: Optional[dict] = None,
        allowed_sids: Optional[set] = None,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.client = client
        self.cache = cache
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.dc_only = dc_only
        self.threads = threads
        self.do_kerberos = do_kerberos
        self.aes_key = aes_key
        self.kdc_host = kdc_host
        # sAMAccountName (lowercase) → SID string; avoids per-session ADWS queries
        self._sam_cache: dict[str, str] = sam_cache or {}
        # Optional allowlist of computer SIDs (upper) that passed the TCP:445
        # precheck; None = no filter (query all matched computers).
        self._allowed_sids: Optional[set] = allowed_sids

    def collect(self) -> dict[str, CollectionResult]:
        """Return dict mapping computer_sid → CollectionResult with session results."""
        ldap_filter = _DC_FILTER if self.dc_only else _ALL_COMPUTERS_FILTER
        log.info("Enumerating sessions (%s mode) …", "DC-only" if self.dc_only else "all-computers")

        computers = self.client.search(ldap_filter, _COMPUTER_ATTRS)
        if self._allowed_sids is not None:
            computers = [c for c in computers
                         if (c.get("objectSid") or "").upper() in self._allowed_sids]
        results: dict[str, CollectionResult] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._enum_sessions, c): c
                for c in computers
            }
            for fut in concurrent.futures.as_completed(future_map):
                comp = future_map[fut]
                sid = comp.get("objectSid")
                if not sid:
                    continue
                try:
                    result = fut.result()
                    results[sid.upper()] = result
                except Exception as exc:
                    log.debug("Session enum failed for %s: %s",
                              comp.get("dNSHostName", "?"), exc)
                    results[sid.upper()] = CollectionResult(
                        Results=[], Collected=False,
                        FailureReason=str(exc),
                    )

        log.info("Session collection complete: %d computers queried", len(results))
        return results

    def _enum_sessions(self, comp: dict) -> CollectionResult:
        hostname = comp.get("dNSHostName") or comp.get("sAMAccountName", "").rstrip("$")
        if not hostname:
            return CollectionResult(Results=[], Collected=False, FailureReason="No hostname")

        try:
            sessions = _net_session_enum(
                hostname, self.domain, self.username,
                self.password, self.hashes,
                self.do_kerberos, self.aes_key, self.kdc_host,
            )
            resolved = []
            comp_sid = comp.get("objectSid", "")
            for user_str in sessions:
                # user_str is "\\domain\username" or "domain\username"
                user_name = user_str.strip("\\").split("\\")[-1]
                # Use pre-built cache first; fall back to live ADWS query on miss
                user_sid = self._sam_cache.get(user_name.lower())
                if not user_sid:
                    objs = self.client.search(
                        f"(sAMAccountName={user_name})", ["objectSid"]
                    )
                    if objs and "objectSid" in objs[0]:
                        user_sid = objs[0]["objectSid"].upper()
                if user_sid:
                    resolved.append(SessionResult(
                        UserSID=user_sid.upper(),
                        ComputerSID=comp_sid.upper() if comp_sid else "",
                    ))

            return CollectionResult(Results=resolved, Collected=True)
        except Exception as exc:
            return CollectionResult(
                Results=[], Collected=False,
                FailureReason=str(exc),
            )


def _net_session_enum(
    hostname: str,
    domain: str,
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    do_kerberos: bool = False,
    aes_key: str = "",
    kdc_host: Optional[str] = None,
) -> list[str]:
    """Call NetSessionEnum via impacket MSRPC and return list of session user strings."""
    from impacket.dcerpc.v5 import transport, srvs
    from impacket.dcerpc.v5.dtypes import NULL
    from adwshound.collectors.base import set_dcerpc_creds

    string_binding = f"ncacn_np:{hostname}[\\pipe\\srvsvc]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    set_dcerpc_creds(rpctransport, username, password, domain, hashes,
                     aes_key, do_kerberos, kdc_host)
    rpctransport.set_connect_timeout(5)

    dce = rpctransport.get_dce_rpc()
    try:
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        sessions = []
        for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            user = session["sesi10_username"][:-1]  # strip null
            if user and not user.startswith("ANONYMOUS"):
                sessions.append(user)
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return sessions
