"""User Rights Assignment collection via LSA MSRPC.

Enumerates accounts holding each privilege via LsarEnumerateAccountsWithUserRight.
"""
from __future__ import annotations

import logging
import concurrent.futures
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import UserRight, TypedPrincipal, CollectionResult

if TYPE_CHECKING:
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)

# Privileges relevant for BloodHound attack paths
_QUERY_RIGHTS = [
    "SeRemoteInteractiveLogonRight",   # RDP
    "SeInteractiveLogonRight",         # Local logon
    "SeNetworkLogonRight",             # Network logon
    "SeBatchLogonRight",
    "SeServiceLogonRight",
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeTcbPrivilege",                  # Act as OS component
    "SeEnableDelegationPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeSecurityPrivilege",
]

# Skip SIDs that are too noisy / not useful for BH
_SKIP_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


class UserRightsCollector:

    def __init__(
        self,
        domain: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        cache: "ResolverCache",
        threads: int = 10,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.domain   = domain
        self.username = username
        self.password = password
        self.hashes   = hashes
        self.cache    = cache
        self.threads  = threads
        self.do_kerberos = do_kerberos
        self.aes_key  = aes_key
        self.kdc_host = kdc_host

    def collect(self, computers: list) -> dict[str, CollectionResult]:
        """Return {comp_sid: CollectionResult(Results=[UserRight, ...])} per computer."""
        results: dict[str, CollectionResult] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._collect_one, comp): comp
                for comp in computers
            }
            for fut in concurrent.futures.as_completed(future_map):
                comp = future_map[fut]
                sid  = comp.get("objectSid", "")
                if not sid:
                    continue
                try:
                    cr = fut.result()
                    results[sid.upper()] = cr
                except Exception as exc:
                    log.debug("UserRights failed for %s: %s",
                              comp.get("dNSHostName", "?"), exc)
                    results[sid.upper()] = CollectionResult(
                        Results=[], Collected=False, FailureReason=str(exc)
                    )

        return results

    def _collect_one(self, comp: dict) -> CollectionResult:
        hostname = comp.get("dNSHostName") or comp.get("sAMAccountName", "").rstrip("$")
        if not hostname:
            return CollectionResult(Results=[], Collected=False, FailureReason="No hostname")

        from impacket.dcerpc.v5 import transport, lsad
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from adwshound.collectors.base import set_dcerpc_creds

        try:
            binding = rf"ncacn_np:{hostname}[\pipe\lsarpc]"
            trans = transport.DCERPCTransportFactory(binding)
            set_dcerpc_creds(trans, self.username, self.password, self.domain,
                             self.hashes, self.aes_key, self.do_kerberos, self.kdc_host)
            trans.set_connect_timeout(5)
            dce = trans.get_dce_rpc()

            try:
                dce.connect()
                dce.bind(lsad.MSRPC_UUID_LSAD)

                resp = lsad.hLsarOpenPolicy2(
                    dce,
                    MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES,
                )
                policy_handle = resp["PolicyHandle"]

                rights_data: list[UserRight] = []
                for right_name in _QUERY_RIGHTS:
                    try:
                        enum_resp = lsad.hLsarEnumerateAccountsWithUserRight(
                            dce, policy_handle, right_name
                        )
                        principals = []
                        for sid_info in enum_resp["EnumerationBuffer"]["Information"]:
                            try:
                                sid_str = sid_info["Sid"].formatCanonical()
                            except Exception:
                                continue
                            if sid_str in _SKIP_SIDS:
                                continue
                            tp = self.cache.resolve_sid(sid_str)
                            if not tp:
                                tp = TypedPrincipal(
                                    ObjectIdentifier=self.cache.qualify_sid(sid_str),
                                    ObjectType="Base",
                                )
                            principals.append(tp)

                        if principals:
                            rights_data.append(UserRight(
                                Privilege=right_name,
                                Results=principals,
                            ))
                    except Exception:
                        # No accounts have this right — normal
                        pass

                lsad.hLsarClose(dce, policy_handle)
            finally:
                try:
                    dce.disconnect()
                except Exception:
                    pass

            return CollectionResult(Results=rights_data, Collected=True)

        except Exception as exc:
            return CollectionResult(Results=[], Collected=False, FailureReason=str(exc))
