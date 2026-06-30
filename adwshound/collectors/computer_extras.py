"""Per-computer auxiliary collection: WebClient, SmbInfo, NTLMRegistry, DCRegistry, LdapServices.

All use WinReg MSRPC or SMB/SCM to gather data not available via ADWS/LDAP.
"""
from __future__ import annotations

import logging
import concurrent.futures
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import (
    DCRegistryData, SmbInfoData, NTLMRegistryData, LdapServicesData,
)
from adwshound.collectors.registry_utils import (
    open_registry, open_hklm, read_dword,
)

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ─── Registry key paths ───────────────────────────────────────────────────────

_SCHANNEL_KEY   = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
_KDC_KEY        = r"SYSTEM\CurrentControlSet\Services\Kdc"
_NETLOGON_PARAMS = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
_LSA_KEY        = r"SYSTEM\CurrentControlSet\Control\Lsa"
_NETLOGON_KEY   = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
_LANMAN_KEY     = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
_NTDS_KEY       = r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters"


# ─── DCRegistry (DC-only) ─────────────────────────────────────────────────────

def _int_reg_result(value: Optional[int]) -> Optional[dict]:
    """Wrap a registry int as BloodHound's IntRegistryAPIResult shape.

    None (key absent / not read) stays null; Go reads that as the zero value.
    """
    if value is None:
        return None
    return {"Collected": True, "FailureReason": None, "Value": value}


def _bool_api_result(value: Optional[bool]) -> Optional[dict]:
    """Wrap a bool as BloodHound's BoolAPIResult shape (null stays null)."""
    if value is None:
        return None
    return {"Collected": True, "FailureReason": None, "Value": bool(value)}


def collect_dc_registry(
    hostname: str, domain: str, username: str,
    password: Optional[str], hashes: Optional[str],
    do_kerberos: bool = False, aes_key: str = "", kdc_host: Optional[str] = None,
) -> DCRegistryData:
    """Read certificate mapping, Netlogon security from DC registry."""
    try:
        with open_registry(hostname, domain, username, password, hashes,
                           do_kerberos, aes_key, kdc_host) as dce:
            h_root = open_hklm(dce)
            cert_map   = read_dword(dce, h_root, _SCHANNEL_KEY,
                                    "CertificateMappingMethods")
            strong_cert = read_dword(dce, h_root, _KDC_KEY,
                                     "StrongCertificateBindingEnforcement")
        # BloodHound expects CertificateMappingMethods / StrongCertificateBinding-
        # Enforcement as IntRegistryAPIResult objects ({Collected, FailureReason,
        # Value}), not raw ints — a bare scalar fails ingest ("cannot unmarshal
        # ... into Go struct field"). VulnerableNetlogonSecurityDescriptor is a
        # distinct Go struct type; SharpHound never emits it, so leave it null
        # (Go reads null as the zero value) rather than risk another type clash.
        return DCRegistryData(
            CertificateMappingMethods=_int_reg_result(cert_map),
            StrongCertificateBindingEnforcement=_int_reg_result(strong_cert),
            VulnerableNetlogonSecurityDescriptor=None,
        )
    except Exception as exc:
        log.debug("DCRegistry failed for %s: %s", hostname, exc)
        return DCRegistryData()


# ─── WebClient service check ──────────────────────────────────────────────────

def check_webclient(
    hostname: str, domain: str, username: str,
    password: Optional[str], hashes: Optional[str],
    do_kerberos: bool = False, aes_key: str = "", kdc_host: Optional[str] = None,
) -> Optional[bool]:
    """Return True if WebClient service is running on hostname, None on failure."""
    from impacket.dcerpc.v5 import transport, scmr
    from adwshound.collectors.base import set_dcerpc_creds
    try:
        binding = rf"ncacn_np:{hostname}[\pipe\svcctl]"
        trans = transport.DCERPCTransportFactory(binding)
        set_dcerpc_creds(trans, username, password, domain, hashes,
                         aes_key, do_kerberos, kdc_host)
        trans.set_connect_timeout(5)
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        try:
            sc_handle = scmr.hROpenSCManagerW(dce, hostname)["lpScHandle"]
            try:
                svc = scmr.hROpenServiceW(dce, sc_handle, "WebClient")["lpServiceHandle"]
                status = scmr.hRQueryServiceStatus(dce, svc)
                running = (status["lpServiceStatus"]["dwCurrentState"] ==
                           scmr.SERVICE_RUNNING)
                scmr.hRCloseServiceHandle(dce, svc)
                return running
            except Exception:
                return False
            finally:
                try:
                    scmr.hRCloseServiceHandle(dce, sc_handle)
                except Exception:
                    pass
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
    except Exception as exc:
        log.debug("WebClient check failed for %s: %s", hostname, exc)
        return None


# ─── SMB Info ─────────────────────────────────────────────────────────────────

def collect_smb_info(
    hostname: str, domain: str, username: str,
    password: Optional[str], hashes: Optional[str],
    os_version: Optional[str] = None,
    do_kerberos: bool = False, aes_key: str = "", kdc_host: Optional[str] = None,
) -> Optional[SmbInfoData]:
    """Collect SMB signing and SMBv1 status via registry and SMB negotiation."""
    try:
        with open_registry(hostname, domain, username, password, hashes,
                           do_kerberos, aes_key, kdc_host) as dce:
            h_root = open_hklm(dce)
            require_sign = read_dword(dce, h_root, _LANMAN_KEY,
                                      "RequireSecuritySignature", 0)
            enable_sign  = read_dword(dce, h_root, _LANMAN_KEY,
                                      "EnableSecuritySignature", 0)
            smb1_val     = read_dword(dce, h_root, _LANMAN_KEY, "SMB1", 1)

        return SmbInfoData(
            Signing=bool(require_sign),
            SigningEnabled=bool(require_sign or enable_sign),
            SMBv1Enabled=bool(smb1_val),
            OsVersion=os_version,
        )
    except Exception as exc:
        log.debug("SmbInfo failed for %s: %s", hostname, exc)
        return None


# ─── NTLM Registry ───────────────────────────────────────────────────────────

def collect_ntlm_registry(
    hostname: str, domain: str, username: str,
    password: Optional[str], hashes: Optional[str],
    do_kerberos: bool = False, aes_key: str = "", kdc_host: Optional[str] = None,
) -> Optional[NTLMRegistryData]:
    """Collect NTLM configuration from registry."""
    try:
        with open_registry(hostname, domain, username, password, hashes,
                           do_kerberos, aes_key, kdc_host) as dce:
            h_root = open_hklm(dce)
            lm_compat      = read_dword(dce, h_root, _LSA_KEY, "LmCompatibilityLevel")
            no_lm_hash     = read_dword(dce, h_root, _LSA_KEY, "NoLMHash")
            restrict_dom   = read_dword(dce, h_root, _NETLOGON_KEY,
                                        "RestrictNTLMInDomain")
            restrict_send  = read_dword(dce, h_root, _NETLOGON_KEY,
                                        "RestrictSendingNTLMTraffic")
            incoming_filt  = read_dword(dce, h_root, _NETLOGON_KEY,
                                        "InboundNTLMFilter")

        return NTLMRegistryData(
            LmCompatibilityLevel=lm_compat,
            NoLMHash=bool(no_lm_hash) if no_lm_hash is not None else None,
            RestrictNTLMInDomain=restrict_dom,
            RestrictSendingNTLMTraffic=restrict_send,
            IncomingNTLMFilter=incoming_filt,
        )
    except Exception as exc:
        log.debug("NTLMRegistry failed for %s: %s", hostname, exc)
        return None


# ─── LDAP Services (DC-only) ─────────────────────────────────────────────────

def collect_ldap_services(
    hostname: str, domain: str, username: str,
    password: Optional[str], hashes: Optional[str],
    do_kerberos: bool = False, aes_key: str = "", kdc_host: Optional[str] = None,
) -> Optional[LdapServicesData]:
    """Collect LDAP signing and channel binding settings from DC registry."""
    try:
        with open_registry(hostname, domain, username, password, hashes,
                           do_kerberos, aes_key, kdc_host) as dce:
            h_root = open_hklm(dce)
            ldap_sign = read_dword(dce, h_root, _NTDS_KEY,
                                   "LDAPServerIntegrity")
            ldap_bind = read_dword(dce, h_root, _NTDS_KEY,
                                   "LdapEnforceChannelBinding")

        return LdapServicesData(
            LdapSigning=ldap_sign,
            LdapChannelBinding=ldap_bind,
        )
    except Exception as exc:
        log.debug("LdapServices failed for %s: %s", hostname, exc)
        return None


# ─── Parallel per-computer collection ────────────────────────────────────────

class ComputerExtrasCollector:
    """Runs all enabled extra collectors per computer in parallel."""

    def __init__(
        self,
        domain: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        threads: int = 10,
        collect_webclient: bool = False,
        collect_smb: bool = False,
        collect_ntlm: bool = False,
        collect_dc_reg: bool = False,
        collect_ldap: bool = False,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.domain            = domain
        self.username          = username
        self.password          = password
        self.hashes            = hashes
        self.threads           = threads
        self.collect_webclient = collect_webclient
        self.collect_smb       = collect_smb
        self.collect_ntlm      = collect_ntlm
        self.collect_dc_reg    = collect_dc_reg
        self.collect_ldap      = collect_ldap
        self._krb = dict(do_kerberos=do_kerberos, aes_key=aes_key, kdc_host=kdc_host)

    def collect(self, computers: list) -> dict:
        """Return {comp_sid: dict_of_extras}."""
        results = {}
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
                    results[sid.upper()] = fut.result()
                except Exception as exc:
                    log.debug("ComputerExtras failed for %s: %s",
                              comp.get("dNSHostName", "?"), exc)
                    results[sid.upper()] = {}
        return results

    def _collect_one(self, comp: dict) -> dict:
        hostname  = comp.get("dNSHostName") or comp.get("sAMAccountName", "").rstrip("$")
        is_dc     = bool(comp.get("_is_dc", False))
        os_ver    = comp.get("_os_version")
        extras    = {}

        creds = (hostname, self.domain, self.username, self.password, self.hashes)

        if self.collect_webclient:
            # BloodHound expects IsWebClientRunning as a BoolAPIResult object,
            # not a bare bool ("cannot unmarshal bool into ... ein.BoolAPIResult").
            extras["webclient"] = _bool_api_result(check_webclient(*creds, **self._krb))

        if self.collect_smb:
            extras["smbinfo"] = collect_smb_info(*creds, os_version=os_ver, **self._krb)

        if self.collect_ntlm:
            extras["ntlm"] = collect_ntlm_registry(*creds, **self._krb)

        if self.collect_dc_reg and is_dc:
            extras["dcregistry"] = collect_dc_registry(*creds, **self._krb)

        if self.collect_ldap and is_dc:
            extras["ldapservices"] = collect_ldap_services(*creds, **self._krb)

        return extras
