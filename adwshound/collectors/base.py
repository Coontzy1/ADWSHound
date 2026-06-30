"""Base collector ABC and shared helpers."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)


def _ci_get(obj: dict, key: str, default=None):
    """dict.get with a case-insensitive fallback.

    ADWS returns attributes under their canonical schema name (e.g. gPLink),
    which may differ in case from how a collector requests/reads them. Falling
    back to a case-insensitive match avoids silent misses.
    """
    if key in obj:
        return obj[key]
    kl = key.lower()
    for k, v in obj.items():
        if k.lower() == kl:
            return v
    return default


def first(obj: dict, key: str, default=None):
    """Return obj[key] (case-insensitive), unwrapping single-element lists."""
    val = _ci_get(obj, key, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val


def as_list(obj: dict, key: str) -> list:
    """Return obj[key] always as a list (case-insensitive; missing/scalar/list)."""
    val = _ci_get(obj, key)
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def uac_flag(uac: int, flag: int) -> bool:
    return bool(uac & flag)


# userAccountControl bit flags we care about
UAC_ACCOUNTDISABLE           = 0x0002
UAC_PASSWD_NOTREQD           = 0x0020
UAC_PASSWD_CANT_CHANGE       = 0x0040
UAC_ENCRYPTED_TEXT_PWD       = 0x0080
UAC_DONT_EXPIRE_PASSWORD     = 0x10000
UAC_SMARTCARD_REQUIRED       = 0x40000
UAC_TRUSTED_FOR_DELEGATION   = 0x80000
UAC_NOT_DELEGATED            = 0x100000
UAC_USE_DES_KEY_ONLY         = 0x200000
UAC_DONT_REQ_PREAUTH         = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELG = 0x1000000
UAC_SERVER_TRUST_ACCOUNT     = 0x2000  # domain controller


_ENC_TYPE_NAMES = {
    0x01: "DES-CBC-CRC",
    0x02: "DES-CBC-MD5",
    0x04: "RC4-HMAC-MD5",
    0x08: "AES128-CTS-HMAC-SHA1-96",
    0x10: "AES256-CTS-HMAC-SHA1-96",
    0x20: "AES256-CTS-HMAC-SHA1-96-SK",
}


def encryption_types(raw) -> list | None:
    """Convert msDS-SupportedEncryptionTypes integer to BloodHound string array."""
    if raw is None:
        return None
    try:
        mask = int(raw)
    except (TypeError, ValueError):
        return None
    result = [name for bit, name in _ENC_TYPE_NAMES.items() if mask & bit]
    return result or None


def install_dns_override(server: str) -> None:
    """Route all hostname resolution through `server` (a DNS server IP).

    Patches socket.getaddrinfo once so every connection site — the TCP:445
    precheck and all impacket SMB/RPC transports — resolves target FQDNs via
    the chosen DNS (typically the DC), regardless of the host's /etc/resolv.conf.
    Literal IPs and lookups that fail fall back to the original resolver.
    """
    import socket
    import functools
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = 5.0

    _orig_getaddrinfo = socket.getaddrinfo

    @functools.lru_cache(maxsize=4096)
    def _resolve(host: str) -> str | None:
        try:
            ans = resolver.resolve(host, "A")
            return str(ans[0])
        except Exception:
            return None

    def _patched(host, *args, **kwargs):
        if isinstance(host, str):
            try:
                socket.inet_aton(host)          # already an IPv4 literal
            except OSError:
                ip = _resolve(host)
                if ip:
                    host = ip
        return _orig_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = _patched
    log.info("DNS resolution routed through %s", server)


def check_tcp(hostname: str, port: int = 445, timeout: float = 2.0) -> bool:
    """Return True if hostname:port accepts a TCP connection within timeout."""
    import socket
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def split_hashes(hashes: str | None) -> tuple[str, str]:
    """Return (lm, nt) from a 'LM:NT' or ':NT' string (empty strings if absent)."""
    if not hashes:
        return "", ""
    if ":" in hashes:
        parts = hashes.split(":", 1)
        return parts[0], parts[1]
    return "", hashes


def set_dcerpc_creds(rpctransport, username, password, domain, hashes=None,
                     aes_key="", do_kerberos=False, kdc_host=None) -> None:
    """Apply credentials to an impacket DCERPC transport, with optional Kerberos.

    Kerberos avoids NTLM on the wire entirely (no 4776 events; blends with normal
    AD traffic) — but requires the target be reachable by FQDN/SPN, and a KDC.
    """
    lm, nt = split_hashes(hashes)
    rpctransport.set_credentials(username, password or "", domain, lm, nt, aes_key or "")
    if do_kerberos:
        rpctransport.set_kerberos(True, kdcHost=kdc_host)


def smb_login(conn, username, password, domain, hashes=None,
              aes_key="", do_kerberos=False, kdc_host=None) -> None:
    """Log an impacket SMBConnection in via Kerberos when requested, else NTLM."""
    lm, nt = split_hashes(hashes)
    if do_kerberos:
        conn.kerberosLogin(username, password or "", domain, lm, nt,
                           aes_key or "", kdcHost=kdc_host or "")
    else:
        conn.login(username, password or "", domain, lm, nt)


def dn_to_domain(dn: str) -> str:
    """Extract domain FQDN from a distinguished name."""
    parts = [p.strip() for p in dn.upper().split(",")]
    dc_parts = [p[3:] for p in parts if p.startswith("DC=")]
    return ".".join(dc_parts)


def object_name(cn: str, domain: str) -> str:
    """Build BloodHound display name: NAME@DOMAIN.LOCAL"""
    return f"{cn.upper()}@{domain.upper()}"


class BaseCollector(ABC):
    """ABC for all per-object-type collectors."""

    def __init__(
        self,
        client: "ADWSClient",
        cache: "ResolverCache",
        domain: str,
        domain_sid: str,
        collect_acls: bool = False,
        collect_all_props: bool = False,
        adminsdholder_hash: str | None = None,
    ):
        self.client = client
        self.cache = cache
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self.collect_acls = collect_acls
        self.collect_all_props = collect_all_props
        self.adminsdholder_hash = adminsdholder_hash
        self.log = logging.getLogger(self.__class__.__name__)

    def _is_adminsdholder_protected(self, aces: list) -> bool:
        """Return True if object's non-inherited ACEs match the AdminSDHolder hash."""
        if not self.adminsdholder_hash:
            return False
        import hashlib
        direct = [a for a in aces if not a.IsInherited]
        canonical = "|".join(
            sorted(f"{a.PrincipalSID}:{a.RightName}" for a in direct)
        )
        return hashlib.sha1(canonical.encode()).hexdigest().upper() == self.adminsdholder_hash

    def _attrs(self, base_attrs: list) -> list:
        """Return attribute list — wildcard when --collectallproperties is set."""
        if self.collect_all_props:
            return ["*"]
        return base_attrs

    @abstractmethod
    def collect(self) -> list:
        """Run collection and return list of output objects."""
