"""ADCS (Active Directory Certificate Services) collectors.

Queries Configuration NC for all ADCS objects:
  RootCA, AIACA, EnterpriseCA, NTAuthStore, CertTemplate, IssuancePolicy

All objects live under:
  CN=Public Key Services,CN=Services,CN=Configuration,<DOMAIN_DN>

Registry-based collection (non-ADWS, uses MSRPC/WinReg via impacket):
  - CA security descriptor → ManageCA / ManageCertificates ACEs
  - EditFlags registry value → IsUserSpecifiesSanEnabled (ESC6 detection)
"""
from __future__ import annotations

import hashlib
import logging
import struct
import urllib.request
import urllib.error
from typing import Optional, TYPE_CHECKING

from adwshound.collectors.base import BaseCollector, first, as_list, object_name
from adwshound.collectors.acls import parse_acl
from adwshound.schema.types import (
    TypedPrincipal,
    RootCAOutput, AIACAOutput, EnterpriseCAOutput,
    NTAuthStoreOutput, CertTemplateOutput, IssuancePolicyOutput,
    CARegistryData, CASecurityResult, CAEnrollmentRestrictions, CABoolResult,
)

if TYPE_CHECKING:
    from adwshound.transport.client import ADWSClient
    from adwshound.resolvers.cache import ResolverCache

log = logging.getLogger(__name__)

# ─── LDAP filters ─────────────────────────────────────────────────────────────

_FILTER_ROOT_CA      = "(objectClass=certificationAuthority)"
_FILTER_ENTERPRISE   = "(objectClass=pKIEnrollmentService)"
_FILTER_CERT_TPL     = "(objectClass=pKICertificateTemplate)"
_FILTER_ISSUANCE     = "(objectClass=msPKI-Enterprise-Oid)"

_ATTRS_CA_BASE = [
    "objectGUID", "cn", "distinguishedName", "whenCreated",
    "cACertificate", "nTSecurityDescriptor",
]
_ATTRS_AIACA = _ATTRS_CA_BASE + ["crossCertificatePair"]
_ATTRS_ENTERPRISE = [
    "objectGUID", "cn", "distinguishedName", "whenCreated",
    "cACertificate", "certificateTemplates", "dNSHostName",
    "flags", "nTSecurityDescriptor",
]
_ATTRS_NTAUTH = _ATTRS_CA_BASE[:]
_ATTRS_CERT_TPL = [
    "objectGUID", "cn", "displayName", "distinguishedName", "whenCreated",
    "msPKI-Cert-Template-OID", "msPKI-Template-Schema-Version",
    "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
    "msPKI-RA-Signature", "msPKI-Private-Key-Flag",
    "msPKI-Certificate-Application-Policy", "msPKI-RA-Policies",
    "msPKI-Certificate-Policy",
    "pKIExtendedKeyUsage", "pKIExpirationPeriod", "pKIOverlapPeriod",
    "nTSecurityDescriptor",
]
_ATTRS_ISSUANCE = [
    "objectGUID", "cn", "displayName", "distinguishedName", "whenCreated",
    "flags",  # 1 = per-template OID, 2 = issuance policy (only 2 is emitted)
    "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink",
    "nTSecurityDescriptor",
]

# ─── Period conversion ────────────────────────────────────────────────────────

_TICKS_YEAR  = 365 * 864_000_000_000
_TICKS_MONTH = 30  * 864_000_000_000
_TICKS_WEEK  = 7   * 864_000_000_000
_TICKS_DAY   = 864_000_000_000
_TICKS_HOUR  = 36_000_000_000


def _bytes_to_period(data) -> str:
    """Convert 8-byte LE Windows negative interval to human-readable period."""
    if not data or not isinstance(data, (bytes, bytearray)):
        return "0"
    try:
        ticks = abs(struct.unpack("<q", data[:8])[0])
    except struct.error:
        return "0"
    if ticks == 0:
        return "0"
    for unit, name in (
        (_TICKS_YEAR,  "year"),
        (_TICKS_MONTH, "month"),
        (_TICKS_WEEK,  "week"),
        (_TICKS_DAY,   "day"),
        (_TICKS_HOUR,  "hour"),
    ):
        if ticks >= unit and ticks % unit == 0:
            n = ticks // unit
            return f"{n} {name}{'s' if n > 1 else ''}"
    return f"{ticks // _TICKS_DAY} days"


# ─── Cert thumbprint ─────────────────────────────────────────────────────────

def _thumbprint(cert_bytes) -> str | None:
    if not cert_bytes or not isinstance(cert_bytes, (bytes, bytearray)):
        return None
    return hashlib.sha1(cert_bytes).hexdigest().upper()


def _cert_chain(cert_value) -> list[str]:
    """Build certchain list from cACertificate (single bytes or list)."""
    if not cert_value:
        return []
    if isinstance(cert_value, (bytes, bytearray)):
        t = _thumbprint(cert_value)
        return [t] if t else []
    if isinstance(cert_value, list):
        result = []
        for c in cert_value:
            t = _thumbprint(c)
            if t:
                result.append(t)
        return result
    return []


# ─── bitmask → flag-name string ──────────────────────────────────────────────

_ENROLLMENT_FLAGS = {
    0x00000001: "INCLUDE_SYMMETRIC_ALGORITHMS",
    0x00000002: "PEND_ALL_REQUESTS",
    0x00000004: "PUBLISH_TO_DS",
    0x00000008: "EXPORTABLE_KEY",
    0x00000010: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    0x00000020: "AUTO_ENROLLMENT",
    0x00000040: "PREVIOUS_APPROVAL",
    0x00000080: "USER_INTERACTION_REQUIRED",
    0x00000100: "ADD_TEMPLATE_NAME",
    0x00000200: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    0x00000400: "ALLOW_ENROLL_ON_BEHALF_OF",
    0x00000800: "ADD_OCSP_NOCHECK",
    0x00001000: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    0x00002000: "NOREVOCATIONINFOINISSUEDCERTS",
    0x00004000: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    0x00008000: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL",
    0x00010000: "CERTIFICATE_ISSUANCE_POLICIES_FROM_REQUEST",
    0x00020000: "SKIP_AUTO_RENEWAL",
}

_CERT_NAME_FLAGS = {
    0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
    0x00010000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    0x00400000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x00800000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    0x01000000: "SUBJECT_ALT_REQUIRE_DNS",
    0x02000000: "SUBJECT_ALT_REQUIRE_EMAIL",
    0x04000000: "SUBJECT_ALT_REQUIRE_UPN",
    0x08000000: "SUBJECT_ALT_REQUIRE_SPN",
    0x10000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    0x20000000: "SUBJECT_REQUIRE_COMMON_NAME",
    0x40000000: "SUBJECT_REQUIRE_EMAIL",
    0x80000000: "SUBJECT_REQUIRE_DNS_AS_CN",
}

# EKUs that enable authentication (used for ESC detection)
_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",        # Client Authentication
    "1.3.6.1.5.2.3.4",           # PKINIT Client Auth
    "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
    "2.5.29.37.0",               # Any Purpose
}
_SCHANNEL_EKUS = {
    "1.3.6.1.5.5.7.3.1",        # Server Authentication
}


def _flags_to_str(mask: int, flag_map: dict) -> str:
    names = [name for bit, name in sorted(flag_map.items()) if mask & bit]
    return ", ".join(names) if names else "NONE"


# ─── ACL helper ──────────────────────────────────────────────────────────────

def _parse_acl_safe(sd_bytes, cache, identifier, props):
    """Parse SD, set isaclprotected + doesanyace* flags, return cleaned aces."""
    if not sd_bytes or not isinstance(sd_bytes, bytes):
        return []
    aces, is_protected = parse_acl(sd_bytes, cache, identifier)
    props["isaclprotected"] = is_protected
    _or_aces = [a for a in aces if a.PrincipalSID == "S-1-3-4"]
    props["doesanyacegrantownerrights"] = any(not a.IsInherited for a in _or_aces)
    props["doesanyinheritedacegrantownerrights"] = any(a.IsInherited for a in _or_aces)
    return [a for a in aces if a.PrincipalSID != "S-1-3-4"]


# ─── Base properties shared by all ADCS objects ──────────────────────────────

def _base_props(obj: dict, cn: str, domain: str, domain_sid: str) -> dict:
    return {
        "domain":            domain,
        "name":              object_name(cn, domain),
        "distinguishedname": (first(obj, "distinguishedName", "") or "").upper(),
        "domainsid":         domain_sid,
        "doesanyacegrantownerrights":          False,
        "doesanyinheritedacegrantownerrights": False,
        "isaclprotected":    False,
        "whencreated":       obj.get("whenCreated", -1),
    }


# ─── CA cert properties ───────────────────────────────────────────────────────

def _ca_cert_props(obj: dict) -> dict:
    cert = obj.get("cACertificate")
    chain = _cert_chain(cert)
    thumb = chain[0] if chain else None
    return {
        "certthumbprint":          thumb,
        "certname":                thumb,
        "certchain":               chain,
        "hasbasicconstraints":     False,
        "basicconstraintpathlength": 0,
    }


# ─── DN container helpers ────────────────────────────────────────────────────

def _in_container(dn: str, container: str) -> bool:
    return container.upper() in dn.upper()


# ─── Collectors ──────────────────────────────────────────────────────────────

class ADCSCollector:
    """Single collector that produces all 6 ADCS output types.

    Uses ADWS for object discovery + properties.
    Uses MSRPC/WinReg for CA registry data (ManageCA, ManageCertificates, ESC6).
    Uses HTTP for enrollment endpoint detection.
    """

    def __init__(
        self,
        client: "ADWSClient",
        cache: "ResolverCache",
        domain: str,
        domain_sid: str,
        collect_acls: bool = False,
        username: str = "",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        do_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: Optional[str] = None,
    ):
        self.client       = client
        self.cache        = cache
        self.domain       = domain.upper()
        self.domain_sid   = domain_sid
        self.collect_acls = collect_acls
        self.username     = username
        self.password     = password
        self.hashes       = hashes
        self.do_kerberos  = do_kerberos
        self.aes_key      = aes_key
        self.kdc_host     = kdc_host
        self.log          = logging.getLogger(self.__class__.__name__)

    # ── Public entry points ──────────────────────────────────────────────────

    def collect_rootcas(self) -> list[RootCAOutput]:
        self.log.info("Collecting RootCAs …")
        objects = self.client.search_config_nc(_FILTER_ROOT_CA, _ATTRS_CA_BASE)
        return [
            self._process_rootca(obj) for obj in objects
            if _in_container(first(obj, "distinguishedName", ""), "CN=CERTIFICATION AUTHORITIES")
        ]

    def collect_aiacas(self) -> list[AIACAOutput]:
        self.log.info("Collecting AIACAs …")
        objects = self.client.search_config_nc(_FILTER_ROOT_CA, _ATTRS_AIACA)
        return [
            self._process_aiaca(obj) for obj in objects
            if _in_container(first(obj, "distinguishedName", ""), "CN=AIA,")
        ]

    def collect_ntauthstores(self) -> list[NTAuthStoreOutput]:
        self.log.info("Collecting NTAuthStores …")
        objects = self.client.search_config_nc(_FILTER_ROOT_CA, _ATTRS_NTAUTH)
        return [
            self._process_ntauth(obj) for obj in objects
            if _in_container(first(obj, "distinguishedName", ""), "CN=NTAUTHCERTIFICATES")
        ]

    def collect_enterprisecas(self) -> list[EnterpriseCAOutput]:
        self.log.info("Collecting EnterpriseCAs …")
        objects = self.client.search_config_nc(_FILTER_ENTERPRISE, _ATTRS_ENTERPRISE)
        return [self._process_enterprise(obj) for obj in objects]

    def collect_certtemplates(self) -> list[CertTemplateOutput]:
        self.log.info("Collecting CertTemplates …")
        objects = self.client.search_config_nc(_FILTER_CERT_TPL, _ATTRS_CERT_TPL)
        return [self._process_certtemplate(obj) for obj in objects]

    def collect_issuancepolicies(self) -> list[IssuancePolicyOutput]:
        self.log.info("Collecting IssuancePolicies …")
        objects = self.client.search_config_nc(_FILTER_ISSUANCE, _ATTRS_ISSUANCE)
        # The OID container holds one auto-generated OID per cert template
        # (flags=1) plus the real issuance policies (flags=2). SharpHound emits
        # only the latter — filter to flags=2 or we inflate the count massively.
        issuance = [o for o in objects if (int(first(o, "flags", 0) or 0) & 2)]
        return [self._process_issuance(obj) for obj in issuance]

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _contained_by(self, dn: str):
        """Resolve parent container for a Config NC object's ContainedBy field."""
        if not dn:
            return None
        idx = dn.find(",")
        if idx == -1:
            return None
        parent_dn = dn[idx + 1:]
        # Config NC containers aren't in the domain cache; look up via ADWS
        tp = self.cache.resolve_dn_to_sid(parent_dn, self.client)
        if tp:
            return tp
        # Fallback: query Config NC directly for the parent object's GUID
        try:
            objs = self.client.search_config_nc(
                f"(distinguishedName={parent_dn})",
                ["objectGUID", "objectClass"],
            )
            if objs:
                guid = objs[0].get("objectGUID")
                if guid:
                    from adwshound.schema.types import TypedPrincipal
                    return TypedPrincipal(ObjectIdentifier=guid.upper(), ObjectType="Container")
        except Exception:
            pass
        return None

    # ── Object processors ───────────────────────────────────────────────────

    def _process_rootca(self, obj: dict) -> RootCAOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn         = first(obj, "distinguishedName", "")
        props      = _base_props(obj, cn, self.domain, self.domain_sid)
        props.update(_ca_cert_props(obj))

        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)

        return RootCAOutput(
            Properties=props,
            DomainSID=self.domain_sid,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn),
        )

    def _process_aiaca(self, obj: dict) -> AIACAOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn         = first(obj, "distinguishedName", "")
        props      = _base_props(obj, cn, self.domain, self.domain_sid)
        props.update(_ca_cert_props(obj))

        cross = as_list(obj, "crossCertificatePair")
        props["crosscertificatepair"] = [_thumbprint(c) for c in cross if c] if cross else []
        props["hascrosscertificatepair"] = bool(props["crosscertificatepair"])

        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)

        return AIACAOutput(
            Properties=props,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn),
        )

    def _process_ntauth(self, obj: dict) -> NTAuthStoreOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn         = first(obj, "distinguishedName", "")
        props      = _base_props(obj, cn, self.domain, self.domain_sid)

        cert = obj.get("cACertificate")
        thumbs = _cert_chain(cert)
        props["certthumbprints"] = thumbs

        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)

        return NTAuthStoreOutput(
            Properties=props,
            DomainSID=self.domain_sid,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn),
        )

    def _process_enterprise(self, obj: dict) -> EnterpriseCAOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn         = first(obj, "distinguishedName", "")
        props      = _base_props(obj, cn, self.domain, self.domain_sid)
        props.update(_ca_cert_props(obj))

        flags_int = int(obj.get("flags") or 0)
        props["flags"]      = _ca_flags_str(flags_int)
        props["caname"]     = cn
        props["catype"]     = "Enterprise"
        dns = first(obj, "dNSHostName", None)
        props["dnshostname"] = dns
        props["unresolvedpublishedtemplates"] = []

        tpl_names        = as_list(obj, "certificateTemplates")
        enabled_templates = self._resolve_templates(tpl_names)

        # ── Hosting computer (ADWS) ──────────────────────────────────────────
        hosting_computer = None
        if dns:
            objs = self.client.search(f"(dNSHostName={dns})", ["objectSid"])
            if objs:
                sid = objs[0].get("objectSid")
                if sid:
                    # BloodHound schema: HostingComputer is a plain SID string
                    hosting_computer = sid.upper()

        # ── Registry-based CA data (MSRPC/WinReg) ───────────────────────────
        ca_sec      = CASecurityResult()
        san_enabled = CABoolResult()
        role_sep    = CABoolResult()

        ea_restr = CAEnrollmentRestrictions()
        if dns and self.username:
            try:
                reg_aces, san_val, role_sep_val, ea_list = _read_ca_registry(
                    hostname=dns,
                    domain=self.domain,
                    username=self.username,
                    password=self.password,
                    hashes=self.hashes,
                    ca_name=cn,
                    cache=self.cache,
                    do_kerberos=self.do_kerberos,
                    aes_key=self.aes_key,
                    kdc_host=self.kdc_host,
                )
                ca_sec      = CASecurityResult(Data=reg_aces, Collected=True, FailureReason=None)
                san_enabled = CABoolResult(Value=san_val, Collected=True, FailureReason=None)
                role_sep    = CABoolResult(Value=role_sep_val, Collected=True, FailureReason=None)
                ea_restr    = CAEnrollmentRestrictions(
                    Restrictions=ea_list, Collected=True, FailureReason=None
                )
            except Exception as exc:
                reason = str(exc)
                ca_sec      = CASecurityResult(Collected=False, FailureReason=reason)
                san_enabled = CABoolResult(Collected=False, FailureReason=reason)
                role_sep    = CABoolResult(Collected=False, FailureReason=reason)
                ea_restr    = CAEnrollmentRestrictions(Collected=False, FailureReason=reason)
                self.log.debug("CA registry collection failed for %s: %s", cn, exc)

        # Update collected flags on properties
        props["casecuritycollected"]                  = ca_sec.Collected
        props["isuserspecifiessanenabledcollected"]   = san_enabled.Collected
        props["roleseparationenabledcollected"]       = role_sep.Collected
        props["enrollmentagentrestrictionscollected"] = False

        # ── HTTP enrollment endpoints ────────────────────────────────────────
        http_endpoints = _check_http_endpoints(dns, cn) if dns else []

        # ── LDAP ACLs ────────────────────────────────────────────────────────
        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)
            # Merge registry CA security ACEs (ManageCA/ManageCertificates)
            if ca_sec.Collected:
                aces = aces + ca_sec.Data

        return EnterpriseCAOutput(
            Properties=props,
            HostingComputer=hosting_computer,
            CARegistryData=CARegistryData(
                CASecurity=ca_sec,
                EnrollmentAgentRestrictions=ea_restr,
                IsUserSpecifiesSanEnabled=san_enabled,
                RoleSeparationEnabled=role_sep,
            ),
            EnabledCertTemplates=enabled_templates,
            HttpEnrollmentEndpoints=http_endpoints,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn),
        )

    def _process_certtemplate(self, obj: dict) -> CertTemplateOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn         = first(obj, "distinguishedName", "")
        props      = _base_props(obj, cn, self.domain, self.domain_sid)

        enroll_flag = int(obj.get("msPKI-Enrollment-Flag") or 0)
        name_flag   = int(obj.get("msPKI-Certificate-Name-Flag") or 0)
        schema_ver  = int(obj.get("msPKI-Template-Schema-Version") or 1)
        ra_sig      = int(obj.get("msPKI-RA-Signature") or 0)
        oid_val     = first(obj, "msPKI-Cert-Template-OID", None)
        display     = first(obj, "displayName", cn)

        # Period fields (come as bytes from transport)
        validity  = _bytes_to_period(obj.get("pKIExpirationPeriod"))
        renewal   = _bytes_to_period(obj.get("pKIOverlapPeriod"))

        ekus     = as_list(obj, "pKIExtendedKeyUsage")
        app_pol  = as_list(obj, "msPKI-Certificate-Application-Policy")
        ra_pol   = as_list(obj, "msPKI-RA-Policies")
        cert_pol = as_list(obj, "msPKI-Certificate-Policy")

        # Determine effective EKUs for authentication
        all_ekus    = set(ekus) | set(app_pol)
        auth_enabled = bool(all_ekus & _AUTH_EKUS) or (not ekus and not app_pol)
        sch_enabled  = bool(all_ekus & _SCHANNEL_EKUS)

        props.update({
            "displayname":               display,
            "oid":                       oid_val,
            "schemaversion":             schema_ver,
            "validityperiod":            validity,
            "renewalperiod":             renewal,
            "enrollmentflag":            _flags_to_str(enroll_flag, _ENROLLMENT_FLAGS),
            "certificatenameflag":       _flags_to_str(name_flag, _CERT_NAME_FLAGS),
            "requiresmanagerapproval":   bool(enroll_flag & 0x2),
            "nosecurityextension":       bool(enroll_flag & 0x00080000),
            "enrolleesuppliessubject":   bool(name_flag & 0x1),
            "subjectaltrequireupn":      bool(name_flag & 0x04000000),
            "subjectaltrequiredns":      bool(name_flag & 0x01000000),
            "subjectaltrequiredomaindns": bool(name_flag & 0x00400000),
            "subjectaltrequireemail":    bool(name_flag & 0x02000000),
            "subjectaltrequirespn":      bool(name_flag & 0x08000000),
            "subjectrequireemail":       bool(name_flag & 0x40000000),
            "ekus":                      ekus,
            "certificateapplicationpolicy": app_pol,
            "certificatepolicy":         cert_pol,
            "issuancepolicies":          ra_pol,
            "applicationpolicies":       app_pol,
            "authorizedsignatures":      ra_sig,
            "effectiveekus":             list(all_ekus) if all_ekus else [],
            "authenticationenabled":     auth_enabled,
            "schannelauthenticationenabled": sch_enabled,
        })

        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)

        return CertTemplateOutput(
            Properties=props,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn),
        )

    def _process_issuance(self, obj: dict) -> IssuancePolicyOutput:
        guid       = obj.get("objectGUID", "")
        identifier = guid.upper() if guid else ""
        cn         = first(obj, "cn", "")
        dn_ip      = first(obj, "distinguishedName", "")
        display    = first(obj, "displayName", cn)
        oid_val    = first(obj, "msPKI-Cert-Template-OID", None)
        props      = _base_props(obj, display or cn, self.domain, self.domain_sid)
        props.update({
            "displayname":     display,
            "certtemplateoid": oid_val,
        })

        # GroupLink — resolve msDS-OIDToGroupLink DN to TypedPrincipal
        group_dn  = first(obj, "msDS-OIDToGroupLink", None)
        group_link = TypedPrincipal(ObjectIdentifier=None, ObjectType="Base")
        if group_dn:
            tp = self.cache.resolve_dn_to_sid(group_dn, self.client)
            if tp:
                group_link = tp

        aces = []
        if self.collect_acls:
            aces = _parse_acl_safe(obj.get("nTSecurityDescriptor"), self.cache, identifier, props)

        return IssuancePolicyOutput(
            Properties=props,
            GroupLink=group_link,
            Aces=aces,
            ObjectIdentifier=identifier,
            IsACLProtected=props.get("isaclprotected", False),
            ContainedBy=self._contained_by(dn_ip),
        )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _resolve_templates(self, names: list[str]) -> list[TypedPrincipal]:
        """Resolve template common names to TypedPrincipals via ADWS."""
        result = []
        for name in names:
            try:
                objs = self.client.search_config_nc(
                    f"(&(objectClass=pKICertificateTemplate)(cn={name}))",
                    ["objectGUID"],
                )
                if objs:
                    guid = objs[0].get("objectGUID")
                    if guid:
                        result.append(TypedPrincipal(
                            ObjectIdentifier=guid.upper(),
                            ObjectType="CertTemplate",
                        ))
            except Exception:
                pass
        return result


# ─── CA flags ────────────────────────────────────────────────────────────────

_CA_FLAGS = {
    0x00000001: "SUPPORTS_NT_AUTHENTICATION",
    0x00000004: "NO_OCSP_FAILOPEN",
    0x00000008: "CA_SERVERTYPE_ADVANCED",
}


def _ca_flags_str(mask: int) -> str:
    names = [name for bit, name in sorted(_CA_FLAGS.items()) if mask & bit]
    return ", ".join(names) if names else "NONE"


# ─── CA registry access (MSRPC/WinReg) ───────────────────────────────────────
#
# CA security descriptor lives at:
#   HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\Security
# EditFlags (ESC6) lives at:
#   HKLM\SYSTEM\...\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
#
# CA access mask bits (from certreq.h / ICertAdmin):
#   0x00000001 = CA_ACCESS_ADMIN     → ManageCA
#   0x00000002 = CA_ACCESS_OFFICER   → ManageCertificates
#   0x00000004 = CA_ACCESS_AUDITOR   (not mapped to BH edge)
#   0x00000008 = CA_ACCESS_OPERATOR  (not mapped)
#   0x00000100 = CA_ACCESS_READ      (not mapped)
#   0x00000200 = CA_ACCESS_ENROLL    → Enroll (already collected via LDAP)

_CA_ACCESS_ADMIN   = 0x00000001
_CA_ACCESS_OFFICER = 0x00000002
_CA_ACCESS_ENROLL  = 0x00000200

# ESC6: if EDITF_ATTRIBUTESUBJECTALTNAME2 bit is set, requester can specify SAN
_EDITF_SAN = 0x00040000
# Role separation: InterfaceFlags bit IF_ROLEENFORCEMENT
_IF_ROLEENFORCEMENT = 0x00000080

_CERTSVC_KEY  = "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration"
_POLICY_SUBKEY = "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
_EA_RIGHTS_VALUE = "EnrollmentAgentRights"


def _creds_split(hashes: Optional[str]) -> tuple[str, str]:
    if hashes and ":" in hashes:
        p = hashes.split(":", 1)
        return p[0], p[1]
    return "", hashes or ""


def _read_ca_registry(
    hostname: str,
    domain: str,
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    ca_name: str,
    cache,
    do_kerberos: bool = False,
    aes_key: str = "",
    kdc_host: Optional[str] = None,
) -> tuple[list, bool, bool, list]:
    """Read CA security SD, EditFlags, InterfaceFlags, and EnrollmentAgentRights.

    Returns (ca_security_aces, san_enabled_bool, role_sep_bool, ea_restrictions_list).
    Raises on connection failure so caller can handle gracefully.
    """
    from impacket.dcerpc.v5 import transport as imptransport, rrp
    from adwshound.schema.types import ACE, TypedPrincipal
    from adwshound.collectors.base import set_dcerpc_creds

    string_binding = f"ncacn_np:{hostname}[\\pipe\\winreg]"
    rpctransport = imptransport.DCERPCTransportFactory(string_binding)
    set_dcerpc_creds(rpctransport, username, password, domain, hashes,
                     aes_key, do_kerberos, kdc_host)
    rpctransport.set_connect_timeout(5)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)

    try:
        # Open HKLM
        ans     = rrp.hOpenLocalMachine(dce)
        h_root  = ans["phKey"]

        ca_key_path = f"{_CERTSVC_KEY}\\{ca_name}"

        # ── CA Security SD ───────────────────────────────────────────────────
        ans_ca      = rrp.hBaseRegOpenKey(dce, h_root, ca_key_path,
                                          samDesired=rrp.MAXIMUM_ALLOWED)
        h_ca        = ans_ca["phkResult"]
        ans_sec     = rrp.hBaseRegQueryValue(dce, h_ca, "Security")
        sd_bytes    = bytes(ans_sec["lpData"])
        ca_aces     = _parse_ca_security(sd_bytes, cache)

        # ── EditFlags (ESC6) ─────────────────────────────────────────────────
        san_enabled = False
        try:
            ans_pol = rrp.hBaseRegOpenKey(dce, h_ca, _POLICY_SUBKEY,
                                           samDesired=rrp.MAXIMUM_ALLOWED)
            h_pol   = ans_pol["phkResult"]
            ans_ef  = rrp.hBaseRegQueryValue(dce, h_pol, "EditFlags")
            ef_data = bytes(ans_ef["lpData"])
            if len(ef_data) >= 4:
                ef_val = struct.unpack("<I", ef_data[:4])[0]
                san_enabled = bool(ef_val & _EDITF_SAN)
            rrp.hBaseRegCloseKey(dce, h_pol)
        except Exception:
            pass

        # ── InterfaceFlags (role separation) ─────────────────────────────────
        role_sep = False
        try:
            ans_if  = rrp.hBaseRegQueryValue(dce, h_ca, "InterfaceFlags")
            if_data = bytes(ans_if["lpData"])
            if len(if_data) >= 4:
                if_val   = struct.unpack("<I", if_data[:4])[0]
                role_sep = bool(if_val & _IF_ROLEENFORCEMENT)
        except Exception:
            pass

        # ── EnrollmentAgentRights (enrollment agent restrictions) ────────────
        ea_restrictions: list = []
        try:
            ans_pol2 = rrp.hBaseRegOpenKey(dce, h_ca, _POLICY_SUBKEY,
                                            samDesired=rrp.MAXIMUM_ALLOWED)
            h_pol2   = ans_pol2["phkResult"]
            try:
                ans_ear  = rrp.hBaseRegQueryValue(dce, h_pol2, _EA_RIGHTS_VALUE)
                ear_data = bytes(ans_ear["lpData"])
                ea_restrictions = _parse_ea_restrictions(ear_data, cache)
            except Exception:
                pass
            rrp.hBaseRegCloseKey(dce, h_pol2)
        except Exception:
            pass

        rrp.hBaseRegCloseKey(dce, h_ca)
        rrp.hBaseRegCloseKey(dce, h_root)
    finally:
        dce.disconnect()

    return ca_aces, san_enabled, role_sep, ea_restrictions


def _parse_ea_restrictions(sd_bytes: bytes, cache) -> list:
    """Parse EnrollmentAgentRights SD → list of restriction dicts.

    Each restriction: {"Agent": TypedPrincipal, "Template": str, "AccessType": int}
    The SD DACL contains allow ACEs where the SID is the agent principal.
    Object GUIDs in object ACEs identify the template OID.
    """
    if not sd_bytes:
        return []
    try:
        from impacket.ldap.ldaptypes import (
            SR_SECURITY_DESCRIPTOR,
            ACCESS_ALLOWED_ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
        )
        from adwshound.schema.types import TypedPrincipal as _TP
    except ImportError:
        return []

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        return []

    if not sd["Dacl"]:
        return []

    results = []
    for ace in sd["Dacl"].aces:
        ace_type = ace["AceType"]
        if ace_type not in (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue
        try:
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        agent = cache.resolve_sid(sid)
        if not agent:
            agent = _TP(ObjectIdentifier=cache.qualify_sid(sid), ObjectType="Base")

        template_guid = None
        if ace_type == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
            try:
                import uuid
                raw_guid = bytes(ace["Ace"]["ObjectType"])
                if len(raw_guid) == 16:
                    template_guid = str(uuid.UUID(bytes_le=raw_guid)).upper()
            except Exception:
                pass

        results.append({
            "Agent": {"ObjectIdentifier": agent.ObjectIdentifier, "ObjectType": agent.ObjectType},
            "Template": template_guid,
            "AllTemplates": template_guid is None,
        })
    return results


def _parse_ca_security(sd_bytes: bytes, cache) -> list:
    """Parse CA registry security descriptor and return ManageCA/ManageCertificates ACEs."""
    from adwshound.schema.types import ACE, TypedPrincipal

    try:
        from impacket.ldap.ldaptypes import (
            SR_SECURITY_DESCRIPTOR,
            ACCESS_ALLOWED_ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
        )
    except ImportError:
        return []

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        return []

    if not sd["Dacl"]:
        return []

    aces = []
    for ace in sd["Dacl"].aces:
        ace_type  = ace["AceType"]
        if ace_type not in (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue

        ace_body = ace["Ace"]
        try:
            sid = ace_body["Sid"].formatCanonical()
        except Exception:
            continue

        mask = int(ace_body["Mask"]["Mask"])
        is_inherited = bool(ace["AceFlags"] & 0x10)

        # Map CA-specific access bits to BloodHound right names
        rights_to_emit = []
        if mask & _CA_ACCESS_ADMIN:
            rights_to_emit.append("ManageCA")
        if mask & _CA_ACCESS_OFFICER:
            rights_to_emit.append("ManageCertificates")
        if mask & _CA_ACCESS_ENROLL:
            rights_to_emit.append("Enroll")

        if not rights_to_emit:
            continue

        tp = cache.resolve_sid(sid)
        if not tp:
            tp = TypedPrincipal(
                ObjectIdentifier=cache.qualify_sid(sid),
                ObjectType="Base",
            )

        for right in rights_to_emit:
            aces.append(ACE(
                PrincipalSID=tp.ObjectIdentifier,
                PrincipalType=tp.ObjectType,
                RightName=right,
                IsInherited=is_inherited,
            ))

    return aces


# ─── HTTP enrollment endpoint check ──────────────────────────────────────────

_HTTP_ENDPOINT_PATTERNS = [
    ("http",  "/certsrv/"),
    ("https", "/certsrv/"),
]

_CES_KERBEROS_PATTERNS = [
    ("http",  "/{ca_name}_CES_Kerberos/service.svc"),
    ("https", "/{ca_name}_CES_Kerberos/service.svc"),
]


def _check_http_endpoints(dns: str, ca_name: str) -> list:
    """Check HTTP/HTTPS CA enrollment endpoints for NTLM accessibility."""
    results = []
    patterns = _HTTP_ENDPOINT_PATTERNS + [
        (scheme, path.format(ca_name=ca_name))
        for scheme, path in _CES_KERBEROS_PATTERNS
    ]
    for scheme, path in patterns:
        url = f"{scheme}://{dns}{path}"
        result_entry = {"Url": url, "Result": None, "Collected": False, "FailureReason": None}
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0")
            # Short timeout; we just want to check reachability + auth challenge
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                result_entry["Result"]    = {"NtlmEndpointUrl": url, "StatusCode": status}
                result_entry["Collected"] = True
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # 401 = server is there and requires auth (NTLM/Kerberos) — accessible
                result_entry["Result"]    = {"NtlmEndpointUrl": url, "StatusCode": 401}
                result_entry["Collected"] = True
            else:
                result_entry["FailureReason"] = f"HTTP {exc.code}"
        except urllib.error.URLError as exc:
            result_entry["FailureReason"] = str(exc.reason)
        except Exception as exc:
            result_entry["FailureReason"] = str(exc)
        results.append(result_entry)
    return results
