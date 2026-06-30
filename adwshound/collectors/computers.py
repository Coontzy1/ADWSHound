"""Computer enumeration collector."""
from __future__ import annotations

from adwshound.collectors.base import (
    BaseCollector, first, as_list, uac_flag, dn_to_domain, encryption_types,
    UAC_ACCOUNTDISABLE, UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELG, UAC_SERVER_TRUST_ACCOUNT,
    UAC_ENCRYPTED_TEXT_PWD, UAC_USE_DES_KEY_ONLY,
)

UAC_PARTIAL_SECRETS = 0x04000000  # Read-Only Domain Controller
from adwshound.schema.types import (
    ComputerOutput, TypedPrincipal, CollectionResult,
    DCRegistryData, ComputerStatus,
)

_FILTER = "(objectClass=computer)"

_ATTRS = [
    "objectGUID", "objectSid", "sAMAccountName", "dNSHostName",
    "operatingSystem", "userAccountControl",
    "lastLogon", "lastLogonTimestamp", "pwdLastSet",
    "servicePrincipalName", "description", "distinguishedName", "scriptPath",
    "primaryGroupID", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AllowedToDelegateTo",
    "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
    "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
    "msDS-HostServiceAccount",
    "sIDHistory", "adminCount", "whenCreated",
    "msDS-SupportedEncryptionTypes",
    "operatingSystemServicePack",
    "nTSecurityDescriptor",
]

_UAC_LOCKOUT     = 0x0010
_UAC_PWD_EXPIRED = 0x800000
_EMPTY_CR        = CollectionResult(Results=[], Collected=False, FailureReason=None)


class ComputerCollector(BaseCollector):

    def collect(self) -> list[ComputerOutput]:
        self.log.info("Collecting computers …")
        _base_attrs = _ATTRS if self.collect_acls else [a for a in _ATTRS if a != "nTSecurityDescriptor"]
        attrs = self._attrs(_base_attrs)
        objects = self.client.search(_FILTER, attrs)
        results = []

        for obj in objects:
            sid  = obj.get("objectSid")
            guid = obj.get("objectGUID")
            identifier = sid or (f"{{{guid}}}" if guid else None)
            if not identifier:
                continue

            dn  = first(obj, "distinguishedName", "")
            sam = first(obj, "sAMAccountName", "")
            dns = first(obj, "dNSHostName") or f"{sam.rstrip('$')}.{dn_to_domain(dn).lower()}"
            uac = int(obj.get("userAccountControl", 0) or 0)
            is_dc        = uac_flag(uac, UAC_SERVER_TRUST_ACCOUNT)
            unconstrained = uac_flag(uac, UAC_TRUSTED_FOR_DELEGATION)
            spns = as_list(obj, "servicePrincipalName")

            props = {
                "domain":          self.domain,
                "name":            (dns or sam.rstrip("$")).upper(),
                "distinguishedname": dn.upper() if dn else "",
                "domainsid":       self.domain_sid,
                "samaccountname":  sam,
                "haslaps":         bool(
                    obj.get("ms-Mcs-AdmPwdExpirationTime") or
                    obj.get("msLAPS-PasswordExpirationTime") or
                    obj.get("ms-Mcs-AdmPwd") or
                    obj.get("msLAPS-Password") or
                    obj.get("msLAPS-EncryptedPassword")
                ),
                "lapsexpirationtime": _laps_expiry(obj),
                "doesanyacegrantownerrights":          False,
                "doesanyinheritedacegrantownerrights": False,
                "isaclprotected":         False,
                "adminsdholderprotected": bool(first(obj, "adminCount", 0)),
                "whencreated":     obj.get("whenCreated", -1),
                "enabled":         not uac_flag(uac, UAC_ACCOUNTDISABLE),
                "unconstraineddelegation": unconstrained,
                "trustedtoauth":   uac_flag(uac, UAC_TRUSTED_TO_AUTH_FOR_DELG),
                "isdc":            is_dc,
                "isreadonlydc":    uac_flag(uac, UAC_PARTIAL_SECRETS),
                "encryptedtextpwdallowed": uac_flag(uac, UAC_ENCRYPTED_TEXT_PWD),
                "usedeskeyonly":   uac_flag(uac, UAC_USE_DES_KEY_ONLY),
                "logonscriptenabled": bool(first(obj, "scriptPath", None)),
                "lockedout":       uac_flag(uac, _UAC_LOCKOUT),
                "passwordexpired": uac_flag(uac, _UAC_PWD_EXPIRED),
                "supportedencryptiontypes": encryption_types(obj.get("msDS-SupportedEncryptionTypes")),
                "admincount":      bool(first(obj, "adminCount", 0)),
                "lastlogon":        obj.get("lastLogon", -1),
                "lastlogontimestamp": obj.get("lastLogonTimestamp", -1),
                "pwdlastset":       obj.get("pwdLastSet", -1),
                "serviceprincipalnames": spns,
                "hasspn":          bool(spns),
                "email":           None,
                "useraccountcontrol": uac,
                "operatingsystem": first(obj, "operatingSystem", None),
                "operatingsystemservicepack": first(obj, "operatingSystemServicePack", None),
                "objectguid":      guid.upper() if guid else None,
                "sidhistory":      [],
                "description":     first(obj, "description", None),
            }

            primary_sid  = _build_primary_sid(identifier, first(obj, "primaryGroupID"))
            allowed_act  = _parse_allowed_to_act(
                obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity"), self.cache
            )
            dump_smsa = _parse_host_service_accounts(
                as_list(obj, "msDS-HostServiceAccount"), self.cache, self.client
            )
            allowed_delegate = _parse_allowed_to_delegate(
                as_list(obj, "msDS-AllowedToDelegateTo"), self.client
            )
            sid_history  = _parse_sid_history(as_list(obj, "sIDHistory"), self.cache)
            props["sidhistory"] = [tp.ObjectIdentifier for tp in sid_history]

            aces = []
            if obj.get("nTSecurityDescriptor") and self.collect_acls:
                from adwshound.collectors.acls import parse_acl
                aces, is_protected = parse_acl(obj["nTSecurityDescriptor"], self.cache, identifier)
                props["isaclprotected"] = is_protected
                _or_aces = [a for a in aces if a.PrincipalSID == "S-1-3-4"]
                props["doesanyacegrantownerrights"] = any(not a.IsInherited for a in _or_aces)
                props["doesanyinheritedacegrantownerrights"] = any(a.IsInherited for a in _or_aces)
                aces = [a for a in aces if a.PrincipalSID != "S-1-3-4"]
                props["adminsdholderprotected"] = self._is_adminsdholder_protected(aces)

            results.append(ComputerOutput(
                Properties=props,
                PrimaryGroupSID=primary_sid,
                AllowedToDelegate=allowed_delegate,
                AllowedToAct=allowed_act,
                HasSIDHistory=sid_history,
                DumpSMSAPassword=dump_smsa,
                Sessions=_EMPTY_CR,
                PrivilegedSessions=_EMPTY_CR,
                RegistrySessions=_EMPTY_CR,
                LocalGroups=[],
                UserRights=[],
                DCRegistryData=DCRegistryData(),
                Status=ComputerStatus(),
                IsACLProtected=props.get("isaclprotected", False),
                IsDC=is_dc,
                UnconstrainedDelegation=unconstrained,
                DomainSID=self.domain_sid,
                IsWebClientRunning=None,
                SmbInfo=None,
                NtlmSessions=None,
                NTLMRegistryData=None,
                LdapServicesData=None,
                Aces=aces,
                ObjectIdentifier=identifier.upper(),
            ))

        self.log.info("Collected %d computers", len(results))
        return results


def _build_primary_sid(obj_sid, rid_raw):
    if not rid_raw:
        return None
    try:
        rid = int(rid_raw)
    except (TypeError, ValueError):
        return None
    parts = obj_sid.rsplit("-", 1)
    return f"{parts[0]}-{rid}" if len(parts) == 2 else None


def _parse_allowed_to_act(sd_bytes, cache):
    if not isinstance(sd_bytes, bytes):
        return []
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        if not sd["Dacl"]:
            return []
        return [
            cache.resolve_sid(ace["Ace"]["Sid"].formatCanonical()) or
            TypedPrincipal(ace["Ace"]["Sid"].formatCanonical().upper(), "Base")
            for ace in sd["Dacl"].aces
            if ace["AceType"] == ACCESS_ALLOWED_ACE.ACE_TYPE
        ]
    except Exception:
        return []


def _parse_sid_history(raw, cache):
    result = []
    for item in raw:
        if isinstance(item, bytes):
            from impacket.ldap.ldaptypes import LDAP_SID
            sid = LDAP_SID(data=item).formatCanonical()
        else:
            sid = str(item)
        result.append(cache.resolve_sid(sid) or TypedPrincipal(sid.upper(), "Computer"))
    return result


def _parse_host_service_accounts(dn_list: list, cache, client) -> list[TypedPrincipal]:
    """Resolve msDS-HostServiceAccount DN list → standalone MSA TypedPrincipals."""
    result = []
    for dn in dn_list:
        if not dn:
            continue
        tp = cache.resolve_dn_to_sid(dn, client)
        if tp:
            result.append(tp)
    return result


def _laps_expiry(obj: dict) -> int:
    """Return LAPS expiration time as Windows FILETIME int, -1 if absent."""
    raw = obj.get("ms-Mcs-AdmPwdExpirationTime") or obj.get("msLAPS-PasswordExpirationTime")
    if raw is None:
        return -1
    try:
        return int(raw)
    except (TypeError, ValueError):
        return -1


def _parse_allowed_to_delegate(spn_list: list, client) -> list[TypedPrincipal]:
    """Resolve msDS-AllowedToDelegateTo SPN values to computer TypedPrincipals."""
    result = []
    seen: set[str] = set()
    for spn in spn_list:
        if "/" not in spn:
            continue
        host = spn.split("/", 1)[1].split(":")[0].split("/")[0]
        if not host or host.upper() in seen:
            continue
        seen.add(host.upper())
        objs = client.search(f"(dNSHostName={host})", ["objectSid"])
        if not objs:
            short = host.split(".")[0].upper()
            objs = client.search(f"(sAMAccountName={short}$)", ["objectSid"])
        if objs:
            sid = objs[0].get("objectSid")
            if sid:
                result.append(TypedPrincipal(ObjectIdentifier=sid.upper(), ObjectType="Computer"))
    return result
