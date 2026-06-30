"""User enumeration collector."""
from __future__ import annotations

from adwshound.collectors.base import (
    BaseCollector, first, as_list, object_name, uac_flag, encryption_types,
    UAC_ACCOUNTDISABLE, UAC_PASSWD_NOTREQD, UAC_DONT_EXPIRE_PASSWORD,
    UAC_SMARTCARD_REQUIRED, UAC_TRUSTED_FOR_DELEGATION, UAC_NOT_DELEGATED,
    UAC_DONT_REQ_PREAUTH, UAC_TRUSTED_TO_AUTH_FOR_DELG, UAC_ENCRYPTED_TEXT_PWD,
    UAC_USE_DES_KEY_ONLY,
)
from adwshound.schema.types import UserOutput, TypedPrincipal

# sAMAccountType=805306368 (0x30000000) = SAM_USER_OBJECT (normal user accounts only)
# Avoids objectCategory shorthand which ADWS doesn't resolve when using OID-based filters
_FILTER = "(sAMAccountType=805306368)"

_ATTRS = [
    "objectGUID", "objectSid", "sAMAccountName", "cn", "displayName",
    "description", "mail", "title", "department", "homeDirectory",
    "userAccountControl", "pwdLastSet", "lastLogon", "lastLogonTimestamp",
    "accountExpires", "adminCount", "memberOf",
    "servicePrincipalName", "sIDHistory",
    "primaryGroupID", "distinguishedName", "whenCreated",
    "scriptPath", "profilePath",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",  # gMSA password readers
    "objectClass",              # detect MSA/gMSA account type
    "nTSecurityDescriptor",
]

_GMSA_CLASS = "msds-groupmanagedserviceaccount"
_MSA_CLASS  = "msds-managedserviceaccount"

_UAC_LOCKOUT         = 0x0010
_UAC_PASSWD_CANT     = 0x0040
_UAC_PWD_EXPIRED     = 0x800000


class UserCollector(BaseCollector):

    def collect(self) -> list[UserOutput]:
        self.log.info("Collecting users …")
        _base_attrs = _ATTRS if self.collect_acls else [a for a in _ATTRS if a != "nTSecurityDescriptor"]
        attrs = self._attrs(_base_attrs)
        objects = self.client.search(_FILTER, attrs)
        results = []

        for obj in objects:
            sid = obj.get("objectSid")
            guid = obj.get("objectGUID")
            identifier = sid or (f"{{{guid}}}" if guid else None)
            if not identifier:
                continue

            dn = first(obj, "distinguishedName", "")
            sam = first(obj, "sAMAccountName", "")
            name = object_name(sam or first(obj, "cn"), self.domain)
            uac = int(obj.get("userAccountControl", 0) or 0)
            unconstrained = uac_flag(uac, UAC_TRUSTED_FOR_DELEGATION)
            spns = as_list(obj, "servicePrincipalName")

            props = {
                "domain":          self.domain,
                "name":            name,
                "distinguishedname": dn.upper() if dn else "",
                "domainsid":       self.domain_sid,
                "samaccountname":  sam,
                "doesanyacegrantownerrights":          False,
                "doesanyinheritedacegrantownerrights": False,
                "isaclprotected":         False,
                "adminsdholderprotected": bool(first(obj, "adminCount", 0)),
                "description":     first(obj, "description", None),
                "whencreated":     obj.get("whenCreated", -1),
                "sensitive":       uac_flag(uac, UAC_NOT_DELEGATED),
                "dontreqpreauth":  uac_flag(uac, UAC_DONT_REQ_PREAUTH),
                "passwordnotreqd": uac_flag(uac, UAC_PASSWD_NOTREQD),
                "unconstraineddelegation": unconstrained,
                "pwdneverexpires": uac_flag(uac, UAC_DONT_EXPIRE_PASSWORD),
                "enabled":         not uac_flag(uac, UAC_ACCOUNTDISABLE),
                "trustedtoauth":   uac_flag(uac, UAC_TRUSTED_TO_AUTH_FOR_DELG),
                "smartcardrequired":       uac_flag(uac, UAC_SMARTCARD_REQUIRED),
                "encryptedtextpwdallowed": uac_flag(uac, UAC_ENCRYPTED_TEXT_PWD),
                "usedeskeyonly":   uac_flag(uac, UAC_USE_DES_KEY_ONLY),
                "logonscriptenabled": bool(first(obj, "scriptPath", None)),
                "lockedout":       uac_flag(uac, _UAC_LOCKOUT),
                "passwordcantchange": uac_flag(uac, _UAC_PASSWD_CANT),
                "passwordexpired": uac_flag(uac, _UAC_PWD_EXPIRED),
                "useraccountcontrol": uac,
                "lastlogon":        obj.get("lastLogon", -1),
                "lastlogontimestamp": obj.get("lastLogonTimestamp", -1),
                "pwdlastset":       obj.get("pwdLastSet", -1),
                "serviceprincipalnames": spns,
                "hasspn":          bool(spns),
                "displayname":     first(obj, "displayName", None),
                "email":           first(obj, "mail", None),
                "title":           first(obj, "title", None),
                "department":      first(obj, "department", None),
                "homedirectory":   first(obj, "homeDirectory", None),
                "userpassword":    None,
                "unixpassword":    None,
                "unicodepassword": None,
                "sfupassword":     None,
                "logonscript":     first(obj, "scriptPath", None),
                "profilepath":     first(obj, "profilePath", None),
                "admincount":      bool(first(obj, "adminCount", 0)),
                "supportedencryptiontypes": encryption_types(obj.get("msDS-SupportedEncryptionTypes")),
                "sidhistory":      [],
            }

            # Detect MSA / gMSA account types
            obj_classes = {c.lower() for c in as_list(obj, "objectClass")}
            if _GMSA_CLASS in obj_classes:
                props["gmsa"] = True
            elif _MSA_CLASS in obj_classes:
                props["msa"] = True

            primary_group_sid = _build_primary_sid(identifier, first(obj, "primaryGroupID"))
            sid_history = _parse_sid_history(as_list(obj, "sIDHistory"), self.cache)
            props["sidhistory"] = [tp.ObjectIdentifier for tp in sid_history]
            allowed_to_delegate = _parse_allowed_to_delegate(
                as_list(obj, "msDS-AllowedToDelegateTo"), self.client
            )
            allowed_to_act = _parse_allowed_to_act(
                obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity"), self.cache
            )

            aces = []
            acl_bytes = obj.get("nTSecurityDescriptor")
            if acl_bytes and self.collect_acls:
                from adwshound.collectors.acls import parse_acl
                aces, is_protected = parse_acl(acl_bytes, self.cache, identifier)
                props["isaclprotected"] = is_protected
                _or_aces = [a for a in aces if a.PrincipalSID == "S-1-3-4"]
                props["doesanyacegrantownerrights"] = any(not a.IsInherited for a in _or_aces)
                props["doesanyinheritedacegrantownerrights"] = any(a.IsInherited for a in _or_aces)
                aces = [a for a in aces if a.PrincipalSID != "S-1-3-4"]
                props["adminsdholderprotected"] = self._is_adminsdholder_protected(aces)

            # gMSA: parse msDS-GroupMSAMembership → ReadGMSAPassword ACEs
            gmsa_sd = obj.get("msDS-GroupMSAMembership")
            if gmsa_sd and isinstance(gmsa_sd, bytes) and self.collect_acls:
                aces = aces + _parse_gmsa_readers(gmsa_sd, self.cache)

            results.append(UserOutput(
                Properties=props,
                AllowedToDelegate=allowed_to_delegate,
                AllowedToAct=allowed_to_act,
                PrimaryGroupSID=primary_group_sid,
                HasSIDHistory=sid_history,
                SPNTargets=[],
                UnconstrainedDelegation=unconstrained,
                DomainSID=self.domain_sid,
                Aces=aces,
                ObjectIdentifier=identifier.upper(),
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d users", len(results))
        return results


def _build_primary_sid(obj_sid: str, rid_raw) -> str | None:
    if not rid_raw:
        return None
    try:
        rid = int(rid_raw)
    except (TypeError, ValueError):
        return None
    parts = obj_sid.rsplit("-", 1)
    return f"{parts[0]}-{rid}" if len(parts) == 2 else None


def _parse_sid_history(raw: list, cache) -> list[TypedPrincipal]:
    result = []
    for item in raw:
        if isinstance(item, bytes):
            from impacket.ldap.ldaptypes import LDAP_SID
            sid = LDAP_SID(data=item).formatCanonical()
        else:
            sid = str(item)
        tp = cache.resolve_sid(sid) or TypedPrincipal(sid.upper(), "User")
        result.append(tp)
    return result


def _parse_allowed_to_delegate(spn_list: list, client) -> list[TypedPrincipal]:
    """Resolve msDS-AllowedToDelegateTo SPN values to computer TypedPrincipals."""
    result = []
    seen = set()
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


def _parse_allowed_to_act(sd_bytes, cache) -> list:
    """Parse msDS-AllowedToActOnBehalfOfOtherIdentity SD → AllowedToAct principals."""
    if not isinstance(sd_bytes, bytes):
        return []
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        if not sd["Dacl"]:
            return []
        from adwshound.schema.types import TypedPrincipal as _TP
        return [
            cache.resolve_sid(ace["Ace"]["Sid"].formatCanonical()) or
            _TP(ace["Ace"]["Sid"].formatCanonical().upper(), "Base")
            for ace in sd["Dacl"].aces
            if ace["AceType"] == ACCESS_ALLOWED_ACE.ACE_TYPE
        ]
    except Exception:
        return []


def _parse_gmsa_readers(sd_bytes: bytes, cache) -> list:
    """Parse msDS-GroupMSAMembership SD → ReadGMSAPassword ACEs."""
    from adwshound.schema.types import ACE, TypedPrincipal
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
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
        if ace["AceType"] != ACCESS_ALLOWED_ACE.ACE_TYPE:
            continue
        try:
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        tp = cache.resolve_sid(sid)
        if not tp:
            tp = TypedPrincipal(ObjectIdentifier=cache.qualify_sid(sid), ObjectType="Base")
        aces.append(ACE(
            PrincipalSID=tp.ObjectIdentifier,
            PrincipalType=tp.ObjectType,
            RightName="ReadGMSAPassword",
            IsInherited=False,
        ))
    return aces
