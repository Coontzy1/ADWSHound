"""Group enumeration collector."""
from __future__ import annotations

from adwshound.collectors.base import BaseCollector, first, as_list, object_name
from adwshound.schema.types import GroupOutput, TypedPrincipal

_FILTER = "(objectCategory=group)"

_ATTRS = [
    "objectGUID", "objectSid", "sAMAccountName", "cn",
    "description", "adminCount", "groupType",
    "member", "memberOf", "distinguishedName", "whenCreated",
    "nTSecurityDescriptor",
]

# groupType flags
_GT_SECURITY    = 0x80000000
_GT_GLOBAL      = 0x00000002
_GT_DOMAIN_LOCAL = 0x00000004
_GT_UNIVERSAL   = 0x00000008

def _group_scope(group_type_int: int) -> str:
    if group_type_int & _GT_UNIVERSAL:
        return "Universal"
    if group_type_int & _GT_DOMAIN_LOCAL:
        return "DomainLocal"
    return "Global"


class GroupCollector(BaseCollector):

    def collect(self) -> list[GroupOutput]:
        self.log.info("Collecting groups …")
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
            cn  = sam or first(obj, "cn")
            name = object_name(cn, self.domain)
            gt  = int(obj.get("groupType", 0) or 0)

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
                "admincount":      bool(first(obj, "adminCount", 0)),
                "groupscope":      _group_scope(gt),
                "sidhistory":      [],
            }

            members = []
            for dn_m in as_list(obj, "member"):
                tp = self.cache.resolve_dn_to_sid(dn_m, self.client)
                if tp:
                    members.append(tp)

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

            results.append(GroupOutput(
                Properties=props,
                Members=members,
                HasSIDHistory=[],
                DomainSID=self.domain_sid,
                Aces=aces,
                ObjectIdentifier=identifier.upper(),
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d groups", len(results))
        return results
