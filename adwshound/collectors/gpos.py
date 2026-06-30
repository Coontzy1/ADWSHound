"""Group Policy Object collector."""
from __future__ import annotations

from adwshound.collectors.base import BaseCollector, first, object_name
from adwshound.schema.types import GPOOutput

_FILTER = "(objectClass=groupPolicyContainer)"

_ATTRS = [
    "objectGUID", "cn", "displayName", "description",
    "gpcFileSysPath", "distinguishedName", "whenCreated",
    "flags",
    "nTSecurityDescriptor",
]


class GPOCollector(BaseCollector):

    def collect(self) -> list[GPOOutput]:
        self.log.info("Collecting GPOs …")
        _base_attrs = _ATTRS if self.collect_acls else [a for a in _ATTRS if a != "nTSecurityDescriptor"]
        attrs = self._attrs(_base_attrs)
        objects = self.client.search(_FILTER, attrs)
        results = []

        for obj in objects:
            guid = obj.get("objectGUID")
            if not guid:
                continue

            # ObjectIdentifier = plain GUID, no braces
            identifier = guid.upper()
            dn      = first(obj, "distinguishedName", "")
            display = first(obj, "displayName") or first(obj, "cn", "")

            props = {
                "domain":          self.domain,
                "name":            object_name(display, self.domain),
                "distinguishedname": dn.upper() if dn else "",
                "domainsid":       self.domain_sid,
                "doesanyacegrantownerrights":          False,
                "doesanyinheritedacegrantownerrights": False,
                "isaclprotected":  False,
                "description":     first(obj, "description", None),
                "gpcpath":         first(obj, "gpcFileSysPath", None),
                "whencreated":     obj.get("whenCreated", -1),
                "gpostatus":       str(int(first(obj, "flags", 0) or 0)),
            }

            aces = []
            if obj.get("nTSecurityDescriptor") and self.collect_acls:
                from adwshound.collectors.acls import parse_acl
                aces, is_protected = parse_acl(obj["nTSecurityDescriptor"], self.cache, identifier)
                props["isaclprotected"] = is_protected
                _or_aces = [a for a in aces if a.PrincipalSID == "S-1-3-4"]
                props["doesanyacegrantownerrights"] = any(not a.IsInherited for a in _or_aces)
                props["doesanyinheritedacegrantownerrights"] = any(a.IsInherited for a in _or_aces)
                aces = [a for a in aces if a.PrincipalSID != "S-1-3-4"]

            results.append(GPOOutput(
                Properties=props,
                Aces=aces,
                ObjectIdentifier=identifier,
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d GPOs", len(results))
        return results
