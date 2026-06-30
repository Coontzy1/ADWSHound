"""Container object collector."""
from __future__ import annotations

from adwshound.collectors.base import BaseCollector, first, object_name
from adwshound.schema.types import ContainerOutput

_FILTER = "(objectClass=container)"

_ATTRS = [
    "objectGUID", "name", "description",
    "distinguishedName", "whenCreated", "nTSecurityDescriptor",
]


class ContainerCollector(BaseCollector):

    def collect(self) -> list[ContainerOutput]:
        self.log.info("Collecting containers …")
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
            dn   = first(obj, "distinguishedName", "")
            name = first(obj, "name", "")

            props = {
                "domain":          self.domain,
                "name":            object_name(name, self.domain),
                "distinguishedname": dn.upper() if dn else "",
                "domainsid":       self.domain_sid,
                "doesanyacegrantownerrights":          False,
                "doesanyinheritedacegrantownerrights": False,
                "isaclprotected":  False,
                "description":     first(obj, "description", None),
                "whencreated":     obj.get("whenCreated", -1),
            }

            aces = []
            inheritance_hashes = []
            if obj.get("nTSecurityDescriptor") and self.collect_acls:
                from adwshound.collectors.acls import parse_acl, compute_inheritance_hashes
                aces, is_protected = parse_acl(obj["nTSecurityDescriptor"], self.cache, identifier)
                props["isaclprotected"] = is_protected
                _or_aces = [a for a in aces if a.PrincipalSID == "S-1-3-4"]
                props["doesanyacegrantownerrights"] = any(not a.IsInherited for a in _or_aces)
                props["doesanyinheritedacegrantownerrights"] = any(a.IsInherited for a in _or_aces)
                aces = [a for a in aces if a.PrincipalSID != "S-1-3-4"]
                inheritance_hashes = compute_inheritance_hashes(aces)

            results.append(ContainerOutput(
                Properties=props,
                ChildObjects=[],
                InheritanceHashes=inheritance_hashes,
                Aces=aces,
                ObjectIdentifier=identifier,
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d containers", len(results))
        return results
