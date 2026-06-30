"""Organizational Unit collector."""
from __future__ import annotations

import re

from adwshound.collectors.base import BaseCollector, first, object_name
from adwshound.schema.types import OUOutput, GPOLink, empty_gpo_changes

_FILTER = "(objectClass=organizationalUnit)"

_ATTRS = [
    "objectGUID", "name", "description", "distinguishedName",
    "gPLink", "gPOptions", "whenCreated", "nTSecurityDescriptor",
]


def _parse_gplinks(gplink_str: str) -> list[GPOLink]:
    """Parse gpLink → list of GPOLink with plain GUID (no braces), uppercase key.

    flags: 0=enabled, 1=disabled, 2=enforced. Skip disabled links (flags==1).
    """
    if not gplink_str:
        return []
    links = []
    for m in re.finditer(r'\[LDAP://([^;]+);(\d+)\]', gplink_str, re.IGNORECASE):
        dn    = m.group(1)
        flags = int(m.group(2))
        if flags == 1:      # link disabled — skip, no path through disabled links
            continue
        guid_m = re.search(r'\{([0-9a-fA-F-]+)\}', dn)
        if guid_m:
            links.append(GPOLink(
                GUID=guid_m.group(1).upper(),
                IsEnforced=(flags == 2),
            ))
    return links


class OUCollector(BaseCollector):

    def collect(self) -> list[OUOutput]:
        self.log.info("Collecting OUs …")
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
                "blocksinheritance": bool(int(first(obj, "gPOptions", 0) or 0) & 0x1),
            }

            links = _parse_gplinks(first(obj, "gPLink", "") or "")

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

            results.append(OUOutput(
                GPOChanges=empty_gpo_changes(),
                Properties=props,
                Links=links,
                ChildObjects=[],
                InheritanceHashes=inheritance_hashes,
                Aces=aces,
                ObjectIdentifier=identifier,
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d OUs", len(results))
        return results
