"""SID / GUID / DN resolution cache.

Pre-loads a full SID→type mapping from AD in one batch query so later
collectors can resolve principals without extra roundtrips.
"""
from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

from adwshound.schema.types import TypedPrincipal

if TYPE_CHECKING:
    from adwshound.transport.client import ADWSClient

log = logging.getLogger(__name__)

# Attributes fetched during preload
_PRELOAD_ATTRS = [
    "objectSid", "objectGUID", "distinguishedName",
    "sAMAccountType", "objectClass",
]

_PRELOAD_FILTER = (
    "(|(objectClass=user)(objectClass=computer)"
    "(objectClass=group)(objectClass=organizationalUnit)"
    "(objectClass=container)(objectClass=domain)"
    "(objectClass=groupPolicyContainer)"
    "(objectClass=foreignSecurityPrincipal))"
)

# sAMAccountType → BloodHound principal type
_SAM_TYPE_MAP = {
    0x10000000: "Group",        # SAM_GROUP_OBJECT
    0x10000001: "Group",        # SAM_NON_SECURITY_GROUP_OBJECT
    0x20000000: "Group",        # SAM_ALIAS_OBJECT (local group)
    0x20000001: "Group",
    0x30000000: "User",         # SAM_USER_OBJECT
    0x30000001: "Computer",     # SAM_MACHINE_ACCOUNT
    0x30000002: "User",         # SAM_TRUST_ACCOUNT
}

# objectClass → BloodHound principal type (fallback when sAMAccountType absent)
_CLASS_TYPE_MAP = {
    "user": "User",
    "computer": "Computer",
    "group": "Group",
    "organizationalunit": "OU",
    "container": "Container",
    "grouppolicycontainer": "GPO",
    "domain": "Domain",
    "domaindns": "Domain",
}

# Well-known SIDs that are always "Group" type
_WELL_KNOWN_GROUP_SIDS = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-545",  # Users
    "S-1-5-32-546",  # Guests
    "S-1-5-32-547",  # Power Users
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-32-552",  # Replicators
    "S-1-5-32-554",  # Pre-Windows 2000 Compatible Access
    "S-1-5-32-555",  # Remote Desktop Users
    "S-1-5-32-558",  # Performance Monitor Users
    "S-1-5-32-573",  # Event Log Readers
    "S-1-5-32-580",  # Remote Management Users
}


def _object_type(obj: dict) -> str:
    """Determine BloodHound principal type from an AD object dict."""
    sam_type = obj.get("sAMAccountType")
    if sam_type is not None:
        t = _SAM_TYPE_MAP.get(int(sam_type) if isinstance(sam_type, str) else sam_type)
        if t:
            return t

    classes = obj.get("objectClass", [])
    if isinstance(classes, str):
        classes = [classes]
    for cls in reversed(classes):  # most specific class is usually last
        t = _CLASS_TYPE_MAP.get(cls.lower())
        if t:
            return t

    return "Base"


class ResolverCache:
    """Caches SID/GUID/DN → TypedPrincipal mappings for a single domain."""

    def __init__(self, domain: str = ""):
        self._domain = domain.upper()
        self._sid: dict[str, TypedPrincipal] = {}
        self._guid: dict[str, TypedPrincipal] = {}
        self._dn: dict[str, TypedPrincipal] = {}

        # Seed well-known group SIDs; BUILTIN (S-1-5-32-*) qualified with domain
        for sid in _WELL_KNOWN_GROUP_SIDS:
            identifier = self._qualify(sid)
            tp = TypedPrincipal(ObjectIdentifier=identifier, ObjectType="Group")
            self._sid[sid.upper()] = tp

    def _qualify(self, sid: str) -> str:
        """Prefix well-known non-domain SIDs with domain name — BloodHound format.

        Qualifies: S-1-5-32-* (BUILTIN), S-1-5-11 (Authenticated Users),
        S-1-1-0 (Everyone), S-1-5-9 (Enterprise DCs) and other NT Authority SIDs
        that are not unique per-domain on their own.
        """
        if not self._domain:
            return sid.upper()
        sid_upper = sid.upper()
        if (sid_upper.startswith("S-1-5-32-")   # BUILTIN
                or sid_upper in {"S-1-1-0", "S-1-5-11", "S-1-5-17",
                                  "S-1-5-20", "S-1-5-9"}):
            return f"{self._domain}-{sid_upper}"
        return sid_upper

    def preload(self, client: "ADWSClient") -> None:
        """Bulk-fetch all principals and populate cache."""
        log.info("Pre-loading SID/GUID/DN cache from ADWS …")
        try:
            objects = client.search(_PRELOAD_FILTER, _PRELOAD_ATTRS)
        except Exception as exc:
            log.warning("Cache preload failed: %s — resolution will use per-object queries", exc)
            return

        for obj in objects:
            sid = obj.get("objectSid")
            guid = obj.get("objectGUID")
            dn = obj.get("distinguishedName")
            obj_type = _object_type(obj)

            identifier = sid or (f"{{{guid}}}" if guid else None)
            if not identifier:
                continue

            tp = TypedPrincipal(ObjectIdentifier=identifier.upper(), ObjectType=obj_type)

            if sid:
                self._sid[sid.upper()] = tp
            if guid:
                self._guid[guid.upper()] = tp
            if dn:
                self._dn[dn.upper()] = tp

        log.info("Cache preloaded: %d SIDs, %d GUIDs, %d DNs",
                 len(self._sid), len(self._guid), len(self._dn))

    def qualify_sid(self, sid: str) -> str:
        """Return the BloodHound-qualified ObjectIdentifier for a SID."""
        return self._qualify(sid)

    def resolve_sid(self, sid: str) -> Optional[TypedPrincipal]:
        return self._sid.get(sid.upper())

    def resolve_guid(self, guid: str) -> Optional[TypedPrincipal]:
        key = guid.upper().strip("{}")
        return self._guid.get(key)

    def resolve_dn(self, dn: str) -> Optional[TypedPrincipal]:
        return self._dn.get(dn.upper())

    def add(self, identifier: str, obj_type: str) -> TypedPrincipal:
        tp = TypedPrincipal(ObjectIdentifier=identifier.upper(), ObjectType=obj_type)
        self._sid[identifier.upper()] = tp
        return tp

    def resolve_dn_to_sid(
        self, dn: str, client: Optional["ADWSClient"] = None
    ) -> Optional[TypedPrincipal]:
        """Resolve a DN; falls back to a live ADWS query if not cached."""
        result = self.resolve_dn(dn)
        if result:
            return result

        if client is None:
            return None

        # Live lookup
        try:
            objs = client.search(
                f"(distinguishedName={dn})",
                ["objectSid", "objectGUID", "sAMAccountType", "objectClass"],
            )
        except Exception:
            return None

        for obj in objs:
            sid = obj.get("objectSid")
            guid = obj.get("objectGUID")
            obj_type = _object_type(obj)
            identifier = sid or (f"{{{guid}}}" if guid else None)
            if not identifier:
                continue
            tp = TypedPrincipal(ObjectIdentifier=identifier.upper(), ObjectType=obj_type)
            self._dn[dn.upper()] = tp
            if sid:
                self._sid[sid.upper()] = tp
            if guid:
                self._guid[guid.upper()] = tp
            return tp

        return None
