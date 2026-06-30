"""ACL parsing and extended right / schema GUID resolution.

parse_acl() is the main entry point used by every other collector
when collect_acls=True.  It takes a raw nTSecurityDescriptor bytes
blob and returns a list of ACE dicts ready for BloodHound.

Extended right GUIDs are loaded once from the Configuration NC on
first call and cached in module-level dicts.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import TYPE_CHECKING

from adwshound.schema.types import ACE, TypedPrincipal

if TYPE_CHECKING:
    from adwshound.resolvers.cache import ResolverCache
    from adwshound.transport.client import ADWSClient

log = logging.getLogger(__name__)

# ─── ACE right constants ──────────────────────────────────────────────────────

GENERIC_ALL          = 0x000F01FF
WRITE_DACL           = 0x00040000
WRITE_OWNER          = 0x00080000
READ_CONTROL         = 0x00020000

# ADS_RIGHT_DS_WRITE_PROP
DS_WRITE_PROP        = 0x00000020
# ADS_RIGHT_DS_CONTROL_ACCESS (extended right)
DS_CONTROL_ACCESS    = 0x00000100
# ADS_RIGHT_DS_SELF (self-relative write)
DS_SELF              = 0x00000008
# ADS_RIGHT_DS_CREATE_CHILD
DS_CREATE_CHILD      = 0x00000001
# ADS_RIGHT_DS_DELETE_CHILD
DS_DELETE_CHILD      = 0x00000002

# ─── Well-known extended right GUIDs ─────────────────────────────────────────
# https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password

# Extended rights (DS_CONTROL_ACCESS) → BloodHound CE edge names.
# NOTE: BloodHound has NO "DCSync" ACE edge — DCSync is a *composite* it derives in
# post-processing from a principal holding BOTH GetChanges and GetChangesAll on the
# domain. So we must emit those two component edges, never "DCSync".
_EXTENDED_RIGHTS: dict[str, str] = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",             # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",          # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "ReadLAPSPassword",  # ms-Mcs-AdmPwd
    "4662e521-b70f-4eff-8c17-aea1cc820b0a": "ReadLAPSPassword",  # ms-LAPS-Password
    "b8ff6735-5a23-4a6c-a69c-f6a00c7d0681": "ReadLAPSPassword",  # ms-LAPS-EncryptedPassword
    "fe814bc9-8cf8-4c2a-b1e2-0566ad38c14b": "ReadLAPSPassword",
    "ee791a9f-2f55-4a5a-927b-f45d5e9dff30": "ManageCA",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a3": "ManageCertificates",
}

# Validated writes (DS_SELF) → BloodHound CE edge names.
_VALIDATED_WRITES: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",   # Self-Membership (member)
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "WriteSPN",    # Validated-SPN
}

# Specific property writes (DS_WRITE_PROP) → BloodHound CE edge names. Only the
# abusable attributes become edges; other property writes are not graph edges.
_WRITABLE_PROPS: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",            # member
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "WriteGPLink",          # gPLink
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "AddAllowedToAct",      # msDS-AllowedToActOnBehalfOfOtherIdentity
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "AddKeyCredentialLink", # msDS-KeyCredentialLink
    "4c164200-20c0-11d0-a768-00aa006e0529": "WriteAccountRestrictions",  # User-Account-Restrictions property set
    "bf967a68-0de6-11d0-a285-00aa003049e2": "WriteAccountRestrictions",  # userAccountControl attribute
}
# Fallback by attribute lDAPDisplayName (resolved via schema cache) when the GUID
# isn't in _WRITABLE_PROPS above — covers environment-specific schemaIDGUIDs.
_WRITABLE_PROP_NAMES: dict[str, str] = {
    "member": "AddMember",
    "gplink": "WriteGPLink",
    "serviceprincipalname": "WriteSPN",
    "msds-keycredentiallink": "AddKeyCredentialLink",
    "msds-allowedtoactonbehalfofotheridentity": "AddAllowedToAct",
}

# SIDs to skip (not interesting for BloodHound graph)
_SKIP_SIDS = {
    "S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3",  # Creator SIDs
    "S-1-5-18",   # Local System
    "S-1-5-19", "S-1-5-20",
    "S-1-5-9",    # Enterprise Domain Controllers (too noisy)
}

# Cache of extended rights loaded from Config NC
_rights_cache: dict[str, str] = {}
_schema_cache: dict[str, str] = {}
_caches_loaded = False


def load_guid_caches(client: "ADWSClient") -> None:
    """Load extended rights and schema attribute GUIDs from Config NC. Call once."""
    global _caches_loaded
    if _caches_loaded:
        return

    # Extended rights
    try:
        rights = client.search_config_nc(
            "(objectClass=controlAccessRight)",
            ["cn", "rightsGuid"],
        )
        for r in rights:
            guid = r.get("rightsGuid")
            name = r.get("cn")
            if guid and name:
                _rights_cache[guid.lower()] = str(name)
    except Exception as exc:
        log.warning("Could not load extended rights from Config NC: %s", exc)

    # Schema attributes
    try:
        attrs = client.search_schema_nc(
            "(objectClass=attributeSchema)",
            ["cn", "schemaIDGUID"],
        )
        for a in attrs:
            guid_bytes = a.get("schemaIDGUID")
            name = a.get("cn")
            if guid_bytes and name and isinstance(guid_bytes, bytes):
                from uuid import UUID
                try:
                    guid_str = str(UUID(bytes_le=guid_bytes))
                    _schema_cache[guid_str.lower()] = str(name)
                except Exception:
                    pass
    except Exception as exc:
        log.warning("Could not load schema GUIDs from schema NC: %s", exc)

    _caches_loaded = True
    log.debug("Loaded %d extended rights, %d schema attrs", len(_rights_cache), len(_schema_cache))


def _ace_right_name(mask: int, object_type_guid: str | None) -> str | None:
    """Map ACE access mask (+ optional ObjectType GUID) → BloodHound right name."""
    # GENERIC_ALL is a multi-bit mask; require full containment (SharpHound HasFlag
    # semantics). A truthy `&` would swallow WriteDacl/WriteOwner/WriteProperty,
    # since their bits are subsets of GENERIC_ALL (0x000F01FF).
    if mask & GENERIC_ALL == GENERIC_ALL:
        return "GenericAll"
    if mask & WRITE_DACL:
        return "WriteDacl"
    if mask & WRITE_OWNER:
        return "WriteOwner"

    if object_type_guid:
        guid_lower = object_type_guid.lower()

        # Extended right targeting a specific GUID (e.g. GetChanges, ForceChangePassword).
        # An unrecognised specific extended right is NOT "AllExtendedRights" — emit no
        # edge (must not fall through to the all-rights case below, or every benign
        # per-right ACE becomes a bogus AllExtendedRights edge, e.g. Everyone→Domain Admins).
        if mask & DS_CONTROL_ACCESS:
            return _EXTENDED_RIGHTS.get(guid_lower)  # None if unknown → no edge

        # Validated write (DS_SELF) on a specific attribute (member, SPN)
        if mask & DS_SELF:
            right = _VALIDATED_WRITES.get(guid_lower)
            if right:
                return right

        # Write to a specific property → BloodHound edge only for abusable attrs
        if mask & DS_WRITE_PROP:
            right = _WRITABLE_PROPS.get(guid_lower)
            if not right:
                cn = _schema_cache.get(guid_lower)
                if cn:
                    right = _WRITABLE_PROP_NAMES.get(cn.lower())
            if right:
                return right
            return None  # non-abusable specific-property write → no graph edge

    # Control access on ALL extended rights (no specific GUID) — grants DCSync etc.
    if mask & DS_CONTROL_ACCESS:
        return "AllExtendedRights"

    # Write ALL properties with no specific attribute target = GenericWrite
    if mask & DS_WRITE_PROP:
        return "GenericWrite"

    return None


def parse_acl(
    sd_bytes: bytes,
    cache: "ResolverCache",
    object_identifier: str,
) -> tuple[list[ACE], bool]:
    """Parse a nTSecurityDescriptor binary blob into (aces, is_protected).

    is_protected reflects the SE_DACL_PROTECTED control flag (inheritance blocked).
    The owner SID is extracted and emitted as an Owns ACE.
    """
    try:
        from impacket.ldap.ldaptypes import (
            SR_SECURITY_DESCRIPTOR,
            ACCESS_ALLOWED_ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
            ACCESS_ALLOWED_CALLBACK_ACE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
        )
        from uuid import UUID
    except ImportError:
        log.error("impacket not installed — ACL collection unavailable")
        return [], False

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception as exc:
        log.debug("SD parse error for %s: %s", object_identifier, exc)
        return [], False

    # SE_DACL_PROTECTED (0x1000): ACL inheritance is blocked on this object
    is_protected = bool(int(sd["Control"]) & 0x1000)

    aces: list[ACE] = []

    # Object owner has implicit write rights — emit as Owns ACE
    try:
        owner_sid = sd["OwnerSid"].formatCanonical()
        if owner_sid and owner_sid not in _SKIP_SIDS:
            owner_tp = cache.resolve_sid(owner_sid)
            if not owner_tp:
                owner_tp = TypedPrincipal(
                    ObjectIdentifier=cache.qualify_sid(owner_sid),
                    ObjectType="Base",
                )
            aces.append(ACE(
                PrincipalSID=owner_tp.ObjectIdentifier,
                PrincipalType=owner_tp.ObjectType,
                RightName="Owns",
                IsInherited=False,
            ))
    except Exception:
        pass

    if not sd["Dacl"]:
        return aces, is_protected

    for ace in sd["Dacl"].aces:
        ace_type = ace["AceType"]
        ace_flags = ace["AceFlags"]

        # Only handle allow ACEs
        if ace_type not in (
            ACCESS_ALLOWED_ACE.ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_ACE.ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE.ACE_TYPE,
        ):
            continue

        # INHERIT_ONLY_ACE (0x08): the ACE applies only to descendant objects, NOT to
        # this object — skip it, or it produces phantom edges on the current node
        # (SharpHound does the same).
        if ace_flags & 0x08:
            continue

        is_inherited = bool(ace_flags & 0x10)  # INHERITED_ACE

        ace_body = ace["Ace"]
        sid = ace_body["Sid"].formatCanonical()

        if sid in _SKIP_SIDS:
            continue

        mask = int(ace_body["Mask"]["Mask"])

        # ObjectType GUID for object ACEs
        object_type_guid = None
        if ace_type in (
            ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE.ACE_TYPE,
        ):
            # ace_body is an impacket Structure, not a dict → index, don't .get()
            try:
                flags = int(ace_body["Flags"])
            except Exception:
                flags = 0
            if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                try:
                    raw = bytes(ace_body["ObjectType"])
                    object_type_guid = str(UUID(bytes_le=raw))
                except Exception:
                    pass

        right = _ace_right_name(mask, object_type_guid)
        if right is None:
            continue

        tp = cache.resolve_sid(sid)
        if not tp:
            tp = TypedPrincipal(ObjectIdentifier=cache.qualify_sid(sid), ObjectType="Base")

        aces.append(ACE(
            PrincipalSID=tp.ObjectIdentifier,
            PrincipalType=tp.ObjectType,
            RightName=right,
            IsInherited=is_inherited,
        ))

    return aces, is_protected


def compute_inheritance_hashes(aces: list) -> list[str]:
    """Compute per-inherited-ACE hashes for InheritanceHashes field.

    Mirrors SharpHoundCommonLib ACLProcessor.GetInheritedAceHashes():
    for each inherited ACE emit a SHA1 hash of its canonical representation.
    BloodHound CE uses these hashes to detect objects with default-inherited ACLs.
    """
    import hashlib
    hashes = []
    for ace in aces:
        if not ace.IsInherited:
            continue
        canonical = f"{ace.PrincipalSID}|{ace.RightName}"
        h = hashlib.sha1(canonical.encode()).hexdigest().upper()
        hashes.append(h)
    return hashes
