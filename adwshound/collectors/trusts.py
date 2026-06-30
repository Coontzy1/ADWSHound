"""Domain trust enumeration collector.

Queries trustedDomain objects and produces DomainTrust entries
that are attached to the DomainOutput objects.
"""
from __future__ import annotations

import logging
from adwshound.collectors.base import BaseCollector, first
from adwshound.schema.types import DomainTrust

log = logging.getLogger(__name__)

_FILTER = "(objectClass=trustedDomain)"

_ATTRS = [
    "cn", "flatName", "trustType", "trustAttributes",
    "trustDirection", "securityIdentifier", "distinguishedName",
    "whenCreated",
]

# Trust direction flags (trustDirection attribute)
TRUST_DIRECTION_DISABLED     = 0
TRUST_DIRECTION_INBOUND      = 1
TRUST_DIRECTION_OUTBOUND     = 2
TRUST_DIRECTION_BIDIRECTIONAL = 3

_DIRECTION_MAP = {
    TRUST_DIRECTION_DISABLED:      "Disabled",
    TRUST_DIRECTION_INBOUND:       "Inbound",
    TRUST_DIRECTION_OUTBOUND:      "Outbound",
    TRUST_DIRECTION_BIDIRECTIONAL: "Bidirectional",
}

# Trust type flags (trustType attribute)
TRUST_TYPE_DOWNLEVEL  = 1   # Windows NT
TRUST_TYPE_UPLEVEL    = 2   # Windows 2000+
TRUST_TYPE_MIT        = 3   # Non-Windows Kerberos realm
TRUST_TYPE_DCE        = 4   # DCE

# trustAttributes flags
TRUST_ATTR_NON_TRANSITIVE          = 0x0001
TRUST_ATTR_UPLEVEL_ONLY            = 0x0002
TRUST_ATTR_FILTER_SIDS             = 0x0004
TRUST_ATTR_FOREST_TRANSITIVE       = 0x0008
TRUST_ATTR_CROSS_ORG               = 0x0010
TRUST_ATTR_WITHIN_FOREST           = 0x0020
TRUST_ATTR_TREAT_AS_EXTERNAL       = 0x0040
TRUST_ATTR_USES_RC4_ENCRYPTION     = 0x0080
TRUST_ATTR_CROSS_ORG_NO_TGT_DELEG  = 0x0200
TRUST_ATTR_PIM_TRUST               = 0x0400
TRUST_ATTR_CROSS_ORG_ENABLE_TGT_DELEG = 0x0800


def _trust_type_name(trust_type: int, trust_attrs: int) -> str:
    if trust_attrs & TRUST_ATTR_WITHIN_FOREST:
        return "ParentChild"
    if trust_attrs & TRUST_ATTR_FOREST_TRANSITIVE:
        return "Forest"
    if trust_attrs & TRUST_ATTR_CROSS_ORG:
        return "CrossLink"
    if trust_attrs & TRUST_ATTR_TREAT_AS_EXTERNAL:
        return "External"
    if trust_type == TRUST_TYPE_MIT:
        return "External"
    return "Unknown"


def _is_transitive(trust_attrs: int) -> bool:
    return not bool(trust_attrs & TRUST_ATTR_NON_TRANSITIVE)


def _sid_filtering_enabled(trust_attrs: int) -> bool:
    return bool(trust_attrs & TRUST_ATTR_FILTER_SIDS)


def _tgt_delegation_enabled(trust_attrs: int) -> bool:
    # Cross-org trusts disable TGT delegation unless ENABLE_TGT_DELEG is set.
    if trust_attrs & TRUST_ATTR_CROSS_ORG_ENABLE_TGT_DELEG:
        return True
    if trust_attrs & TRUST_ATTR_CROSS_ORG_NO_TGT_DELEG:
        return False
    return not bool(trust_attrs & TRUST_ATTR_CROSS_ORG)


class TrustCollector(BaseCollector):

    def collect(self) -> list[DomainTrust]:
        self.log.info("Collecting domain trusts …")
        objects = self.client.search(_FILTER, _ATTRS)
        results = []

        for obj in objects:
            cn = first(obj, "cn", "")
            flat = first(obj, "flatName", "")

            trust_type_int = int(obj.get("trustType") or 0)
            trust_attrs_int = int(obj.get("trustAttributes") or 0)
            trust_dir_int = int(obj.get("trustDirection") or 0)

            sid_raw = obj.get("securityIdentifier")
            if isinstance(sid_raw, bytes):
                from impacket.ldap.ldaptypes import LDAP_SID
                target_sid = LDAP_SID(data=sid_raw).formatCanonical()
            elif sid_raw:
                target_sid = str(sid_raw)
            else:
                target_sid = ""

            results.append(DomainTrust(
                TargetDomainSid=target_sid.upper(),
                TargetDomainName=cn.upper(),
                IsTransitive=_is_transitive(trust_attrs_int),
                SidFilteringEnabled=_sid_filtering_enabled(trust_attrs_int),
                TGTDelegationEnabled=_tgt_delegation_enabled(trust_attrs_int),
                TrustDirection=_DIRECTION_MAP.get(trust_dir_int, "Unknown"),
                TrustType=_trust_type_name(trust_type_int, trust_attrs_int),
            ))

        self.log.info("Collected %d trusts", len(results))
        return results
