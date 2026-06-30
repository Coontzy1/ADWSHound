"""Domain object collector."""
from __future__ import annotations

from adwshound.collectors.base import BaseCollector, first
from adwshound.collectors.ous import _parse_gplinks
from adwshound.schema.types import DomainOutput, empty_gpo_changes

_FILTER = "(objectClass=domain)"

_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName", "name",
    "description", "whenCreated", "ms-DS-MachineAccountQuota",
    "msDS-Behavior-Version",
    "minPwdLength", "pwdProperties", "pwdHistoryLength",
    "lockoutThreshold", "minPwdAge", "maxPwdAge",
    "lockoutDuration", "lockoutObservationWindow",
    "msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
    "gPLink", "gPOptions",
    "nTSecurityDescriptor",
]

# Fetched from Configuration NC — not on domain root object
_DS_HEURISTICS_FILTER = "(objectClass=nTDSService)"
_DS_HEURISTICS_ATTRS  = ["dSHeuristics"]

_FUNCTIONAL_LEVELS = {
    0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008",
    4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016",
}

# 1 day = 864000000000 × 100-nanosecond intervals (stored as negative in AD)
_DAY_TICKS  = 864000000000
_MIN_TICKS  = 600000000


def _ticks_to_days(val) -> str:
    """Convert Windows negative 100-ns interval to 'N days' string."""
    if val is None:
        return "0"
    try:
        ticks = int(val)
    except (TypeError, ValueError):
        return "0"
    if ticks == 0:
        return "0"
    return f"{abs(ticks) // _DAY_TICKS} days"


def _ticks_to_minutes(val) -> str:
    """Convert Windows negative 100-ns interval to minutes string. 0 = Forever."""
    if val is None:
        return "0"
    try:
        ticks = int(val)
    except (TypeError, ValueError):
        return "0"
    if ticks == 0:
        return "Forever"
    return str(abs(ticks) // _MIN_TICKS)


class DomainCollector(BaseCollector):

    def _dsheuristics(self) -> str | None:
        """Query Configuration NC for dSHeuristics setting."""
        try:
            results = self.client.search_config_nc(
                _DS_HEURISTICS_FILTER, _DS_HEURISTICS_ATTRS
            )
            if results:
                val = results[0].get("dSHeuristics")
                return str(val) if val is not None else None
        except Exception as exc:
            self.log.debug("dSHeuristics lookup failed: %s", exc)
        return None

    def _forest_root_sid(self, domain_dn: str) -> str:
        """Resolve forest root domain SID via Configuration NC crossRef objects.

        The forest root crossRef has no trustParent and systemFlags bit 2 set
        (indicating it is a naming context owned by an NTDS domain).
        Falls back to self.domain_sid if resolution fails.
        """
        try:
            # systemFlags & 0x2 = NC is owned by the local domain (vs read-only replica)
            results = self.client.search_config_nc(
                "(&(objectClass=crossRef)(!(trustParent=*))(systemFlags:1.2.840.113556.1.4.803:=3))",
                ["nCName", "nETBIOSName"],
            )
            for cr in results:
                nc = first(cr, "nCName", "")
                if not nc:
                    continue
                if nc.upper() == domain_dn.upper():
                    return self.domain_sid
                # Different domain — try to get its SID from a domain object query
                # via the resolver cache (may be preloaded for forest trusts)
                tp = self.cache.resolve_dn(nc)
                if tp and tp.ObjectType == "Domain":
                    return tp.ObjectIdentifier
        except Exception as exc:
            self.log.debug("Forest root SID resolution failed: %s", exc)
        return self.domain_sid

    def _netbios_name(self, domain_dn: str) -> str | None:
        """Query Configuration NC for the NetBIOS name of the domain."""
        try:
            results = self.client.search_config_nc(
                f"(&(objectClass=crossRef)(nCName={domain_dn}))",
                ["nETBIOSName"],
            )
            if results:
                return results[0].get("nETBIOSName")
        except Exception as exc:
            self.log.debug("NetBIOS name lookup failed: %s", exc)
        return None

    def collect(self) -> list[DomainOutput]:
        self.log.info("Collecting domain objects …")
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

            dn         = first(obj, "distinguishedName", "")
            func_level = int(obj.get("msDS-Behavior-Version") or 0)

            netbios          = self._netbios_name(dn)
            dsheuristics     = self._dsheuristics()
            forest_root_sid  = self._forest_root_sid(dn)

            props = {
                "domain":          self.domain,
                "name":            self.domain,
                "distinguishedname": dn.upper() if dn else "",
                "domainsid":       self.domain_sid,
                "doesanyacegrantownerrights":          False,
                "doesanyinheritedacegrantownerrights": False,
                "isaclprotected":  False,
                "description":     first(obj, "description", None),
                "functionallevel": _FUNCTIONAL_LEVELS.get(func_level, str(func_level)),
                "machineaccountquota": int(obj.get("ms-DS-MachineAccountQuota") or 10),
                "whencreated":     obj.get("whenCreated", -1),
                "minpwdlength":    int(obj.get("minPwdLength") or 0),
                "pwdproperties":   int(obj.get("pwdProperties") or 0),
                "pwdhistorylength": int(obj.get("pwdHistoryLength") or 0),
                "lockoutthreshold": int(obj.get("lockoutThreshold") or 0),
                "minpwdage":       _ticks_to_days(obj.get("minPwdAge")),
                "maxpwdage":       _ticks_to_days(obj.get("maxPwdAge")),
                "lockoutduration": _ticks_to_minutes(obj.get("lockoutDuration")),
                "lockoutobservationwindow": _ticks_to_minutes(obj.get("lockoutObservationWindow")),
                "expirepasswordsonsmartcardonlyaccounts": bool(
                    obj.get("msDS-ExpirePasswordsOnSmartCardOnlyAccounts")
                ),
                "collected":       True,
                "netbios":         netbios,
                "dsheuristics":    dsheuristics,
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

            links = _parse_gplinks(first(obj, "gPLink", "") or "")

            results.append(DomainOutput(
                GPOChanges=empty_gpo_changes(),
                Properties=props,
                ChildObjects=[],
                Trusts=[],
                Links=links,
                InheritanceHashes=inheritance_hashes,
                ForestRootIdentifier=forest_root_sid,
                Aces=aces,
                ObjectIdentifier=identifier.upper(),
                IsACLProtected=props.get("isaclprotected", False),
            ))

        self.log.info("Collected %d domain objects", len(results))
        return results
