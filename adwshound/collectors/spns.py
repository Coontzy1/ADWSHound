"""SPN target enumeration — finds Kerberoastable user accounts."""
from __future__ import annotations

from adwshound.collectors.base import BaseCollector, first, as_list
from adwshound.schema.types import UserOutput, SPNTarget

# Only user accounts (not computers) with SPNs
_FILTER = (
    "(&(servicePrincipalName=*)"
    "(sAMAccountType=805306368)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    ")"
)

_ATTRS = [
    "objectGUID", "objectSid", "sAMAccountName",
    "servicePrincipalName", "distinguishedName",
    "userAccountControl", "pwdLastSet",
]


class SPNCollector(BaseCollector):
    """Enumerate Kerberoastable accounts and their SPN targets.

    These supplement the UserCollector results; SPNTargets are injected
    into the matching UserOutput objects during post-processing.
    """

    def collect(self) -> list[dict]:
        """Return list of dicts with sid→spn_targets for merging into UserOutput."""
        self.log.info("Collecting SPN targets …")
        objects = self.client.search(_FILTER, _ATTRS)
        results = []

        for obj in objects:
            sid = obj.get("objectSid")
            if not sid:
                continue

            spns = as_list(obj, "servicePrincipalName")
            targets = []
            for spn in spns:
                if "/" not in spn:
                    continue
                svc, rest = spn.split("/", 1)
                # SharpHound ReadSPNTargets only emits MSSQL service targets
                if svc.lower() != "mssqlsvc":
                    continue
                host_port = rest.split(":")
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else _default_port(svc)

                comp_sid = self._resolve_computer(host)
                if comp_sid:
                    targets.append(SPNTarget(
                        ComputerSID=comp_sid.upper(),
                        Port=port,
                        Service=svc,
                    ))

            if targets:
                results.append({
                    "user_sid": sid.upper(),
                    "spn_targets": targets,
                })

        self.log.info("Found %d Kerberoastable accounts with SPN targets", len(results))
        return results

    def _resolve_computer(self, hostname: str) -> str | None:
        objs = self.client.search(f"(dNSHostName={hostname})", ["objectSid"])
        if not objs:
            short = hostname.split(".")[0].upper()
            objs = self.client.search(f"(sAMAccountName={short}$)", ["objectSid"])
        if objs:
            return objs[0].get("objectSid")
        return None


def _default_port(service: str) -> int:
    _PORTS = {
        "MSSQLSvc": 1433, "MSSQL": 1433,
        "HTTP": 80, "HTTPS": 443,
        "ldap": 389, "ldaps": 636,
        "gc": 3268, "gc_ssl": 3269,
        "cifs": 445, "host": 445, "smb": 445,
        "termsrv": 3389, "TERMSRV": 3389,
        "wsman": 5985, "WSMan": 5985,
        "kadmin": 749, "kerberos": 88,
        "ftp": 21, "smtp": 25, "dns": 53,
        "imap": 143, "imaps": 993,
        "pop": 110, "pop3s": 995,
    }
    return _PORTS.get(service, 0)
