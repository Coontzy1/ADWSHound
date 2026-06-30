"""BloodHound v6 output schema — exact match to SharpHound 2.9 JSON structure."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field  # noqa: F401
from typing import Any, Optional


def _asdict(obj) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _asdict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_asdict(i) for i in obj]
    return obj


# ─── Primitives ───────────────────────────────────────────────────────────────

@dataclass
class ACE:
    PrincipalSID: str
    PrincipalType: str
    RightName: str
    IsInherited: bool
    InheritanceHash: str = ""
    IsPermissionForOwnerRightsSid: bool = False
    IsInheritedPermissionForOwnerRightsSid: bool = False


@dataclass
class TypedPrincipal:
    ObjectIdentifier: str
    ObjectType: str


@dataclass
class SPNTarget:
    ComputerSID: str
    Port: int
    Service: str


@dataclass
class SessionResult:
    UserSID: str
    ComputerSID: str


@dataclass
class CollectionResult:
    Results: list
    Collected: bool
    FailureReason: Optional[str] = None


@dataclass
class LocalGroupResult:
    """A computer's local group (Administrators, RDP, …) for BloodHound.

    Needs ObjectIdentifier ("<computerSID>-<RID>") and Name
    ("GROUP@COMPUTER.FQDN") so BloodHound can build the local group node and
    its AdminTo / CanRDP / ExecuteDCOM / CanPSRemote edges; without them the
    members are dropped (Local Admins shows 0).
    """
    ObjectIdentifier: str
    Name: str
    Results: list
    Collected: bool = True
    FailureReason: Optional[str] = None
    LocalNames: list = field(default_factory=list)


@dataclass
class DomainTrust:
    TargetDomainSid: str
    TargetDomainName: str
    IsTransitive: bool
    SidFilteringEnabled: bool
    TGTDelegationEnabled: bool
    TrustDirection: str
    TrustType: str


@dataclass
class GPOLink:
    GUID: str        # uppercase key, NO braces: "ABC123-..."
    IsEnforced: bool


@dataclass
class GPOChanges:
    LocalAdmins: list
    RemoteDesktopUsers: list
    DcomUsers: list
    PSRemoteUsers: list
    AffectedComputers: list


@dataclass
class DCRegistryData:
    CertificateMappingMethods: Optional[Any] = None
    StrongCertificateBindingEnforcement: Optional[Any] = None
    VulnerableNetlogonSecurityDescriptor: Optional[Any] = None


@dataclass
class SmbInfoData:
    Signing: Optional[bool] = None
    SigningEnabled: Optional[bool] = None
    SMBv1Enabled: Optional[bool] = None
    OsVersion: Optional[str] = None


@dataclass
class NTLMRegistryData:
    LmCompatibilityLevel: Optional[int] = None
    NoLMHash: Optional[bool] = None
    RestrictNTLMInDomain: Optional[int] = None
    RestrictSendingNTLMTraffic: Optional[int] = None
    IncomingNTLMFilter: Optional[int] = None


@dataclass
class LdapServicesData:
    LdapSigning: Optional[int] = None
    LdapChannelBinding: Optional[int] = None


@dataclass
class UserRight:
    Privilege: str
    Results: list


@dataclass
class ComputerStatus:
    Connectable: bool = False
    Error: Optional[str] = None


def empty_gpo_changes() -> GPOChanges:
    return GPOChanges([], [], [], [], [])


# ─── AD Object types ──────────────────────────────────────────────────────────

@dataclass
class UserOutput:
    Properties: dict
    AllowedToDelegate: list
    AllowedToAct: list
    PrimaryGroupSID: Optional[str]
    HasSIDHistory: list
    SPNTargets: list
    UnconstrainedDelegation: bool
    DomainSID: str
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class GroupOutput:
    Properties: dict
    Members: list
    HasSIDHistory: list
    DomainSID: str
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class ComputerOutput:
    Properties: dict
    PrimaryGroupSID: Optional[str]
    AllowedToDelegate: list
    AllowedToAct: list
    HasSIDHistory: list
    DumpSMSAPassword: list
    Sessions: CollectionResult
    PrivilegedSessions: CollectionResult
    RegistrySessions: CollectionResult
    LocalGroups: list
    UserRights: list
    DCRegistryData: DCRegistryData
    Status: ComputerStatus
    IsDC: bool
    UnconstrainedDelegation: bool
    DomainSID: str
    IsWebClientRunning: Optional[bool]
    SmbInfo: Optional[Any]
    NtlmSessions: Optional[Any]
    NTLMRegistryData: Optional[Any]
    LdapServicesData: Optional[Any]
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class DomainOutput:
    GPOChanges: GPOChanges
    Properties: dict
    ChildObjects: list
    Trusts: list
    Links: list
    InheritanceHashes: list
    ForestRootIdentifier: str
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class OUOutput:
    GPOChanges: GPOChanges
    Properties: dict
    Links: list
    ChildObjects: list
    InheritanceHashes: list
    Aces: list
    ObjectIdentifier: str      # plain GUID, no braces
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class ContainerOutput:
    Properties: dict
    ChildObjects: list
    InheritanceHashes: list
    Aces: list
    ObjectIdentifier: str      # plain GUID, no braces
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class GPOOutput:
    Properties: dict
    Aces: list
    ObjectIdentifier: str      # plain GUID, no braces
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


# ─── ADCS output types ────────────────────────────────────────────────────────

@dataclass
class CARegistryResult:
    Collected: bool = False
    FailureReason: Optional[str] = "Not collected via ADWS"


@dataclass
class CASecurityResult:
    Data: list = field(default_factory=list)
    Collected: bool = False
    FailureReason: Optional[str] = "Not collected via ADWS"


@dataclass
class CAEnrollmentRestrictions:
    Restrictions: list = field(default_factory=list)
    Collected: bool = False
    FailureReason: Optional[str] = "Not collected via ADWS"


@dataclass
class CABoolResult:
    Value: bool = False
    Collected: bool = False
    FailureReason: Optional[str] = "Not collected via ADWS"


@dataclass
class CARegistryData:
    CASecurity: CASecurityResult = field(default_factory=CASecurityResult)
    EnrollmentAgentRestrictions: CAEnrollmentRestrictions = field(
        default_factory=CAEnrollmentRestrictions
    )
    IsUserSpecifiesSanEnabled: CABoolResult = field(default_factory=CABoolResult)
    RoleSeparationEnabled: CABoolResult = field(default_factory=CABoolResult)


@dataclass
class RootCAOutput:
    Properties: dict
    DomainSID: str
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class AIACAOutput:
    Properties: dict
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class EnterpriseCAOutput:
    Properties: dict
    HostingComputer: Optional[str]   # SID string (BloodHound schema), not a TypedPrincipal
    CARegistryData: CARegistryData
    EnabledCertTemplates: list
    HttpEnrollmentEndpoints: list
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class NTAuthStoreOutput:
    Properties: dict
    DomainSID: str
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class CertTemplateOutput:
    Properties: dict
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


@dataclass
class IssuancePolicyOutput:
    Properties: dict
    GroupLink: TypedPrincipal
    Aces: list
    ObjectIdentifier: str
    IsDeleted: bool = False
    IsACLProtected: bool = False
    ContainedBy: Optional[TypedPrincipal] = None


# ─── Collection method bitmask ────────────────────────────────────────────────

class CollectionMethod:
    Group          = 0x00001
    LocalGroup     = 0x00002
    GPOLocalGroup  = 0x00004
    Session        = 0x00008
    LoggedOn       = 0x00010
    Trusts         = 0x00020
    ACL            = 0x00040
    Container      = 0x00080
    RDP            = 0x00100
    ObjectProps    = 0x00200
    SPNTargets     = 0x00400
    DCOM           = 0x00800
    PSRemote       = 0x01000
    UserRights     = 0x02000
    CARegistry     = 0x04000
    DCRegistry     = 0x08000
    CertServices   = 0x10000

    WebClientService = 0x20000
    LdapServices     = 0x40000
    SmbInfo          = 0x80000
    NTLMRegistry     = 0x100000

    Default = (Group | LocalGroup | GPOLocalGroup | Session | LoggedOn | Trusts |
               ACL | Container | ObjectProps | UserRights)
    DCOnly  = Group | LocalGroup | GPOLocalGroup | LoggedOn | Trusts | ACL | Container | ObjectProps | UserRights
    ComputerOnly = (LocalGroup | Session | LoggedOn | RDP | DCOM | PSRemote |
                    UserRights | WebClientService | SmbInfo | NTLMRegistry)
    All     = (Group | LocalGroup | GPOLocalGroup | Session | LoggedOn | Trusts |
               ACL | Container | RDP | ObjectProps | SPNTargets | DCOM | PSRemote |
               UserRights | CARegistry | DCRegistry | CertServices |
               WebClientService | LdapServices | SmbInfo | NTLMRegistry)

    _NAME_MAP = {
        "group": Group, "localgroup": LocalGroup, "localadmin": LocalGroup,
        "gpolocalgroup": GPOLocalGroup, "session": Session, "loggedon": LoggedOn,
        "trusts": Trusts, "acl": ACL, "container": Container, "rdp": RDP,
        "objectprops": ObjectProps, "objectproperties": ObjectProps,
        "spntargets": SPNTargets, "spn": SPNTargets, "dcom": DCOM,
        "psremote": PSRemote, "userrights": UserRights, "caregistry": CARegistry,
        "dcregistry": DCRegistry, "certservices": CertServices,
        "webclientservice": WebClientService, "webclient": WebClientService,
        "ldapservices": LdapServices, "ldap": LdapServices,
        "smbinfo": SmbInfo, "smb": SmbInfo,
        "ntlmregistry": NTLMRegistry, "ntlm": NTLMRegistry,
        "default": Default, "dconly": DCOnly,
        "computeronly": ComputerOnly, "all": All,
    }

    @classmethod
    def parse(cls, methods_str: str) -> int:
        mask = 0
        for tok in methods_str.replace(" ", "").split(","):
            tok_lower = tok.lower()
            if tok_lower not in cls._NAME_MAP:
                raise ValueError(f"Unknown collection method: {tok!r}")
            mask |= cls._NAME_MAP[tok_lower]
        return mask
