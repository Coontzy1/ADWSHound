# ADWSHound

BloodHound collector that enumerates Active Directory over **Active Directory Web Services
(ADWS, TCP/9389)** instead of LDAP. Produces JSON/ZIP compatible with **BloodHound CE**
(SharpHound v6 schema).

The goal: the same data SharpHound collects, but the directory queries travel over ADWS (SOAP
on 9389) rather than LDAP (389/636), which is quieter and bypasses LDAP-focused controls.

> Built on **[SoaPy](https://github.com/logangoins/SoaPy)** — see *Credits / SoaPy* below.

---

## How it works

Each directory query is a WS-Enumeration exchange to
`net.tcp://DC:9389/ActiveDirectoryWebServices/Windows/Enumeration`: an `Enumerate` (filter +
attributes → EnumerationContext) followed by `Pull` messages that stream results. ADWSHound
parses the SOAP/NBFS responses back into the SharpHound object model and writes BloodHound v6 JSON.

> ADWS replaces the **LDAP directory queries only**. Remote *computer*-targeted methods
> (Sessions, LoggedOn, LocalGroup, UserRights, host checks, CA/DC registry) still use SMB/MSRPC
> over **445** via impacket. Pure-ADWS collection means avoiding those methods — see *OPSEC tiers*.

---

## Requirements

```
Python 3.10+
impacket>=0.11.0        # SMB/MSRPC, SID/SD parsing, NTLM/Kerberos primitives
pycryptodomex>=3.19.0
pyasn1>=0.5.0
dnspython>=2.4.0        # SRV-based DC auto-discovery + target hostname resolution
pyzipper>=0.3.6         # AES-encrypted ZIP output (--zippassword)
```
Optional: `lxml` (more robust XML recovery for malformed ADWS responses).

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Default collection
python3 adwshound.py -d domain.local -u user -p password --dc 10.0.0.1

# Everything
python3 adwshound.py -c All -d domain.local -u user -p password --dc 10.0.0.1

# Pass-the-hash
python3 adwshound.py -c Default -d domain.local -u user --hashes :NTHASH --dc 10.0.0.1

# Most-opsec (ADWS only, no host/SMB) — also exercises ACL/DCSync
python3 adwshound.py -d domain.local -u user -p pass --dc 10.0.0.1 \
  -c Group,ACL,Container,ObjectProps,Trusts --opsec --skipportcheck \
  --throttle 1000 --jitter 40

# Kerberos end-to-end (no NTLM anywhere) — TGT auto-requested from creds
python3 adwshound.py -c All -d domain.local -u user -p pass --dc 10.0.0.1 \
  -k --dc-host dc01.domain.local

# Kerberos with an existing ticket (kinit / getTGT.py) or AES key
export KRB5CCNAME=/path/to/user.ccache
python3 adwshound.py -c All -d domain.local -u user --dc 10.0.0.1 \
  -k --dc-host dc01.domain.local
python3 adwshound.py -c All -d domain.local -u user --aesKey <AES256> \
  --dc 10.0.0.1 --dc-host dc01.domain.local

# ADCS
python3 adwshound.py -c CertServices -d domain.local -u user -p pass --dc 10.0.0.1

# Forest / trusts
python3 adwshound.py -c Default --searchforest -d domain.local -u user -p pass --dc 10.0.0.1
python3 adwshound.py -c Default --recursedomains -d domain.local -u user -p pass --dc 10.0.0.1

# Capture a log
python3 adwshound.py -c All -d domain.local -u user -p pass --dc 10.0.0.1 \
  -vv 2>&1 | tee adwshound_$(date +%Y%m%d_%H%M%S).log
```
Password is prompted if `-p`/`--hashes` omitted. `-d` auto-detects from local FQDN; `--dc`
auto-resolves via `_ldap._tcp` SRV if omitted.

**Name resolution.** Remote collectors connect to computers by their `dNSHostName`, which a
non-domain-joined Linux box usually can't resolve. ADWSHound routes all target lookups through a
DNS server — by default the **DC** (when `--dc` is an IP), or `--nameserver <IP>` to override — so
collection works without editing `/etc/resolv.conf`. Literal IPs bypass it; failed lookups fall
back to the system resolver.

**Reachability gating.** Before remote collection, hosts are probed on **TCP:445**; only those that
answer are queried (Sessions/LocalGroup/UserRights/etc.), so dead/stale computer objects don't slow
the run or flood the log. `--skipportcheck` disables the probe and queries every computer.

---

## Collection methods

`-c` takes comma-separated, case-insensitive methods (or a preset). Users, Computers and Domains
are always collected.

| Method | Collects | Beyond ADWS |
|---|---|---|
| `Default` | Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, ObjectProps, UserRights | DC SMB + all computers |
| `DCOnly` | Group, LocalGroup, GPOLocalGroup, LoggedOn, Trusts, ACL, Container, ObjectProps, UserRights | DC SMB only |
| `All` | Everything below | DC + computers + CA |
| `ComputerOnly` | LocalGroup, Session, LoggedOn, RDP, DCOM, PSRemote, UserRights, WebClientService, SmbInfo, NTLMRegistry | Computers |
| `Group` | Group memberships | ADWS |
| `ACL` | ACEs from nTSecurityDescriptor (needs the SD_FLAGS control — handled) | ADWS |
| `Container` | OUs, containers, GPO links, DN hierarchy (ContainedBy/ChildObjects) | ADWS |
| `ObjectProps` | Extended object properties | ADWS |
| `Trusts` | Domain trusts | ADWS |
| `SPNTargets` | Kerberoastable MSSQL SPN targets | ADWS |
| `LocalGroup`/`LocalAdmin` · `RDP` · `DCOM` · `PSRemote` | Local group members (SAMR) | Computers (445) |
| `Session` · `LoggedOn` · `UserRights` | NetSessionEnum · registry+NetWkstaUserEnum · LSA | Computers (445) |
| `GPOLocalGroup` | Local groups from GPO XML (SYSVOL) | DC (445) |
| `CertServices` | ADCS: RootCA, AIACA, EnterpriseCA, NTAuthStore, CertTemplate, IssuancePolicy | ADWS + CA registry/HTTP |
| `CARegistry` · `DCRegistry` · `LdapServices` | CA registry (ESC6/role-sep/EA) · DC registry (Zerologon) · LDAP signing/CBT | CA/DC (445) |
| `SmbInfo` · `WebClientService` · `NTLMRegistry` | host checks | Computers (445) |

---

## Flags

```
Connection:
  -d/--domain          Domain FQDN (auto from local FQDN if omitted)
  --dc/--domaincontroller   DC IP/FQDN (auto via _ldap._tcp SRV if omitted)
  -u/--ldapusername    Username
  -p/--ldappassword    Password (prompted if omitted and no --hashes)
  --hashes LM:NT       Pass-the-hash
  -k/--kerberos        Kerberos for remote SMB/MSRPC collectors (see Auth note)
  --aesKey HEX         AES key for Kerberos (implies -k)
  --dc-host FQDN       KDC/DC hostname for Kerberos tickets
  --nameserver/--dns-server IP   DNS for resolving target hostnames (default: the DC)

Collection:
  -c/--CollectionMethods   Methods (default: Default)
  --stealth            Strip remote-computer methods; DC-only ADWS + GPOLocalGroup
  --searchforest       Enumerate all forest domains (crossRef)
  --recursedomains     Follow domain trusts recursively, collecting each trusted domain
  --excludedcs         Exclude DCs from computer-targeted collection
  --computerfile FILE  Restrict remote collection to listed computers
  --collectallproperties   Request all LDAP attributes (*) instead of curated set
  --skipportcheck      Skip TCP:445 probe before remote collection
  --skipregistryloggedon   Skip registry-based logged-on enumeration
  --opsec              Hex-escape LDAP filter values (alpha; numbers/names unchanged)
  --no-reuse           One ADWS connection per query (default: reuse one)

Output:  --outputdirectory DIR · --outputprefix PREFIX · --nozip · --zippassword PASS · --prettyprint
Perf:    -t/--threads N · --throttle MS · --jitter PCT
Misc:    -v/-vv · --version
```

---

## Authentication & logon footprint

- **NTLM and Pass-the-Hash** for the ADWS transport (`-p` or `--hashes`).
- **Connection reuse is the default**: one authenticated ADWS connection for the whole run (one
  NTLM logon instead of one per query). This avoids account lockout from logon volume and reduces
  detection noise. `--no-reuse` reverts to per-query connections (auto-retries once on failure).
- `-k/--kerberos` uses Kerberos **end-to-end** — the ADWS transport **and** the remote SMB/MSRPC
  collectors — so a run emits **no NTLM** anywhere (blends as 4768/4769, works where NTLM is
  restricted/disabled). The TGT is taken from the ccache (`$KRB5CCNAME`); get one first with
  `getTGT.py` or `kinit`. Use `--dc-host <FQDN>` (the ADWS SPN must resolve; not an IP). The ADWS
  Kerberos transport (AP-REQ over MS-NNS + GSS_Wrap sealing) is ported from SoaPy.

> If you see `SEC_E_LOGON_DENIED` after a few queries it's almost always **account lockout** from
> logon volume — reuse (default) removes the cause. Check `badPwdCount`/`lockoutTime` to confirm.

---

## OPSEC tiers (least → most noisy)

| Tier | Command | Footprint |
|---|---|---|
| 1 | `-c Group,ACL,Container,ObjectProps,Trusts --opsec --skipportcheck` | ADWS 9389 only. Zero SMB. |
| 2 | `-c DCOnly --stealth --opsec` | + SMB 445 to DC (GPO XML from SYSVOL) |
| 3 | `-c Default --opsec` | + SMB/registry/LSA to every computer |
| 4 | `-c All --opsec` | + RDP/DCOM/PSRemote SAMR, ADCS CA registry, host checks |

**`--opsec`** hex-escapes LDAP filter assertion **values** (attribute names unchanged — ADWS needs
readable names; pure-numeric values left as-is since AD won't match escaped digits; `*` preserved).
It defeats SIEM signatures matching raw filter substrings; it does not hide that an ADWS
enumeration is happening.

**`--throttle MS` / `--jitter PCT`** space out ADWS pull batches with random jitter.

---

## ACL collection (the SD_FLAGS control)

AD/ADWS omits `nTSecurityDescriptor` from results unless the **LDAP_SERVER_SD_FLAGS** control
(OID `1.2.840.113556.1.4.801`, value `0x7` = Owner|Group|DACL, no SACL) is sent. ADWSHound carries
it on the **Pull** message (matching SoaPy). ACE rights are mapped to BloodHound CE edge names:

`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights`,
`ForceChangePassword`, `GetChanges` / `GetChangesAll` / `GetChangesInFilteredSet` (→ **DCSync**),
`AddMember`, `AddAllowedToAct`, `AddKeyCredentialLink`, `WriteSPN`, `WriteGPLink`,
`WriteAccountRestrictions`, `ReadLAPSPassword`, `ReadGMSAPassword`, `Enroll`, `AutoEnroll`,
`ManageCA`, `ManageCertificates`.

Parser correctness: full-mask `GenericAll`, INHERIT_ONLY ACEs skipped, unrecognised specific
extended rights are **not** turned into `AllExtendedRights`, owner emitted as `Owns`.

> Tier Zero / high-value is **not** emitted per object — BloodHound CE computes it post-ingest
> from membership + ACL edges (same as SharpHound 2.x).

---

## Forest / multi-domain

- `--searchforest` — all domains in the **same forest** via `crossRef` (one-level).
- `--recursedomains` — reads `trustedDomain` objects and **walks trusts recursively**, collecting
  each reachable trusted domain (covers external/forest trusts). Works without `Trusts` in `-c`.

Both dedupe via a visited-set (lowercased FQDNs) to avoid loops on bidirectional trusts. Each
domain needs valid creds there and a reachable DC (9389); unreachable domains are logged & skipped.

---

## Output

One JSON file per object type (`*_users.json`, `*_groups.json`, …, ADCS types), `meta.version = 6`,
zipped by default (`--nozip` to skip, `--zippassword` for AES). All files are written **after**
containment/GPO wiring so `ContainedBy`, `ChildObjects`, `Links` and `GPOChanges` are populated.

---

## Architecture

```
adwshound.py                  CLI + collection pipeline (write-after-wiring, forest BFS)
adwshound/
  transport/client.py         ADWS client: reuse, RootDSE discovery, OPSEC, fault-retry
  vendor/                     Vendored SoaPy ADWS stack (NMF/NNS/encoder/SOAP) + SD-control Pull
  collectors/                 users, computers, groups, domains, ous, containers, gpos, trusts,
                              acls, spns, sessions, local_groups, logged_on, user_rights, adcs,
                              computer_extras, registry_utils, base
  resolvers/cache.py          SID/GUID/DN → TypedPrincipal cache (incl. FSPs)
  schema/types.py             BloodHound v6 dataclasses + CollectionMethod bitmask
  output/                     writer (v6 JSON) + zipper (AES)
  opsec.py                    LDAP filter value obfuscation
```

---

## Credits / SoaPy

The ADWS protocol implementation (MS-NMF, MS-NNS, NBFS/NBFSE encoder, SOAP templates) is vendored
and adapted from **[SoaPy](https://github.com/logangoins/SoaPy)** by Logan Goins / IBM X-Force.
SoaPy is the reference for stealthy ADWS interaction from Linux; ADWSHound reuses its transport and
adds the BloodHound collection layer (ACLs via the SD_FLAGS Pull control, RootDSE discovery,
connection reuse, full SharpHound-equivalent object/edge collection). All credit for the ADWS
transport groundwork to the SoaPy authors.

References: [SoaPy](https://github.com/logangoins/SoaPy) ·
[SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ·
[SharpHound](https://github.com/SpecterOps/SharpHound) ·
Kerberos: [impacket getTGT.py](https://github.com/fortra/impacket/blob/master/examples/getTGT.py) ·
[MS-NNS Kerberos (GSS) auth](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Remote collectors fail on every host with `Name or service not known` | The box can't resolve AD hostnames. ADWSHound resolves via the DC by default; pass `--nameserver <DC-IP>` if `--dc` is an FQDN, or point `/etc/resolv.conf` at the AD DNS. |
| `[Errno 24] Too many open files` mid-run | File-descriptor pressure with many threads/hosts. Raise the limit: `ulimit -n 65535`. |
| Lots of `timed out` / `No route to host` / `STATUS_NO_LOGON_SERVERS` at `-vv` | Normal: stale/offline computer objects. They're logged at DEBUG and skipped; collection still completes. Drop `-vv` to hide them. |
| `RegistrySessions` almost always empty | Expected: needs the **RemoteRegistry** service running (disabled by default on modern Windows). Sessions/PrivilegedSessions cover logon. `--skipregistryloggedon` to skip it. |
| Searching a user by `sAMAccountName` in BloodHound finds nothing | BloodHound's search bar matches the node **`name`** (and objectid), not `samaccountname`. Nodes are named `SAMACCOUNTNAME@DOMAIN`, so the SAM still matches; ensure you ingested a current run into a clean DB. |
| `cannot unmarshal … into Go struct field` on ingest | Output/schema mismatch for a computer telemetry field — file an issue with the field name. |

---

## Status / validation

Fixes are verified at the unit/serialisation level (encoder round-trips, `parse_acl` against
synthetic SDs). **End-to-end parity with SharpHound is not yet machine-verified** — that needs
running SharpHound and ADWSHound against the same lab DC with the same account and diffing the
output. Treat unusual single findings (e.g. broad `AllExtendedRights` from `Everyone`) as suspect
until confirmed against ground truth.
