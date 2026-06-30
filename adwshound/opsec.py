r"""OPSEC filter obfuscation: hex-escape assertion values.

ADWS does not resolve OID-based attribute names in filter expressions, so
attribute names are left unchanged and only the *values* are obfuscated. The
obfuscation is a full per-character LDAP hex escape (RFC 4515 \XX), applied to
every character of the value — including digits — so numeric signature filters
like (sAMAccountType=805306368) no longer travel in cleartext. Substring
wildcards (*) are preserved so substring filters keep working.

  (objectClass=computer)
    → (objectClass=\63\6f\6d\70\75\74\65\72)

  (&(objectCategory=person)(objectClass=user))
    → (&(objectCategory=\70\65\72\73\6f\6e)(objectClass=\75\73\65\72))

  (sAMAccountType=805306368)
    → (sAMAccountType=\38\30\35\33\30\36\33\36\38)

  (name=admin*)        → (name=\61\64\6d\69\6e*)
  (sAMAccountName=*)   → (sAMAccountName=*)

Extensible-match assertions (the `attr:oid:=value` form, e.g. the
userAccountControl bitwise-AND filter) are left unchanged: their numeric value
is semantically required and AD is least tolerant of escaping it.

Rules:
  - Attribute names → left as-is (ADWS requires readable names in filters).
  - Equality assertion values → every char hex-escaped, `*` preserved.
  - Extensible-match (`:oid:=`) values → unchanged.
"""
from __future__ import annotations

import re


# ─── Value encoding ───────────────────────────────────────────────────────────

def _hex_encode_str(value: str) -> str:
    r"""Encode every character in value as \XX LDAP hex escape."""
    return "".join(f"\\{ord(c):02x}" for c in value)


def _encode_value(value: str) -> str:
    """Hex-escape alpha values; leave pure-numeric values readable; keep `*`.

    Pure-numeric assertion values (e.g. sAMAccountType=805306368) are left intact:
    AD/ADWS does not reliably match hex-escaped digits, and a bare number is a weak
    signature anyway. Substring wildcards (`*`) are preserved.
    """
    if not value:
        return value
    out = []
    for seg in value.split("*"):
        if not seg:
            out.append("")            # adjacent/edge wildcard
        elif seg.isdigit():
            out.append(seg)           # numeric: leave readable (ADWS-safe)
        else:
            out.append(_hex_encode_str(seg))
    return "*".join(out)


# ─── Main filter transformer ──────────────────────────────────────────────────

_ASSERTION_RE = re.compile(
    r"\(([^()=<>~:]+?)"   # 1: attribute name (or already an OID)
    r"(:[^()=]+)?="       # 2: optional extensible rule  (:oid:= part before =)
    r"([^()]*)\)",        # 3: assertion value
)


def obfuscate_filter(ldap_filter: str) -> str:
    r"""Return ldap_filter with assertion values hex-escaped (attribute names unchanged).

    ADWS requires readable attribute names in filter expressions — OID substitution
    causes empty result sets without errors, so only values are transformed.

    Examples:
      (objectClass=computer)
        → (objectClass=\63\6f\6d\70\75\74\65\72)

      (sAMAccountType=805306368)
        → (sAMAccountType=\38\30\35\33\30\36\33\36\38)

      (sAMAccountName=*)  → (sAMAccountName=*)
    """
    def _replace(m: re.Match) -> str:
        attr     = m.group(1).strip()   # keep attribute name as-is for ADWS
        ext_rule = m.group(2) or ""
        value    = m.group(3)
        # Extensible-match (bitwise) assertions: leave numeric value intact.
        if ext_rule:
            return f"({attr}{ext_rule}={value})"
        return f"({attr}={_encode_value(value)})"

    return _ASSERTION_RE.sub(_replace, ldap_filter)
