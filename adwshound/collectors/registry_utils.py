"""Shared Windows Remote Registry helpers.

Context manager + helpers for all collectors that need WinReg access.
"""
from __future__ import annotations

import struct
from contextlib import contextmanager
from typing import Optional


def _split_hashes(hashes: Optional[str]) -> tuple[str, str]:
    if hashes and ":" in hashes:
        p = hashes.split(":", 1)
        return p[0], p[1]
    return "", hashes or ""


@contextmanager
def open_registry(hostname: str, domain: str, username: str,
                  password: Optional[str], hashes: Optional[str],
                  do_kerberos: bool = False, aes_key: str = "",
                  kdc_host: Optional[str] = None):
    """Context manager: yields connected DCE/RPC bound to winreg pipe."""
    from impacket.dcerpc.v5 import transport, rrp
    from adwshound.collectors.base import set_dcerpc_creds
    binding = rf"ncacn_np:{hostname}[\pipe\winreg]"
    trans = transport.DCERPCTransportFactory(binding)
    set_dcerpc_creds(trans, username, password, domain, hashes,
                     aes_key, do_kerberos, kdc_host)
    trans.set_connect_timeout(5)
    dce = trans.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    try:
        yield dce
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass


def open_hklm(dce):
    """Open HKEY_LOCAL_MACHINE root handle."""
    from impacket.dcerpc.v5 import rrp
    return rrp.hOpenLocalMachine(dce)["phKey"]


def read_dword(dce, h_root, key_path: str, value_name: str,
               default=None) -> Optional[int]:
    """Read a REG_DWORD value. Returns default on any error."""
    from impacket.dcerpc.v5 import rrp
    try:
        ans = rrp.hBaseRegOpenKey(dce, h_root, key_path,
                                  samDesired=rrp.MAXIMUM_ALLOWED)
        h = ans["phkResult"]
        try:
            ans_v = rrp.hBaseRegQueryValue(dce, h, value_name)
            data = bytes(ans_v["lpData"])
            if len(data) >= 4:
                return struct.unpack("<I", data[:4])[0]
        finally:
            try:
                rrp.hBaseRegCloseKey(dce, h)
            except Exception:
                pass
    except Exception:
        pass
    return default


def read_binary(dce, h_root, key_path: str, value_name: str) -> Optional[bytes]:
    """Read a binary registry value. Returns None on any error."""
    from impacket.dcerpc.v5 import rrp
    try:
        ans = rrp.hBaseRegOpenKey(dce, h_root, key_path,
                                  samDesired=rrp.MAXIMUM_ALLOWED)
        h = ans["phkResult"]
        try:
            ans_v = rrp.hBaseRegQueryValue(dce, h, value_name)
            return bytes(ans_v["lpData"])
        finally:
            try:
                rrp.hBaseRegCloseKey(dce, h)
            except Exception:
                pass
    except Exception:
        pass
    return None


def enum_subkeys(dce, h_root, key_path: str) -> list[str]:
    """Enumerate subkey names under key_path."""
    from impacket.dcerpc.v5 import rrp
    try:
        ans = rrp.hBaseRegOpenKey(dce, h_root, key_path,
                                  samDesired=rrp.MAXIMUM_ALLOWED)
        h = ans["phkResult"]
        try:
            names = []
            i = 0
            while True:
                try:
                    ans_e = rrp.hBaseRegEnumKey(dce, h, i)
                    names.append(ans_e["lpNameOut"].rstrip("\x00"))
                    i += 1
                except Exception:
                    break
            return names
        finally:
            try:
                rrp.hBaseRegCloseKey(dce, h)
            except Exception:
                pass
    except Exception:
        return []
