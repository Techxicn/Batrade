"""Parseo de XML de nmap y de mensajes netlink (entradas no confiables)."""
from __future__ import annotations

import socket
import struct

import pytest

from batrade.net.nmap_scan import parse_xml
from batrade.net.neigh import parse_netlink

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.99 scan initiated -->
<nmaprun scanner="nmap" args="nmap -sT" start="1760000000" version="7.99">
<host><status state="up"/>
<hostnames><hostname name="tv.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="2323"><state state="open" reason="syn-ack"/>
  <service name="telnet" method="table"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
  <service name="microsoft-ds" product="Samba" version="4.19"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/><service name="x"/></port>
</ports>
</host></nmaprun>"""


def test_parse_open_ports_and_hostnames(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)
    parsed = parse_xml(path)
    assert parsed["hostnames"] == ["tv.local"]
    assert [p["port"] for p in parsed["ports"]] == [2323, 445]
    assert parsed["ports"][1]["version"] == "Samba 4.19"
    assert all(p["state"] == "open" for p in parsed["ports"])


def test_entity_injection_is_blocked(tmp_path):
    from defusedxml.common import DTDForbidden

    malicious = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<foo>&xxe;</foo>"
    )
    path = tmp_path / "evil.xml"
    path.write_text(malicious)
    with pytest.raises(DTDForbidden):
        parse_xml(path)


@pytest.mark.parametrize("doctype", [
    '<!DOCTYPE nmaprun [<!ELEMENT nmaprun EMPTY>]>',
    '<!DOCTYPE nmaprun SYSTEM "http://example.invalid/nmap.dtd">',
])
def test_doctype_internal_subset_or_external_dtd_is_blocked(tmp_path, doctype):
    """M-04: sólo se acepta el DOCTYPE simple de nmap, nunca subconjuntos ni DTD externos."""
    from defusedxml.common import DTDForbidden

    path = tmp_path / "dtd.xml"
    path.write_text(f'<?xml version="1.0"?>{doctype}<nmaprun/>')
    with pytest.raises(DTDForbidden):
        parse_xml(path)


def _netlink_msg(ip: str, mac: str, *, ifindex: int = 2, state: int = 2,
                 family: int = socket.AF_INET) -> bytes:
    dst = socket.inet_aton(ip)
    lladdr = bytes.fromhex(mac.replace(":", ""))
    attrs = struct.pack("=HH", 8, 1) + dst
    attrs += struct.pack("=HH", 12, 2) + lladdr + b"\x00\x00"
    ndmsg = struct.pack("=BBHiHBB", family, 0, 0, ifindex, state, 0, 0)
    body = ndmsg + attrs
    nl_len = 16 + len(body)
    header = struct.pack("=IHHII", nl_len, 28, 0, 1, 0)
    return header + body


def test_parse_netlink_extracts_binding():
    data = _netlink_msg("10.10.10.1", "00:50:56:aa:bb:01")
    assert list(parse_netlink(data)) == [("10.10.10.1", "00:50:56:aa:bb:01")]


def test_parse_netlink_ignores_failed_state():
    data = _netlink_msg("10.10.10.1", "00:50:56:aa:bb:01", state=32)  # NUD_FAILED
    assert list(parse_netlink(data)) == []


def test_parse_netlink_ignores_ipv6_family():
    data = _netlink_msg("10.10.10.1", "00:50:56:aa:bb:01", family=socket.AF_INET6)
    assert list(parse_netlink(data)) == []


def test_parse_netlink_survives_truncated_input():
    assert list(parse_netlink(b"\x00\x01")) == []
    assert list(parse_netlink(_netlink_msg("10.10.10.1", "00:50:56:aa:bb:01")[:-4])) == []
