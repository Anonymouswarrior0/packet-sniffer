import re

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from sniffer import decode_packet, mask_ip, redact_text


def test_masks_ipv4_and_ipv6_addresses():
    assert mask_ip("192.168.1.42") == "192.168.1.xxx"
    assert mask_ip("2001:db8:abcd:12::1").endswith("/48")


def test_redacts_credentials_and_email():
    value = (
        "Authorization: Bearer abc123\r\nCookie: sid=secret\r\n"
        "contact dev@example.com /?password=hunter2&ok=yes"
    )
    redacted = redact_text(value)
    assert "abc123" not in redacted
    assert "sid=secret" not in redacted
    assert "dev@example.com" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "ok=yes" in redacted


def test_decodes_dns_query_and_masks_ips():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.test")
    )
    record = decode_packet(packet)
    assert record["protocol"] == "UDP"
    assert record["src"] == "192.168.1.xxx"
    assert record["dst"] == "8.8.8.xxx"
    assert record["dns_query"] == "example.test"


def test_decodes_http_request_without_emitting_sensitive_headers():
    payload = (
        b"GET /profile?token=super-secret HTTP/1.1\r\n"
        b"Host: lab.local\r\n"
        b"Authorization: Bearer private\r\n"
        b"Cookie: session=private\r\n\r\n"
    )
    packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=50000, dport=80) / Raw(payload)
    record = decode_packet(packet)
    rendered = str(record)
    assert record["http"]["method"] == "GET"
    assert record["http"]["host"] == "lab.local"
    assert "[REDACTED]" in record["http"]["path"]
    assert not re.search(r"super-secret|private|session=", rendered)