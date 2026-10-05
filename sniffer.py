"""Ethics-first packet inspection for authorized PCAPs and loopback traffic."""

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet
except ImportError:  # Allow redaction helpers to be imported before dependencies are installed.
    DNS = DNSQR = IP = TCP = UDP = IPv6 = Packet = None


_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_SENSITIVE_QUERY_RE = re.compile(
    r"([?&](?:password|passwd|pwd|token|access_token|refresh_token|secret|"
    r"api[_-]?key|session(?:id)?|auth)=)[^&#\s]*",
    re.I,
)
_AUTH_HEADER_RE = re.compile(r"(?im)^(\s*authorization\s*:\s*).*$")
_COOKIE_HEADER_RE = re.compile(r"(?im)^(\s*(?:cookie|set-cookie)\s*:\s*).*$")


def redact_text(value: str) -> str:
    """Remove common credentials and personal identifiers from text fields."""
    value = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", value)
    value = _COOKIE_HEADER_RE.sub(r"\1[REDACTED]", value)
    value = _SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", value)
    return _EMAIL_RE.sub("[REDACTED_EMAIL]", value)


def mask_ip(value: str) -> str:
    """Mask host bits while retaining enough address context for a lab trace."""
    address = ipaddress.ip_address(value)
    if address.version == 4:
        octets = value.split(".")
        return ".".join((*octets[:3], "xxx"))
    network = ipaddress.ip_network(f"{address}/{48}", strict=False)
    return str(network.network_address) + "/48"


def _http_request(payload: bytes) -> dict[str, str] | None:
    text = payload.decode("latin-1", errors="replace")
    lines = text.splitlines()
    if not lines:
        return None
    match = re.match(r"^([A-Z]{1,16})\s+(\S+)\s+HTTP/\d(?:\.\d)?$", lines[0])
    if not match:
        return None
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "host":
            headers["host"] = value.strip()
            break
    request = {
        "method": match.group(1),
        "host": headers.get("host", ""),
        "path": match.group(2),
    }
    return {key: redact_text(value) for key, value in request.items()}


def decode_packet(packet: Any) -> dict[str, Any]:
    """Decode a packet into a minimal, redacted record suitable for JSONL."""
    if Packet is None:
        raise RuntimeError("Scapy is required. Install dependencies with pip install -r requirements.txt.")

    record: dict[str, Any] = {"timestamp": float(packet.time)}
    if IP is not None and packet.haslayer(IP):
        record["src"] = mask_ip(packet[IP].src)
        record["dst"] = mask_ip(packet[IP].dst)
    elif IPv6 is not None and packet.haslayer(IPv6):
        record["src"] = mask_ip(packet[IPv6].src)
        record["dst"] = mask_ip(packet[IPv6].dst)

    if TCP is not None and packet.haslayer(TCP):
        record["protocol"] = "TCP"
        record["src_port"] = int(packet[TCP].sport)
        record["dst_port"] = int(packet[TCP].dport)
        http = _http_request(bytes(packet[TCP].payload))
        if http:
            record["http"] = http
    elif UDP is not None and packet.haslayer(UDP):
        record["protocol"] = "UDP"
        record["src_port"] = int(packet[UDP].sport)
        record["dst_port"] = int(packet[UDP].dport)
    else:
        record["protocol"] = "IP" if "src" in record else "OTHER"

    if DNS is not None and packet.haslayer(DNS):
        dns = packet[DNS]
        question = dns.getlayer(DNSQR)
        query = question.qname if question and dns.qdcount != 0 else None
        if query:
            if isinstance(query, bytes):
                query = query.decode("ascii", errors="replace")
            record["dns_query"] = redact_text(str(query).rstrip("."))

    return record


def _write_record(packet: Any, output: Any) -> None:
    output.write(json.dumps(decode_packet(packet), sort_keys=True) + "\n")
    output.flush()


def _positive_count(value: str) -> int:
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("count must be at least 1")
    return count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("pcap", "live"), default="pcap")
    parser.add_argument("--pcap", type=Path, help="authorized .pcap or .pcapng input")
    parser.add_argument("--interface", default="lo", help="live mode supports only lo")
    parser.add_argument("--count", type=_positive_count, default=25)
    parser.add_argument("--filter", default="", help='BPF filter, e.g. "udp port 53"')
    parser.add_argument("--output", type=Path, help="JSONL output path; defaults to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == "pcap":
        if args.pcap is None:
            parser.error("PCAP mode is the default; provide --pcap with an authorized capture")
        if args.pcap.suffix.lower() not in {".pcap", ".pcapng"} or not args.pcap.is_file():
            parser.error("--pcap must be an existing .pcap or .pcapng file")
    elif args.interface != "lo":
        parser.error("live capture is restricted to the loopback interface 'lo'")
    elif args.pcap is not None:
        parser.error("--pcap can only be used with --mode pcap")

    try:
        from scapy.sendrecv import sniff
    except ImportError:
        print("Scapy is required. Install dependencies with pip install -r requirements.txt.", file=sys.stderr)
        return 2

    output = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
    try:
        sniff(
            offline=str(args.pcap) if args.mode == "pcap" else None,
            iface=args.interface if args.mode == "live" else None,
            count=args.count,
            filter=args.filter or None,
            prn=lambda packet: _write_record(packet, output),
            store=False,
        )
    except (OSError, PermissionError, ValueError) as error:
        print(f"Capture failed: {error}. Use an authorized PCAP if live capture is unavailable.", file=sys.stderr)
        return 1
    finally:
        if args.output:
            output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())