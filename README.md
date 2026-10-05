# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

A small educational packet inspector for authorized lab traffic. It reads a
provided PCAP by default; live capture is restricted to the local loopback
interface (`lo`). Every emitted record masks IP addresses and sanitizes text
before it is written as JSON Lines.

## Learning Goals

- Understand frames and the IP, TCP/UDP, DNS, and unencrypted HTTP layers.
- Practice secure development with Copilot while rejecting unsafe suggestions.
- Capture only authorized lab traffic and redact sensitive fields.
- Explain why sniffers are powerful and how defenders detect misuse.

## Scope and Ethics

Students may capture traffic only on their own machine, loopback, or an
instructor-provided lab VM/network. Never capture on public, shared, or other
people's networks, and never collect traffic without the network owner's
explicit permission. This tool only supports live capture on `lo`; use a PCAP
provided by your instructor for lab-network traffic. Do not use `sudo` or
otherwise bypass operating-system permissions to capture. If live capture is
not permitted, use PCAP mode.

The program never writes packet payloads or raw headers to output. It reports
partially masked IP addresses, DNS query names, and a limited view of
unencrypted HTTP request lines. It redacts email addresses and sensitive query
parameter values. Do not use real credentials or personal data in a lab.
Redaction reduces exposure but does not make unauthorized capture acceptable.

## Setup

Requires Python 3.10+ and Scapy. A system libpcap/Npcap installation may be
needed by Scapy for BPF filtering and live capture.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

PCAP mode is the default and needs no capture privileges. Only inspect a capture
you generated on your own machine or were explicitly given for the lab:

```bash
python sniffer.py --pcap lab.pcap --count 25
python sniffer.py --pcap lab.pcap --filter "udp port 53"
python sniffer.py --pcap lab.pcap --filter "tcp port 80" --output packets.jsonl
```

Live mode must be explicitly selected and only accepts `lo`:

```bash
python sniffer.py --mode live --interface lo --count 25 --filter "udp port 53"
```

If the OS denies live capture, switch to a permitted PCAP instead of elevating
privileges. Output is one redacted JSON record per packet, written to stdout or
the `--output` file. `--count` defaults to 25. Useful filters include
`"tcp port 80"` and `"udp port 53"`.

## Tests

```bash
python -m pytest
```

## AI Use Policy

Students must include this policy in their repository:

- Use Copilot for boilerplate, CLI parsing, JSON formatting, and unit-test
	scaffolds.
- Do not ask Copilot for capturing other people's traffic, bypassing OS
	permissions, stealth features, persistence, or hiding activity.
- Always add an interface/PCAP allowlist and include redaction.
- Default to PCAP mode if capture privileges are missing.
- Review and test generated code; document suggestions you rejected or
	modified.

## Graded Deliverables (100 points)

- Setup and reproducibility: 10
- Correct capture or PCAP parsing: 20
- Correct decoding: 20
- Redaction and ethical controls: 25
- Logging format and usability: 10
- Tests and code quality: 10
- Report quality and Copilot reflection: 5

Submit a GitHub repository containing this tool, setup instructions, tests,
and a 2–3 page report. Use [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md) as a
starting point. Include screenshots or log excerpts from authorized lab
traffic only; redact them before submission.

## Instructor Lab Idea

Provide a tiny local web service and have students generate their own DNS
queries and HTTP requests against it. They can inspect loopback traffic or use
an instructor-provided capture. Avoid real accounts, secrets, or personal
information in the exercise.