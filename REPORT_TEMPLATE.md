# Packet Sniffer Lab Report

**Student:**  
**Date:**  
**Python and Scapy versions:**  
**Capture source:** (own loopback / instructor-provided lab PCAP)  

Target length: 2–3 pages, excluding screenshots or references. Do not include
real credentials, personal data, or unredacted packet captures in this report.

## 1. Lab Setup and Authorization

Describe the lab VM or local service, the traffic you generated yourself, and
how you confirmed that the capture was within the approved scope. State the
capture mode, filter, and packet count. Do not include public or shared network
traffic.

## 2. What I Observed

Summarize the layers and protocols you identified (Ethernet or raw loopback,
IP, TCP/UDP, DNS, and unencrypted HTTP where applicable). Explain what one
redacted record shows. Add only screenshots or log excerpts that have been
checked for sensitive data.

**Redacted excerpt:**

```text
Paste a short, reviewed JSONL excerpt here.
```

## 3. Redaction Decisions

List the fields that were masked or omitted and why. Discuss the remaining
privacy risk in data such as DNS names, timestamps, ports, and partially masked
addresses. Explain why redaction is not permission to capture unauthorized
traffic.

## 4. Risk Memo: Power and Detection

In your own words, explain why packet sniffers are powerful: they can reveal
communication patterns and, when protocols are unencrypted, expose application
content or credentials. Explain how encryption limits content inspection but
does not hide all metadata.

Describe how defenders might detect or investigate misuse, such as reviewing
which hosts and processes have capture privileges, monitoring unexpected
promiscuous-interface changes, investigating unauthorized capture tools or
unusual traffic-monitoring processes, and correlating these signals with host
and network logs. Note that no single indicator proves misuse; legitimate
diagnostics and endpoint/network monitoring also use packet capture.

## 5. Copilot Reflection

Describe one Copilot suggestion you accepted and one you rejected or modified.
Explain what you checked with tests or manual review. Confirm that you did not
request or implement capture of other people's traffic, permission bypass,
stealth, persistence, or concealment.

## 6. Limitations

State what the tool does not decode or guarantee. In particular, it does not
reassemble TCP streams, inspect encrypted HTTPS content, or guarantee that
pattern-based redaction catches every secret. Explain how these limitations
affected your interpretation.