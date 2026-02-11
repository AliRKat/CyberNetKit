# portscan (CyberNetKit)

A small TCP connect port scanner built for learning networking + security fundamentals.
Focus: clean CLI, sane defaults (rate limiting), and useful output (banner grabbing + JSON reports).

> Use only on systems you own or have explicit permission to test.

---

## What it does

- **TCP connect scan**: attempts a TCP connection to each port
- Classifies ports as:
  - **open**: connection succeeded
  - **closed**: actively refused (RST)
  - **filtered/timeout**: no response within timeout
- Optional **banner grabbing** (best-effort):
  - SSH: reads the server banner (`SSH-2.0-...`)
  - HTTP: sends `HEAD /` and reads response headers
- Outputs:
  - human-readable terminal output
  - optional **JSON** report

---

## Why “connect scan” (and limitations)

This scanner uses the OS TCP stack (a normal connect).  
It’s simple and reliable for learning, but it’s not stealthy and it’s slower than raw SYN scanning.

**Important:** “timeout” does *not* always mean “filtered by a firewall” — it can also be packet loss, rate limiting, or a slow host.

---

## Features (planned)

### v1
- Single host scan
- Port list parsing (`22,80,443,8000-8100`)
- Timeouts
- Basic output
