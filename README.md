# 🛡️ Project Heimdall — Persistent Threat Hunter

> A forensic analysis platform for detecting UEFI rootkits, anti-forensics techniques,
> and reconstructing attacker timelines from firmware and Windows event artifacts.

```
██████╗ ████████╗██╗  ██╗
██╔══██╗╚══██╔══╝██║  ██║
██████╔╝   ██║   ███████║
██╔═══╝    ██║   ██╔══██║
██║        ██║   ██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═╝
Persistent Threat Hunter v0.1
```

---

## What Is This?

Most security tools stop at detection — they tell you *something is wrong* but not *what happened, when, or how*. Project Heimdall goes further.

It's a full forensic pipeline that:
- Pulls apart raw UEFI firmware and finds rootkits hiding inside boot drivers
- Detects when an attacker has tampered with timestamps or wiped event logs to cover their tracks
- Correlates all findings into a reconstructed attack timeline
- Produces a confidence-scored forensic report you could actually hand to someone

The idea came from a simple question: *what does a skilled attacker do after they're already inside?* The answer is they go deep — UEFI persistence survives OS reinstalls, and anti-forensics makes sure you can't prove they were ever there. This tool is built to catch both.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERSISTENT THREAT HUNTER                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   FIRMWARE   │    │  ANTI-FOREN- │    │  CORRELATION │       │
│  │   MODULE     │    │  SICS MODULE │    │   ENGINE     │       │
│  │              │    │              │    │              │       │
│  │ • Acquisition│    │ • Timestomp  │    │ • Timeline   │       │
│  │ • UEFI Parse │    │   Detection  │    │   Builder    │       │
│  │ • DXE/SMM    │    │ • Log Gap    │    │ • Attack     │       │
│  │   Analysis   │    │   Analysis   │    │   Graph      │       │
│  │ • Rootkit    │    │ • Audit      │    │ • Confidence │       │
│  │   Detection  │    │   Policy     │    │   Scorer     │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             ▼                                   │
│                  ┌─────────────────────┐                        │
│                  │   REPORT GENERATOR  │                        │
│                  │  HTML + TXT + JSON  │                        │
│                  └─────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## How the Pipeline Works

When you run `python main.py analyze`, here is exactly what happens under the hood:

### Stage 1 — Firmware Acquisition
The `FirmwareDumper` loads a raw firmware binary from disk (or can dump it via flashrom on Linux). It immediately SHA256-hashes the file and stores the result. Every time that file is touched again during the analysis, the hash is re-verified. If anything changes between acquisition and analysis, you know about it. Chain of custody matters in forensics.

### Stage 2 — UEFI Structure Parsing
The `UEFIParser` walks the raw firmware blob byte by byte looking for the `_FVH` signature — the marker for a Firmware Volume. Once it finds one, it reads the volume header, extracts all FFS (Firmware File System) files inside it, and classifies them by type: PEI core, DXE drivers, SMM modules. SMM modules get flagged immediately because they run at the highest privilege level on the machine — ring -2, below the OS, below the hypervisor. That's where rootkits live.

### Stage 3 — Rootkit Detection
The `RootkitDetector` runs every extracted driver through four layers:
1. **Hash matching** — known-bad SHA256 values from real rootkit samples
2. **String + GUID matching** — known indicators for LoJax, CosmicStrand, BlackLotus, MosaicRegressor
3. **Heuristics** — unsigned SMM drivers, suspicious memory allocation patterns, tiny stub loaders
4. **YARA** — custom rules for structural patterns in rootkit DXE drivers (optional, skipped gracefully if yara-python isn't installed)

### Stage 4 — Anti-Forensics Detection
The `LogGapAnalyzer` takes Windows Event Log records (exported JSON or live PowerShell query) and looks for three things: Event ID 1102/104 (explicit log clear), suspicious time gaps where no events appear for 30+ minutes, and Event ID 4719 (audit policy changes — a classic attacker move to disable logging before doing something loud).

The `TimestompDetector` analyzes file timestamps looking for signs of backdating — modification times earlier than creation times, suspiciously round timestamps (exact midnight), or timestamps in the future.

### Stage 5 — Correlation
The `TimelineBuilder` takes all findings from both modules and sorts them chronologically. Each event gets tagged with an ATT&CK phase: initial access, persistence, defense evasion, or impact. The `ConfidenceScorer` assigns weighted scores to each finding type (a known rootkit hash is worth more than a suspicious time gap), applies severity multipliers, and adds a bonus if findings span multiple ATT&CK phases — because multi-phase evidence is much stronger than a single anomaly. The `AttackGraphBuilder` connects the phases into a visual chain showing how the attack progressed.

### Stage 6 — Report
Three files get written to `./output/`:
- `*.html` — Full styled dark-theme forensic report with attack chain visualization
- `*.txt` — Plain text version for logging or printing
- `*.json` — Machine-readable version for piping into other tools

---

## Project Structure

```
persistent-threat-hunter/
├── firmware_module/
│   ├── acquisition.py          # Firmware loading, flashrom, QEMU extraction
│   ├── uefi_parser.py          # FV → FFS → DXE/SMM parsing
│   ├── rootkit_detector.py     # Hash, string, heuristic, YARA detection
│   ├── fake_firmware.py        # Synthetic firmware generator for testing
│   └── rules/
│       ├── uefi_rootkits.yar   # YARA rules for LoJax, BlackLotus etc.
│       └── smm_suspicious.yar  # YARA rules for suspicious SMM patterns
├── anti_forensics_module/
│   ├── timestomp_detector.py   # File timestamp anomaly detection
│   └── log_gap_analyzer.py     # Event log gap and clear detection
├── correlation_engine/
│   ├── timeline_builder.py     # Chronological event sorting + ATT&CK tagging
│   ├── confidence_scorer.py    # Weighted scoring + multi-phase bonus
│   └── attack_graph.py         # Node/edge graph + ASCII chain renderer
├── reporting/
│   ├── report_generator.py     # HTML, text, JSON report generation
│   └── templates/
│       └── forensic_report.html
├── tests/
│   ├── test_acquisition.py
│   ├── test_uefi_parser.py
│   ├── test_rootkit_detector.py
│   ├── test_anti_forensics.py
│   ├── test_correlation.py
│   └── test_report_generator.py
├── sample_data/
│   └── sample_events.json      # Sample Windows event log for testing
├── output/                     # Generated reports land here
├── main.py                     # CLI entry point
├── conftest.py                 # Pytest path configuration
├── requirements.txt
└── setup.py
```

---

## Setup Guide

### Requirements
- Python 3.11 or higher
- Windows 10/11 or Linux (most modules work cross-platform)
- Root/sudo only needed for live flashrom acquisition on Linux

### Installation

```bash
# Clone the repository
git clone https://github.com/dev-rehaann/persistent-threat-hunter
cd persistent-threat-hunter

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Running Tests

```bash
venv\Scripts\python.exe -m pytest tests/ -v
```

All 112+ tests should pass. No hardware or special setup required — the test suite uses synthetic firmware data generated internally.

### Running the Tool

**Full analysis with event log:**
```bash
python main.py analyze --evtx sample_data/sample_events.json --case-id PTH-2026-001
```

**Firmware-only analysis:**
```bash
python main.py firmware path/to/dump.bin
```

**Anti-forensics only:**
```bash
python main.py antiforensics --evtx path/to/events.json
```

**Live Windows event log (requires Windows + PowerShell):**
```bash
python main.py antiforensics --live
```

**Regenerate report from existing case:**
```bash
python main.py report --case-id PTH-2026-001
```

Reports are saved to `./output/` as HTML, TXT, and JSON.

---

## Tech Stack and Why We Chose Each Tool

| Component | Technology | Why |
|-----------|------------|-----|
| Core language | Python 3.11+ | Best ecosystem for forensics tooling, struct parsing, and rapid prototyping |
| CLI framework | Click | Clean command grouping, automatic --help generation, better than argparse |
| Terminal output | Rich | Makes forensic output actually readable — colored severity levels matter |
| Template engine | Jinja2 | Industry standard, logic-in-templates makes HTML reports clean to maintain |
| YARA | yara-python | The standard for malware signature matching, optional so tool runs without it |
| Testing | pytest | Fixtures and parametrize make testing binary parsers straightforward |
| Firmware parsing | Custom (no deps) | uefi-firmware-parser has build issues on Windows; writing our own taught us the spec |

---

## What I Learned Building This

Honestly this project forced me to learn things I never would have touched in a normal course.

**UEFI internals are wild.** The firmware isn't just one blob — it's a nested filesystem inside a filesystem. Firmware Volumes contain FFS files which contain sections which contain PE32+ binaries. Getting the byte offsets right took a lot of re-reading the UEFI specification and a lot of failed parses.

**The `_FVH` signature is at byte 40, not byte 0.** This single fact caused hours of debugging. The Firmware Volume header starts 40 bytes before the signature, so when you find `_FVH` at position X, you need to rewind to X-40 to read the header correctly. Every size and offset calculation is wrong until you get this right.

**Anti-forensics detection is inherently probabilistic.** You can't know for certain that a 90-minute log gap means an attacker deleted logs — it could be a server reboot. That's why confidence scoring exists. You're building a case, not a proof.

**Testing binary parsers is hard without real samples.** Building the fake firmware generator (`fake_firmware.py`) was almost as complex as building the parser itself. But it meant every test was deterministic and reproducible without needing real hardware.

**Scope creep is real.** The original plan had memory analysis with Volatility3 and full MFT parsing with pytsk3. Both got cut because getting them to build on Windows is a project in itself. Knowing what to cut and when is a real skill.

---

## Problems We Hit (And How We Fixed Them)

| Problem | What Happened | Fix |
|---------|--------------|-----|
| `_FVH` offset bug | Parser found 0 firmware volumes on all test firmware | Rewound 40 bytes from signature position to get real header start |
| `console` naming conflict | `console.print()` threw `AttributeError: 'str' has no attribute 'soft_wrap'` | Renamed module-level console to `_con` across all modules |
| pytest collecting 0 items | Tests existed but nothing ran | Deleted `tests/__init__.py` and added `conftest.py` to root with sys.path fix |
| pip installing to user instead of venv | `pip install` went global despite venv being active | Used `venv\Scripts\python.exe -m pip install` explicitly |
| yara-python build failure on Windows | YARA requires MSVC build tools | Made YARA optional — tool detects if it's installed and skips gracefully |
| `datetime.UTC` attribute error | Python 3.11 compatibility issue | Replaced with `timezone.utc` from `datetime` module |
| Copy-paste method truncation | Long files got cut off mid-method during paste | Verified file completeness with `type filename.py` before running |

---

## Known Limitations

- **MFT parsing** (comparing `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps) requires either a raw disk image or a tool like Autopsy to extract MFT records first. Direct NTFS parsing on Windows requires kernel-level access.
- **flashrom acquisition** only works on Linux with the right chipset support. On Windows you need a CH341A hardware programmer.
- **YARA scanning** requires `yara-python` which has a complicated build process on Windows. The tool works without it but with reduced detection coverage.
- **Live memory analysis** (Volatility3) was scoped out — would require a full memory dump as input.

---

## Security & Legal

This tool is for authorized forensic analysis only. Running it against
systems you do not own or have explicit written permission to analyze is
illegal in most jurisdictions.

Full details covering the vulnerability reporting policy, authorized use,
prohibited use, security design decisions, and copyright are in
[SECURITY.md](SECURITY.md).

---

## References and Learning Resources


**UEFI Internals:**
- UEFI Specification v2.9 — uefi.org (free PDF, the actual spec)
- *Beyond the BIOS* — Intel Press
- Chipsec framework documentation — github.com/chipsec/chipsec

**Real-World Rootkits Studied:**
- LoJax — ESET Research (2018)
- CosmicStrand — Kaspersky SecureList (2022)
- BlackLotus — ESET Research (2023)
- MosaicRegressor — Kaspersky SecureList (2020)

**Forensics:**
- *File System Forensic Analysis* — Brian Carrier
- SANS FOR500 Windows Forensic Analysis course materials
- MITRE ATT&CK for Enterprise — attack.mitre.org

---

## Author

**Rehan Khan**

Built as a 6th semester Machine Learning course project and Cybersecurity Portfolio piece.

> *"Most people learn security by reading about attacks. I learned it by building the tool that finds them."*

---

## License

© 2026 Rehan Khan. All rights reserved.

Unauthorized copying, distribution, or modification of this project without explicit written permission is prohibited.

This project is shared publicly for portfolio and educational demonstration purposes only. It may not be reproduced, forked, redistributed, or used as the basis for derivative works without written consent from the author.

---

*Project Heimdall — Named after the Norse god who guards the bridge between worlds. He sees everything. So does this tool.*
