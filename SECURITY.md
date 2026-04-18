# Security & Legal

> Project Heimdall — Persistent Threat Hunter
> © 2026 Rehan Khan. All rights reserved.

---

## Part 1 — Authorized Use & Legal Boundaries

### Who This Tool Is For

This tool is built for:

- Authorized digital forensic investigators
- Security researchers working on systems they own or have written permission to analyze
- Students and academics studying firmware security and anti-forensics in controlled environments
- Cybersecurity professionals conducting incident response engagements

### What You Can Do

You may:

- Study and run this codebase for personal educational purposes
- Reference this project in academic work with proper attribution
- Fork this repository solely to submit issues or pull requests to the original
- Run this tool against systems you own or have explicit written authorization to analyze

### What You Cannot Do

Without explicit written permission from the author, you may **not**:

- Copy, reproduce, or redistribute this codebase in whole or in part
- Use this project as the basis for a derivative work or competing tool
- Include this code in any commercial product or service
- Repackage or republish this tool under a different name or branding
- Remove or alter copyright notices anywhere in the project
- Use the detection signatures or YARA rules in other tools without attribution

### Legal Warning

**Using this tool against systems without explicit written authorization from
the system owner is illegal** in most jurisdictions, including:

| Jurisdiction | Relevant Law |
|-------------|-------------|
| United States | Computer Fraud and Abuse Act (CFAA) |
| United Kingdom | Computer Misuse Act 1990 |
| Pakistan | Prevention of Electronic Crimes Act (PECA) |
| European Union | EU Directive on Attacks Against Information Systems |

The author accepts no liability for misuse. You are solely responsible for
ensuring your use complies with all applicable laws.

---

## Part 2 — Security Policy

### Supported Versions

Security fixes are applied to the latest version only.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active |
| < 0.1   | ❌ No     |

### Reporting a Vulnerability

If you find a security vulnerability in Project Heimdall — in the detection
logic, the CLI, the report generator, or anything else — please report it
responsibly. Do not open a public GitHub issue for security vulnerabilities.

**Contact:** rehan.khan@[yourdomain].com
**Subject line:** `[SECURITY] Project Heimdall — <brief description>`

Include in your report:
- A clear description of the vulnerability
- Steps to reproduce it
- Your assessment of the potential impact
- A suggested fix if you have one

You will receive an acknowledgment within 72 hours. Confirmed vulnerabilities
will be prioritized and you will be credited in the release notes unless you
request otherwise.

### What Is In Scope

- Arbitrary code execution via crafted firmware blobs or event log JSON
- Path traversal in any file input handling
- HTML or JavaScript injection in generated reports
- Logic flaws that cause systematic false negatives in detection
- Vulnerabilities in direct dependencies

### What Is Out of Scope

- Issues in optional dependencies not installed by default
- Attacks requiring physical access to the analysis machine
- Theoretical vulnerabilities with no practical exploit path
- Behavior on systems this tool is used *against* — analyzing compromised
  systems is the entire purpose

---

## Part 3 — Security Design Decisions

These decisions were made deliberately during development.

### Input Is Never Executed

Firmware blobs and event logs are parsed as raw data only. There are no
`eval()` calls, no subprocess execution on user-supplied input, and no
dynamic imports from analyzed files. A malicious firmware blob cannot
cause code execution through the parser.

### Integrity Verification on Acquisition

Every firmware file is SHA256-hashed at load time. If the file changes
between acquisition and analysis — even a single byte — the tool flags it.
This protects chain of custody in a real forensic investigation.

### YARA Rules Run on Memory Buffers

YARA scanning operates on in-memory byte buffers, not on raw disk paths.
A crafted firmware binary cannot escape the scan context or write to disk
through the YARA engine.

### Fully Offline

The tool makes zero network calls. No telemetry, no signature updates over
the wire, no external API calls during analysis. Everything that gets analyzed
stays on your machine.

### Reports Use Autoescaped Templates

The HTML report is generated through Jinja2 with autoescaping enabled.
Any strings extracted from analyzed artifacts are escaped before being
rendered into the report. A firmware blob containing HTML in its strings
cannot inject into the output document.

---

## Third-Party Dependencies

This project uses open-source libraries under their respective licenses.
Their use does not transfer any additional rights to users of this project.

| Package | License |
|---------|---------|
| Click | BSD-3-Clause |
| Rich | MIT |
| Jinja2 | BSD-3-Clause |
| yara-python | Apache 2.0 |
| pytest | MIT |

---

## Attribution

If you reference this project in academic work, research, or public presentations:

```
Rehan Khan. "Project Heimdall — Persistent Threat Hunter:
UEFI Rootkit & Anti-Forensics Detection Platform." 2026.
github.com/dev-rehaann/persistent-threat-hunter
```

---

## Contact

For licensing inquiries, permissions, or security reports:

**Rehan Khan**
dev.rehaann@gmail.com
