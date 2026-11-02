# NetSentinel: Automated Network Forensics and Evidence-Integrity Platform

**Information Security Lab — Mini Project**  
**Technology:** Python 3.11, Streamlit, PyShark/TShark, SQLite, SQLAlchemy, SHA-256, HMAC-SHA256, RSA-2048-PSS

## Overview

NetSentinel is a Python-based network forensics and evidence-integrity application. It analyzes uploaded packet captures (PCAP/PCAPNG), detects suspicious traffic patterns, groups related alerts into incidents, protects collected digital evidence using cryptographic integrity mechanisms, simulates tampering on disposable copies, verifies evidence against stored references, and generates digitally signed forensic PDF reports.

The platform analyzes **recorded traffic**; it does not block attacks or claim to identify an attacker's intent conclusively.

## Main Workflow

```text
PCAP upload
    -> Packet and flow extraction
    -> Rule-based threat detection
    -> Alert correlation and incident creation
    -> Evidence registration and cryptographic sealing
    -> Attacker simulation on copies
    -> Defender verification
    -> Cryptographic experiments and signed PDF report
```

## Main Features

1. **Network Investigation:** Parse packet captures using PyShark/TShark, organize packet/flow records in SQLite, and detect port scans, SSH brute-force patterns, and DNS look-alike queries.
2. **Evidence Vault:** Register PCAP, image, audio, and text evidence. Preserve original files and generate protected reference records.
3. **Tampering & Verification:** Apply controlled modifications to disposable evidence copies and compare them with the original reference.
4. **Cryptographic Key Vault:** Demonstrate disposable educational cryptographic keys separately from operational keys.
5. **Comparison & Reports:** Benchmark cryptographic operations, study avalanche and collision behavior, test RSA signature verification, and generate signed forensic reports.

## Detection Methods

| Detector | Technique | Purpose |
|---|---|---|
| Port scanning | Rule-based analysis of destination ports and scan-like TCP behavior | Identify possible network reconnaissance |
| SSH brute-force pattern | Repeated connection-attempt detection involving destination port 22 | Flag possible automated SSH login attempts |
| DNS typosquatting | String-similarity comparison with protected domains | Identify deceptive look-alike DNS names |

Related alerts from the same source address within a **300-second correlation window** can be grouped into an incident. One detector yields a *suspicious pattern* classification; corroboration by at least two independent detectors yields the project's *confirmed malicious activity* classification. This is a rule-based label, not proof of intent.

## Evidence Integrity and Digital Signatures

For every registered evidence file, NetSentinel creates a protected reference record. The application does not regenerate this original reference when a candidate file fails verification.

| Protection | Applied to | Purpose |
|---|---|---|
| SHA-256 | Evidence file bytes | Generate a 256-bit content fingerprint |
| HMAC-SHA256 | Evidence file bytes | Authenticate file content using a secret key |
| Canonical JSON manifest | Evidence ID, incident ID, filename, type, size, SHA-256 digest, and timestamp | Bind content to identifying metadata |
| HMAC-SHA256 | Canonical manifest | Authenticate the reference metadata |
| RSA-2048-PSS | Canonical manifest | Digitally sign the evidence reference for public-key verification |
| RSA-2048-PSS | Generated PDF report | Produce a detached report signature (`.sig`) |

During verification, the system recalculates the candidate file's hash and HMAC, reconstructs the candidate manifest, and checks the RSA signature against the stored reference. An unchanged candidate can be verified; a modified candidate fails one or more checks. The system also distinguishes a compromised reference from ordinary candidate tampering.

**Important:** Hashing, HMAC, and digital signatures provide integrity/authentication properties; they do not encrypt evidence or make the underlying SQLite database physically immutable.

## Attacker Simulation

The simulator modifies **disposable copies**, leaving registered originals untouched.

| Evidence type | Available modifications |
|---|---|
| Image | Change one pixel; add text overlay; crop |
| Audio | Modify one sample; add noise; trim |
| Text | Change a character; replace a URL; modify an IP address |
| PCAP | Flip one bit; modify a packet field; truncate capture |

The defender compares modified copies with the trusted reference and reports the verification result.

## Technology Stack

- **Python 3.11:** Application and backend logic
- **Streamlit:** Interactive dashboard
- **PyShark and TShark:** Packet capture parsing
- **SQLite and SQLAlchemy:** Relational data storage and queries
- **`hashlib` and cryptography libraries:** SHA-256, HMAC, RSA-PSS, and key operations
- **ReportLab:** Forensic PDF generation
- **pytest:** Automated testing

Other libraries used by the application are listed in `requirements.txt`.

## Installation and Setup (macOS)

### Prerequisites

- Python 3.11
- TShark (Wireshark command-line packet analyzer)
- `pip` and a working terminal

Install TShark using an appropriate Wireshark distribution or Homebrew installation, then confirm it is available:

```bash
tshark --version
which tshark
```

From the project directory containing `app.py` and `requirements.txt`:

```bash
# Create and activate a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install application dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Start NetSentinel
python -m streamlit run app.py
```

Open the local URL printed by Streamlit (normally `http://localhost:8501`). If PyShark cannot locate TShark, ensure the directory reported by `which tshark` is on your shell's `PATH` before starting Streamlit.

### Optional Tests

If the included development requirements and tests are available:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
```

Test results depend on the local environment and installed dependencies; the commands above are not a claim that every test has passed on every platform.

## Application Pages and Demonstration

1. **Network Investigation:** Load `demo_data/attack_demo.pcap` using the bundled demo option, then inspect packets, alerts, and correlated incidents.
2. **Evidence Vault:** Register the bundled simulated image, text, or audio evidence and inspect its protected reference information.
3. **Tampering & Verification:** Select registered evidence, apply a modification to a copy, verify the modified copy, and compare it with the unchanged original.
4. **Cryptographic Key Vault:** If needed, demonstrate the separate educational key generator. The local demonstration PIN is `1234`; it is **not** production-grade authentication.
5. **Comparison & Reports:** Review performance and security experiments, generate a forensic PDF, and verify its detached signature using the appropriate public key.

For the short demonstration script, see `VIVA_GUIDE.md` if included in the project ZIP.

## Bundled Demonstration Data

The synthetic capture `demo_data/attack_demo.pcap` contains **70 packets** over approximately **95 seconds** and is designed to trigger three alerts grouped into two incidents:

| Incident | Source IP | Detection | Project classification |
|---|---|---|---|
| INC001 | `10.0.0.20` | DNS look-alike query for `paypa1.com` | Suspicious pattern |
| INC002 | `10.0.0.66` | Port-scan and SSH brute-force patterns | Confirmed malicious activity |

The bundled `SIMULATED_*` screenshot, message, and audio files are synthetic supporting evidence; they were **not extracted from the PCAP**. Where applicable, demo evidence can be regenerated with:

```bash
python demo_data/make_demo_evidence.py
```

## Cryptographic Experiments

The analysis module includes:

- **Execution-time benchmarks:** Median SHA-256, HMAC-SHA256, and RSA signing/verification timings across input sizes.
- **Throughput:** Data processed per second for bulk hashing/authentication.
- **CPU utilization:** Process CPU time relative to elapsed time, reported as approximately one-core-equivalent utilization.
- **Memory profiling:** Peak Python-tracked allocations; not total native-library or application memory.
- **Scalability:** How execution time changes as input size increases.
- **SHA-256 avalanche effect:** Number of output bits that change when one input bit changes.
- **Collision experiment:** Hashes of 100,000 distinct inputs, compared with a 24-bit truncated-hash control using 20,000 inputs.
- **RSA tamper-resistance checks:** Valid signature accepted; modified data, incorrect public key, modified signature, and edited manifest rejected.

Randomized experiment outcomes and timing measurements can vary between runs and machines. No observed collisions in a finite SHA-256 test does not constitute proof of collision resistance.

## Source Code Structure

```text
netsentinel/
|-- app.py                         # Streamlit entry point
|-- config.py                      # Paths and configuration
|-- services.py                    # Service initialization and wiring
|-- core/
|   |-- ingest_service.py          # Upload, parse, detect workflow
|   `-- incident_manager.py        # Incident management
|-- ingestion/
|   `-- parser.py                  # PCAP parsing and flows
|-- detection/
|   `-- engine.py                  # Rule-based detectors and correlation
|-- database/                      # SQLAlchemy models and database services
|-- evidence/
|   |-- integrity.py               # SHA-256, HMAC, signed manifests
|   |-- evidence_manager.py        # Evidence registration and storage
|   |-- tampering.py               # Controlled tampering methods
|   |-- verification.py            # Defender verification
|   |-- audit.py                   # Hash-chained audit trail
|   `-- pcap_tools.py              # Capture structural checks
|-- crypto/
|   |-- keys.py                    # Key management and RSA helpers
|   |-- benchmarks.py              # Cryptographic performance tests
|   |-- sha_security.py            # Avalanche and collision experiments
|   `-- rsa_security.py            # Signature security experiments
|-- reports/                        # PDF generation and detached signing
|-- ui/                             # Streamlit page implementations
|-- demo_data/                      # Synthetic capture and supporting files
|-- tests/                          # Automated tests
|-- requirements.txt
`-- README.md
```

## Data Storage and Security Notes

Mutable application data is stored under `data/` by default (configurable using `NETSENTINEL_DATA_DIR`). This includes the SQLite database, original captures, registered evidence, simulated copies, reports, and operational cryptographic keys.

**Do not upload or commit `data/keys/`, private `.pem` files, HMAC secrets, or other operational secrets to public repositories.** The educational Key Vault uses disposable demonstration keys separate from operational evidence/report keys.

### Known Limitations

- Detection uses fixed thresholds and a synthetic demonstration capture; it is not validated as a production intrusion-detection system.
- The operational RSA private key is stored unencrypted for laboratory simplicity. Production deployment would require stronger key management, such as an HSM or KMS.
- HMAC-based protection depends on the HMAC secret remaining confidential.
- The hash-chained audit trail is not independently signed; a sufficiently privileged attacker might rewrite the entire chain.
- PDF signatures are **detached** (`.pdf` plus `.sig`), not embedded PAdES signatures.
- Evidence integrity protection does not itself provide confidentiality or prevent every form of unauthorized access.

## Conclusion

NetSentinel demonstrates an end-to-end educational workflow combining recorded network traffic analysis, rule-based threat detection, incident correlation, cryptographically protected digital evidence, controlled tampering, defender verification, security benchmarking, and signed forensic reporting.

The central goal is to help investigators identify suspicious activity and determine whether associated evidence still matches its original trusted reference.
