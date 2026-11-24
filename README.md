# BOAR - Buffer Overflow Analysis & Remediation Framework

🛡️ **Rule-based Memory-Safety Analysis Tool**

BOAR analyzes C/C++ source for potential buffer overflows, heap misuse, and
related memory-safety bugs. It combines a rule-driven static scanner with
optional GDB-based crash analysis and a PoC skeleton generator.

## 🚀 Features

### 🔍 Static Analysis
- **Rule-based Pattern Detection**: Matchers for dangerous memory operations, driven by JSON rules
- **14 Built-in Memory-Safety Rules**: gets, strcpy/strcat, sprintf, scanf width vs capacity, memcpy/memset, format strings, alloca, allocation arithmetic, double free, use-after-free, strncpy/strncat misuse, fgets/read/recv length, sizeof-on-pointer, and stack-address return
- **Scoped Buffer & Constant Resolution**: Tracks buffer capacities per function/block scope and resolves `#define`, `enum`, and `const` integer expressions
- **Comment/String-Aware Matching**: Ignores commented-out code and string contents instead of firing on raw regex hits
- **Severity + Confidence**: CRITICAL, HIGH, MEDIUM, LOW severity with per-finding confidence
- **CWE References**: Each finding includes CWE identifiers and example CVE references
- **CI-friendly Output**: Text, JSON, JSONL, and **SARIF 2.1.0** (GitHub Code Scanning) output with `--fail-on` exit codes

### 🎯 Dynamic Analysis
- **Crash Classification**: Distinguishes segfault, stack smashing, double free, and heap corruption
- **Multi-architecture Support**: 32-bit and 64-bit x86 architectures
- **Binary Protection Detection**: Canary, NX/DEP, PIE, and RELRO (full/partial); ASLR is system-wide and reported separately
- **De Bruijn Offsets**: Unique 4-byte windows for accurate instruction-pointer offset lookup
- **Multiple Input Methods**: stdin and argv

### 🛠️ PoC Scaffolding
- **Offset-Based PoC Skeleton**: Generates a script with the discovered offset and architecture
- **Protection Context**: Includes canary/NX/PIE/RELRO notes next to the payload
- **No Fake Automation**: ROP gadgets and shellcode placement are left explicit for the tester
- **Manual Exploit Development**: Use ropper, ROPgadget, pwntools, and gdb-peda after the skeleton

### 📊 Comprehensive Reporting
- **Structured Reports**: Text, JSON, and JSONL output
- **Severity + Confidence**: Findings include CWE, references, confidence, and remediation
- **CI Integration**: `--fail-on` returns a non-zero exit code when a threshold is reached

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/AtokTajuddin/BOAR.git
cd BOAR

# Install BOAR as a CLI command (`boar`) in editable mode (stdlib only, no external deps)
pip install -e .

# Optional: Install additional tools
pip install pwntools ropper ROPgadget

# Make the tool executable
chmod +x BOAR_beta.py
```

### Requirements
- Python 3.7+
- GDB and readelf (for dynamic analysis and protection checks)
- A C/C++ compiler for building test targets
- Optional: pwntools, ropper, ROPgadget

## Usage

### Basic Usage

```bash
# Static analysis on a single file
python BOAR_beta.py static vulnerable_program.c

# Static analysis on a directory
python BOAR_beta.py static /path/to/project

# Dynamic analysis
python BOAR_beta.py dynamic ./vulnerable_binary -l 1000

# Generate a PoC skeleton
python BOAR_beta.py poc ./vulnerable_binary -o 268 --advanced
```

### Advanced Usage

```bash
# JSON report + CI exit code
python BOAR_beta.py --no-banner static /path/to/project --format json --report report.json --fail-on high

# SARIF 2.1.0 report for GitHub Code Scanning / VS Code SARIF Viewer
python BOAR_beta.py --no-banner static /path/to/project --format sarif --report boar.sarif --fail-on high

# Only check binary protections (does not execute the target)
python BOAR_beta.py dynamic ./binary --check-protections

# Add custom JSON rules
python BOAR_beta.py static /path/to/code --rules rules/extra.json

# Filter findings by exact severity
python BOAR_beta.py static /path/to/code --severity critical

# One JSON object per finding
python BOAR_beta.py static /path/to/code --format jsonl
```

## 🎯 Rule-based Memory-Safety Detection

Rules are JSON templates in `boar_rules.json`. The default set covers fourteen
memory-safety classes:

| Rule | Severity | CWE | What it checks |
| --- | --- | --- | --- |
| BOAR-MEM-001 | critical | CWE-242, CWE-120 | `gets()` unbounded read |
| BOAR-MEM-002 | high | CWE-120, CWE-787 | `strcpy`/`strcat`/`stpcpy` capacity |
| BOAR-MEM-003 | high | CWE-120, CWE-787 | `sprintf`/`vsprintf` output size |
| BOAR-MEM-004 | high | CWE-120, CWE-787 | `scanf` `%s`/`%[` missing width or exceeding buffer capacity |
| BOAR-MEM-005 | medium | CWE-120, CWE-787 | `memcpy`/`memset` length vs buffer |
| BOAR-MEM-006 | high | CWE-134 | non-literal format strings |
| BOAR-MEM-007 | high | CWE-770, CWE-121 | variable-size `alloca()` |
| BOAR-MEM-008 | medium | CWE-190, CWE-122 | multiplication/addition in allocation size |
| BOAR-MEM-009 | high | CWE-415 | double free (including conditional fallthrough) |
| BOAR-MEM-010 | critical | CWE-416 | use-after-free (including conditional fallthrough) |
| BOAR-MEM-011 | high | CWE-120, CWE-170, CWE-193 | `strncpy`/`strncat` off-by-one, capacity overflow, or missing NUL |
| BOAR-MEM-012 | high | CWE-120, CWE-787, CWE-195 | `fgets`/`read`/`recv`/`fread` length exceeding capacity or signed wraparound |
| BOAR-MEM-013 | medium | CWE-467 | `sizeof(pointer)` instead of pointed-to object or array size |
| BOAR-MEM-014 | critical | CWE-562 | returning address of stack-allocated local variable or `alloca()` buffer |

References such as `CVE-2017-14107` are examples of the rule class, not a claim
that the scanner detects that exact CVE.

### Custom Rules

Add a JSON file with the same schema and pass `--rules`:

```json
{
  "rules": [
    {
      "id": "LOCAL-MEM-001",
      "name": "custom-strcpy",
      "severity": "high",
      "confidence": "high",
      "cwe": ["CWE-120"],
      "matcher": "unbounded_copy",
      "functions": ["strcpy"],
      "description": "Local policy: strcpy is not allowed",
      "remediation": "Use the project's checked copy helper"
    }
  ]
}
```

Custom rules merge with the built-in set; a rule with the same `id` overrides
the built-in rule.

Suppress a known false positive on the finding line or the line above:

```c
strcpy(buffer, trusted_constant); // boar:ignore
```

## 🔧 Example Output

### Static Analysis
```
================================================================================
 BOAR MEMORY-SAFETY REPORT
================================================================================
Target: test_vulnerable.c
Rules: 10 | Findings: 9

CRITICAL SEVERITY (1 items)
--------------------------------------------------------------------------------
[CRITICAL] BOAR-MEM-001 gets-unbounded-read (confidence: high)
  Location: test_vulnerable.c:12:5
  Code: gets(buffer);  // Dangerous! No bounds checking
  CWE: CWE-242, CWE-120
  References: CVE-2016-4051, CVE-2012-3489
  Why: gets() reads without a bound and overwrites the destination buffer.
  Fix: Replace gets() with fgets(buffer, sizeof(buffer), stdin) and handle the trailing newline.

HIGH SEVERITY (6 items)
--------------------------------------------------------------------------------
[HIGH] BOAR-MEM-002 unbounded-string-copy (confidence: high)
  Location: test_vulnerable.c:19:5
  Code: strcpy(buffer, input);  // Dangerous! No size checking
  CWE: CWE-120, CWE-787
  Why: Unbounded string copy/concatenation can write past the destination buffer when the source is attacker-controlled.
  Fix: Use strlcpy()/strlcat() where available, or strncpy()/strncat() with an explicit remaining capacity.
```

### Dynamic Analysis
```
[*] Memulai analisis dinamis pada: ./vulnerable_binary
[*] Memeriksa proteksi keamanan binary...
[*] Proteksi aktif: ['nx', 'pie', 'relro']

============================================================
HASIL ANALISIS CRASH
============================================================
Crash Type: segmentation_fault
Exploitability: high

Register States:
  EIP: 0x41414141
  ESP: 0xbffff6a0

[!!!] CRASH TERDETEKSI! (Segmentation Fault)
[+] Instruction Pointer (EIP) tertimpa dengan nilai: 0x41414141
[+] 🎯 Offset kerentanan berhasil ditemukan: 268
[+] Arsitektur: 32-bit (little-endian)

[+] REKOMENDASI EKSPLOITASI:
  1. Buat skrip PoC: python BOAR_beta.py poc ./vulnerable_binary --offset 268
  2. Gunakan offset 268 untuk mengontrol EIP
  3. ⚠️  NX/DEP aktif - gunakan ROP chains
  4. ⚠️  PIE aktif - perlu information leak untuk alamat base
```

## 🎓 Educational Examples

### Test Program
Use the included `test_vulnerable.c` to test BOAR's capabilities:

```bash
# Compile the test program
gcc -o test_vulnerable test_vulnerable.c -fno-stack-protector -no-pie -z execstack -Wno-implicit-function-declaration

# Test static analysis
python BOAR_beta.py static test_vulnerable.c

# Test dynamic analysis
python BOAR_beta.py dynamic ./test_vulnerable -l 500

# Test specific vulnerability
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./test_vulnerable 1
```

## 🛡️ Security Protections Detected

BOAR inspects ELF metadata and reports:

- **Stack Canaries**: `__stack_chk_fail` symbol presence
- **NX/DEP**: `GNU_STACK` executable flag
- **PIE**: `DYN` / position-independent executable type
- **RELRO**: `GNU_RELRO` plus `BIND_NOW` to distinguish partial from full
- **FORTIFY_SOURCE**: Fortified libc `_*_chk` symbol checks
- **ASLR (Host)**: Reads `/proc/sys/kernel/randomize_va_space` (`disabled`, `conservative`, `full`) on Linux

## 📋 Remediation Recommendations

For each finding, BOAR provides:
- **CWE identifiers** and example CVE references for context
- **Confidence** so heuristic hits can be triaged
- **Specific remediation steps** with safe alternatives
- **Exact file, line, and column** for review

## 🔗 CI Integration

Use the machine-readable output and a severity gate:

```bash
python BOAR_beta.py static . --format json --report boar-report.json --fail-on high
```

`--fail-on high` exits with status 1 when a high or critical finding exists.
JSONL output (`--format jsonl`) is suitable for ingestion by other tools.

## ⚠️ Limitations

- Static analysis is heuristic. It has no full dataflow, points-to, or
  interprocedural analysis, so it reports *potential* issues and can miss real
  bugs. Use ASan, UBSan, Valgrind, and fuzzing for confirmation.
- Buffer capacities are inferred from same-file array declarations only.
  Cross-file sizes, structs, and heap allocations are unknown to the matcher.
- Double-free and use-after-free checks are block-scoped approximations.
- Dynamic analysis requires `gdb`, an executable target, and permission to
  trace it. It does not prove exploitability.
- `BOAR_beta.py` is the maintained CLI; `BOAR.py` is the older minimal scanner.

### Web / GitHub Pages

A static web version is feasible only for the source-level rule engine: parse
source in the browser, load the same JSON rules, and render findings locally.
A GitHub Pages build cannot run `gdb`, inspect native binaries, find live
offsets, or generate executable PoCs, because Pages serves static files only.
Those parts require a native runtime or a server.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add JSON rules in `boar_rules.json` or a separate rule file
4. Add a regression test in `tests/`
5. Submit a pull request with detailed descriptions

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Do not use it on systems you do not own or have explicit permission to test. The authors are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- CVE database maintainers
- Security researchers who disclosed the vulnerabilities
- Open source security tools that inspired this project
- The security community for continuous improvement

---

**BOAR** - Making buffer overflow analysis accessible, comprehensive, and educational. 🛡️
