# BOAR - Buffer Overflow Analysis & Remediation Framework

🛡️ **Advanced CVE-based Security Analysis Tool**

BOAR is a comprehensive security analysis framework designed to detect, analyze, and provide remediation advice for buffer overflow vulnerabilities in C/C++ applications. It combines static analysis with real-world CVE patterns, dynamic crash analysis, and advanced exploit generation capabilities.

## 🚀 Features

### 🔍 Static Analysis
- **CVE-based Pattern Detection**: Uses real-world CVE patterns to identify vulnerabilities
- **60+ Known Vulnerability Patterns**: Based on actual CVEs like CVE-2019-9169, CVE-2017-14107, etc.
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW severity levels
- **Comprehensive Reporting**: JSON and text output formats
- **AI-powered Heuristics**: Advanced pattern matching for complex vulnerabilities

### 🎯 Dynamic Analysis
- **Advanced Crash Detection**: Intelligent crash pattern analysis
- **Multi-architecture Support**: 32-bit and 64-bit x86 architectures
- **Binary Protection Detection**: Canary, NX/DEP, PIE, RELRO, ASLR detection
- **Exploitability Assessment**: Automated exploitability scoring
- **Multiple Input Methods**: stdin, argv, and environment variable injection

### 🛠️ Exploit Generation
- **Advanced PoC Templates**: Sophisticated exploit scripts with bypass techniques
- **ROP Chain Integration**: Automatic ROP gadget finding and chain building
- **Shellcode Integration**: Pre-built shellcode for common scenarios
- **Protection Bypass**: Techniques for bypassing modern security mechanisms
- **Interactive Exploitation**: pwntools integration for interactive exploitation

### 📊 Comprehensive Reporting
- **Detailed Security Reports**: JSON reports with CVE references
- **Visual Representation**: Color-coded severity levels
- **Remediation Advice**: Specific fix recommendations for each vulnerability
- **Exploit Examples**: Real-world exploit examples for each pattern

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/BOAR.git
cd BOAR

# Install required dependencies
pip install -r requirements.txt

# Optional: Install additional tools
pip install pwntools ropper ROPgadget

# Make the tool executable
chmod +x BOAR_beta.py
```

### Requirements
- Python 3.6+
- GDB (for dynamic analysis)
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

# Generate advanced PoC
python BOAR_beta.py poc ./vulnerable_binary -o 268 --advanced
```

### Advanced Usage

```bash
# Comprehensive security audit
python BOAR_beta.py audit /path/to/project --report --format json

# Check binary protections
python BOAR_beta.py dynamic ./binary --check-protections

# Create vulnerability database
python BOAR_beta.py database --create

# Filter by severity
python BOAR_beta.py static /path/to/code --severity critical
```

## 🎯 CVE-based Detection

BOAR uses patterns from real-world CVEs to identify vulnerabilities:

### Critical Vulnerabilities
- **CVE-2016-4051**: gets() buffer overflow
- **CVE-2017-14107**: strcpy() buffer overflow
- **CVE-2017-8890**: Use-after-free vulnerabilities

### High Severity Vulnerabilities
- **CVE-2019-9169**: glibc string function vulnerabilities
- **CVE-2017-9047**: sprintf() format string vulnerabilities
- **CVE-2018-16529**: strcat() buffer overflow

### Advanced Patterns
- **CVE-2016-3706**: alloca() stack exhaustion
- **CVE-2017-1000366**: Stack clash vulnerabilities
- **CVE-2000-0573**: Format string vulnerabilities

## 🔧 Example Output

### Static Analysis
```
🛡️======================================================================
   BOAR - Buffer Overflow Analysis & Remediation Framework
   Advanced CVE-based Security Analysis Tool
========================================================================

[*] Memulai analisis statis CVE-based pada: test_vulnerable.c
[*] Menggunakan 8 CVE patterns dan 4 complex patterns

================================================================================
 LAPORAN ANALISIS KEAMANAN CVE-BASED
================================================================================

[!] Ditemukan 8 potensi kerentanan:

🔴====================  CRITICAL SEVERITY (2 items)  ====================

     File: `test_vulnerable.c` | Line: 12
     Function/Pattern: `gets`
     Description: Fungsi gets() tidak melakukan bound checking, sangat mudah di-overflow
     CVE References: CVE-2012-3489, CVE-2015-1781, CVE-2016-4051
     Remediation: Gunakan fgets() dengan buffer size yang tepat
     Code: `gets(buffer);  // Dangerous! No bounds checking`
     Example Exploit: payload = "A" * 1024 + return_address
```

### Dynamic Analysis
```
[*] Memulai analisis dinamis pada: ./vulnerable_binary
[*] Memeriksa proteksi keamanan binary...
[*] Proteksi aktif: ['canary']

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
  3. ⚠️  Stack canary aktif - perlu bypass atau leak canary
```

## 🎓 Educational Examples

### Test Program
Use the included `test_vulnerable.c` to test BOAR's capabilities:

```bash
# Compile the test program
gcc -o test_vulnerable test_vulnerable.c -fno-stack-protector

# Test static analysis
python BOAR_beta.py static test_vulnerable.c

# Test dynamic analysis
python BOAR_beta.py dynamic ./test_vulnerable -l 500

# Test specific vulnerability
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./test_vulnerable 1
```

## 🛡️ Security Protections Detected

BOAR can detect and provide bypass advice for:

- **Stack Canaries**: Detects stack protection and suggests bypass techniques
- **NX/DEP**: Identifies non-executable stack and recommends ROP
- **PIE**: Detects position-independent executables and suggests info leaks
- **RELRO**: Identifies relocation read-only protection
- **ASLR**: Detects address space layout randomization

## 📋 Remediation Recommendations

For each vulnerability found, BOAR provides:
- **Specific CVE references** for context
- **Detailed remediation steps** with code examples
- **Secure coding alternatives** for dangerous functions
- **Protection bypass techniques** for educational purposes
- **Real-world exploit examples** for understanding impact

## 🔗 Integration

BOAR can be integrated with:
- **CI/CD pipelines** for automated security testing
- **IDE plugins** for real-time vulnerability detection
- **Security scanners** as a specialized buffer overflow module
- **Penetration testing frameworks** for exploit development

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add CVE patterns or improve detection logic
4. Submit a pull request with detailed descriptions

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
