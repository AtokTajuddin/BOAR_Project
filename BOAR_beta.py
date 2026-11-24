#!/usr/bin/env python3
"""
BOAR - Buffer Overflow Analysis & Remediation Framework
Rule-driven memory-safety scanner with optional GDB crash analysis
"""

import re
import argparse
import os
import sys
import subprocess
import struct
import json
import time
from pathlib import Path
from boar_engine import (
    analyze_path,
    analyze_source,
    build_report,
    build_sarif,
    filter_by_severity,
    load_rules,
    reaches_threshold,
    render_text,
)

def print_dragon_banner():
    """Print epic dragon breathing BOAR fire banner - inspired by dark fantasy artwork"""
    
    # Color codes for epic effect
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DARK_GRAY = '\033[90m'
    BRIGHT_RED = '\033[101m'
    RESET = '\033[0m'
    
    epic_dragon = f"""
{BOLD}{RED}     ╔══════════════════════════════════════════════════════════════════════════════════════╗{RESET}
{BOLD}{RED}     ║                    🛡️  BOAR SECURITY FRAMEWORK ACTIVATED! 🛡️                      ║{RESET}
{BOLD}{RED}     ╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}

{BOLD}{WHITE}                             ██████╗  ██████╗  █████╗ ██████╗ {RESET}
{BOLD}{WHITE}                             ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗{RESET}
{BOLD}{RED}                             ██████╔╝██║   ██║███████║██████╔╝{RESET}
{BOLD}{RED}                             ██╔══██╗██║   ██║██╔══██║██╔══██╗{RESET}
{BOLD}{RED}                             ██████╔╝╚██████╔╝██║  ██║██║  ██║{RESET}
{BOLD}{WHITE}                             ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{RESET}

{BOLD}{CYAN}                        BOAR - Buffer Overflow Analysis & Remediation Framework{RESET}
{BOLD}{YELLOW}                            Rule-Based Detection Engine{RESET}
{BOLD}{MAGENTA}                            PoC Skeleton Generation{RESET}
{BOLD}{GREEN}                            Dynamic Crash Analysis{RESET}

{BOLD}{BLUE}     ╔══════════════════════════════════════════════════════════════════════════════════════╗{RESET}
{BOLD}{BLUE}     ║  Born to Hunt Buffer Overflow Vulnerabilities!             ║{RESET}
{BOLD}{BLUE}     ╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}
"""

    print(epic_dragon, file=sys.stderr)
    
    # Only pause on interactive terminals so CI and piped runs have zero delay
    if sys.stderr.isatty():
        time.sleep(0.15)
    
    # Print additional info
    print(f"{BOLD}{WHITE}     🔥 14 Memory-Safety Rules | Scoped Buffer Tracking | SARIF & CI-Ready{RESET}", file=sys.stderr)
    print(f"{BOLD}{CYAN}     ═══════════════════════════════════════════════════════════════════════════════════════════════════════{RESET}", file=sys.stderr)
    print(file=sys.stderr)

## =================================================================
## BAGIAN 1: MODUL ANALISIS STATIS BERBASIS RULE
## =================================================================

# Static analysis is rule-driven; rules live in boar_rules.json. Keeping the
# engine in a separate module lets the rule set and matcher tests evolve without
# touching the CLI or the dynamic-analysis code.


def analyze_file(filepath, rules=None):
    """Analyze one file with the rule engine (kept as a public helper)."""
    rules = rules or load_rules()
    source = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    return analyze_source(source, os.path.basename(filepath), rules)


def run_static_analysis(target_path, rules=None, severity="all", output_format="text", report_path=None):
    """Run the rule engine, print the requested format, and return the report."""
    rules = rules or load_rules()
    print(f"[*] Memulai analisis statis pada: {target_path}", file=sys.stderr)
    print(f"[*] Menggunakan {len(rules)} memory-safety rules", file=sys.stderr)

    try:
        findings = analyze_path(target_path, rules)
    except FileNotFoundError as exc:
        print(f"[!] Error: {exc}")
        return None

    findings = filter_by_severity(findings, severity)
    report = build_report(target_path, findings, len(rules))
    sarif_doc = (
        build_sarif(target_path, findings, rules)
        if (output_format == "sarif" or (report_path and str(report_path).lower().endswith(".sarif")))
        else None
    )

    if report_path:
        if str(report_path).lower().endswith(".sarif") or output_format == "sarif":
            payload = sarif_doc or build_sarif(target_path, findings, rules)
            Path(report_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"[+] SARIF report ditulis ke: {report_path}", file=sys.stderr)
        else:
            Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"[+] JSON report ditulis ke: {report_path}", file=sys.stderr)

    if output_format == "json":
        print(json.dumps(report, indent=2))
    elif output_format == "sarif":
        print(json.dumps(sarif_doc, indent=2))
    elif output_format == "jsonl":
        for finding in findings:
            print(json.dumps(finding))
    else:
        print(render_text(report))
    return report

## =================================================================
## BAGIAN 2: MODUL ANALISIS DINAMIS DAN CRASH DETECTION
## =================================================================

def _de_bruijn_bytes(alphabet, order):
    """Yield a prefix of a de Bruijn sequence over ``alphabet``."""
    k = len(alphabet)
    a = [0] * (k * order)

    def generate(t, p):
        if t > order:
            if order % p == 0:
                for index in range(1, p + 1):
                    yield alphabet[a[index]]
            return
        a[t] = a[t - p]
        for value in generate(t + 1, p):
            yield value
        for value in range(a[t - p] + 1, k):
            a[t] = value
            for item in generate(t + 1, t):
                yield item

    return generate(1, 1)


def generate_pattern(length):
    """Generate a de Bruijn pattern with unique 4-byte windows for offset search."""
    if length <= 0:
        return b""

    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    order = 4
    pattern = bytearray()
    for byte in _de_bruijn_bytes(alphabet, order):
        pattern.append(byte)
        if len(pattern) == length:
            break

    # k**order is the maximum number of unique windows; repeating beyond that
    # cannot preserve uniqueness, so return the largest unique prefix.
    return bytes(pattern)

def find_offset(hex_value, pattern):
    """Mencari offset dengan dukungan multiple architectures dan endianness."""
    try:
        # Try different interpretations
        interpretations = []
        
        # 64-bit little-endian
        try:
            search_bytes = struct.pack('<Q', int(hex_value, 16))
            offset = pattern.find(search_bytes)
            if offset != -1:
                interpretations.append((offset, 64, 'little-endian'))
        except (struct.error, ValueError):
            pass
        
        # 32-bit little-endian
        try:
            search_bytes = struct.pack('<I', int(hex_value, 16))
            offset = pattern.find(search_bytes)
            if offset != -1:
                interpretations.append((offset, 32, 'little-endian'))
        except (struct.error, ValueError):
            pass
        
        # 32-bit big-endian
        try:
            search_bytes = struct.pack('>I', int(hex_value, 16))
            offset = pattern.find(search_bytes)
            if offset != -1:
                interpretations.append((offset, 32, 'big-endian'))
        except (struct.error, ValueError):
            pass
        
        # Return the most likely interpretation. Wide values come from a 64-bit
        # instruction pointer; narrow values normally come from a 32-bit one.
        if interpretations:
            value = int(hex_value, 16)
            preferred_bits = 64 if value > 0xFFFFFFFF else 32
            interpretations.sort(key=lambda item: (
                item[2] != 'little-endian', item[1] != preferred_bits,
            ))
            return interpretations[0]
        
    except Exception as e:
        print(f"[!] Error dalam analisis offset: {e}")
    
    return None, None, None

def analyze_crash_pattern(gdb_output, payload=None):
    """Menganalisis pola crash untuk memberikan insight yang lebih baik."""
    crash_info = {
        'crash_type': 'unknown',
        'exploitability': 'unknown',
        'registers': {},
        'stack_info': '',
        'recommendations': []
    }
    
    lower = gdb_output.lower()

    # Specific allocator/stack diagnostics must win over the generic signal:
    # glibc aborts on double free and heap corruption, so checking SIGABRT first
    # would hide the actual memory-safety failure.
    if "stack smashing" in lower:
        crash_info['crash_type'] = 'stack_smashing'
    elif "double free" in lower or "double-free" in lower:
        crash_info['crash_type'] = 'double_free'
    elif "corrupted" in lower and ("malloc" in lower or "free" in lower or "heap" in lower):
        crash_info['crash_type'] = 'heap_corruption'
    elif "SIGSEGV" in gdb_output:
        crash_info['crash_type'] = 'segmentation_fault'
    elif "SIGABRT" in gdb_output:
        crash_info['crash_type'] = 'abort_signal'
    
    # Extract register information
    reg_patterns = [
        r'(eip|rip)\s+(0x[0-9a-fA-F]+)',
        r'(esp|rsp)\s+(0x[0-9a-fA-F]+)',
        r'(ebp|rbp)\s+(0x[0-9a-fA-F]+)',
        r'(eax|rax)\s+(0x[0-9a-fA-F]+)'
    ]
    
    for pattern in reg_patterns:
        matches = re.finditer(pattern, gdb_output, re.IGNORECASE)
        for match in matches:
            reg_name, reg_value = match.groups()
            crash_info['registers'][reg_name.upper()] = reg_value

    controlled = []
    if payload:
        for reg_name, reg_value in crash_info['registers'].items():
            offset, _, _ = find_offset(reg_value, payload)
            if offset is not None:
                controlled.append((reg_name, offset))
    crash_info['controlled_registers'] = controlled

    # Analyze exploitability
    if crash_info['crash_type'] == 'segmentation_fault':
        ip_reg = 'EIP' if 'EIP' in crash_info['registers'] else (
            'RIP' if 'RIP' in crash_info['registers'] else None
        )
        ip_controlled = False
        if payload and ip_reg:
            ip_controlled = find_offset(crash_info['registers'][ip_reg], payload)[0] is not None

        if payload is None:
            ip_controlled = ip_reg is not None

        if ip_controlled:
            crash_info['exploitability'] = 'high'
            crash_info['recommendations'].append(
                'Instruction pointer berisi payload pattern - kemungkinan besar exploitable'
            )
        elif controlled:
            crash_info['exploitability'] = 'high'
            names = ', '.join('{}@{}'.format(name, offset) for name, offset in controlled)
            crash_info['recommendations'].append(
                'Register terkontrol: {} - stack overflow terkonfirmasi, IP belum terbukti'.format(names)
            )
        else:
            crash_info['exploitability'] = 'medium'
            crash_info['recommendations'].append(
                'Crash terdeteksi, tetapi tidak ada register yang cocok dengan payload pattern'
            )
    elif crash_info['crash_type'] == 'double_free':
        crash_info['exploitability'] = 'high'
        crash_info['recommendations'].append('Double free terdeteksi - audit jalur cleanup dan kepemilikan pointer')
    elif crash_info['crash_type'] == 'heap_corruption':
        crash_info['exploitability'] = 'high'
        crash_info['recommendations'].append('Heap corruption terdeteksi - jalankan ulang dengan -fsanitize=address untuk lokasi pasti')
    
    # Stack analysis
    if "stack smashing" in gdb_output.lower():
        crash_info['recommendations'].append('Stack canary terdeteksi - bypass diperlukan untuk eksploitasi')
    
    # Memory protection analysis
    if "NX" in gdb_output or "DEP" in gdb_output:
        crash_info['recommendations'].append('NX/DEP aktif - gunakan ROP/JOP untuk eksploitasi')
    
    if "ASLR" in gdb_output:
        crash_info['recommendations'].append('ASLR aktif - perlu information leak untuk bypass')
    
    return crash_info

def active_protections(protections):
    """Return protection names that are actually enabled."""
    return [
        name for name, value in protections.items()
        if value not in (False, None, 'none', 'disabled')
    ]


def detect_system_aslr(proc_path="/proc/sys/kernel/randomize_va_space"):
    """Read Linux kernel ASLR mode when available ('disabled', 'conservative', 'full', or None)."""
    mapping = {
        "0": "disabled",
        "1": "conservative",
        "2": "full",
    }
    try:
        raw = Path(proc_path).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return mapping.get(raw, raw or None)


_FORTIFY_SYM_RE = re.compile(r"\b__(?!stack_chk_fail\b)[a-z0-9_]+_chk(?:@|\b)")


def check_binary_protections(binary_path):
    """Inspect ELF metadata for canary, NX, PIE, RELRO, FORTIFY, plus host ASLR."""
    protections = {
        'canary': False,
        'nx': False,
        'pie': False,
        'relro': 'none',
        'fortify': False,
        'aslr': detect_system_aslr(),
    }

    try:
        header = subprocess.run(['readelf', '-hW', binary_path],
                                capture_output=True, text=True, timeout=10)
        segments = subprocess.run(['readelf', '-lW', binary_path],
                                  capture_output=True, text=True, timeout=10)
        dynamic = subprocess.run(['readelf', '-dW', binary_path],
                                 capture_output=True, text=True, timeout=10)
        symbols = subprocess.run(['readelf', '-sW', binary_path],
                                 capture_output=True, text=True, timeout=10)

        header_output = header.stdout + header.stderr
        segment_output = segments.stdout + segments.stderr
        dynamic_output = dynamic.stdout + dynamic.stderr
        symbol_output = symbols.stdout + symbols.stderr

        if 'Position-Independent Executable' in header_output:
            protections['pie'] = True
        elif re.search(r'Type:\s+DYN', header_output):
            protections['pie'] = True

        for line in segment_output.splitlines():
            if 'GNU_STACK' in line:
                parts = line.split()
                if len(parts) >= 2:
                    protections['nx'] = 'E' not in parts[-2]
                break

        if 'GNU_RELRO' in segment_output:
            protections['relro'] = 'full' if 'BIND_NOW' in dynamic_output else 'partial'

        if '__stack_chk_fail' in symbol_output:
            protections['canary'] = True

        if _FORTIFY_SYM_RE.search(symbol_output):
            protections['fortify'] = True

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        try:
            with open(binary_path, 'rb') as handle:
                content = handle.read()
            protections['canary'] = b'__stack_chk_fail' in content
            protections['fortify'] = bool(re.search(rb'__(?!stack_chk_fail)[a-z0-9_]+_chk', content))
        except OSError:
            pass

    return protections

def run_dynamic_analysis(binary_path, payload_length, debug=False, method='stdin'):
    """Metode analisis dinamis yang disempurnakan dengan crash analysis."""
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        print(f"[!] Error: File '{binary_path}' tidak valid atau tidak bisa dieksekusi.")
        return

    print(f"[*] Memulai analisis dinamis pada: {binary_path}")
    
    # Check binary protections
    print("[*] Memeriksa proteksi keamanan binary...")
    protections = check_binary_protections(binary_path)
    print(f"[*] Proteksi aktif: {active_protections(protections)}")
    
    # Generate payload
    payload = generate_pattern(payload_length)
    print(f"[*] Membuat payload pola unik dengan panjang: {len(payload)} bytes")
    print(f"[*] Menggunakan metode input: {method.upper()}")

    # Prepare GDB command
    gdb_commands = [
        "set pagination off",
        "set confirm off",
        "set print elements 0",
        "run",
        "info registers",
        "bt",
        "info proc mappings",
        "quit"
    ]
    
    gdb_command = ["gdb", "-q", "--batch"]
    for cmd in gdb_commands:
        gdb_command.extend(["-ex", cmd])
    
    try:
        if method == 'stdin':
            gdb_command.extend(["--args", binary_path])
            print("[*] Menjalankan GDB dan menyalurkan payload melalui STDIN...")
            gdb_process = subprocess.run(gdb_command, input=payload, capture_output=True, timeout=60)
        elif method == 'argv':
            gdb_command.extend(["--args", binary_path, payload.decode('latin-1')])
            print("[*] Menjalankan GDB dan menyalurkan payload melalui ARGV...")
            gdb_process = subprocess.run(gdb_command, capture_output=True, timeout=60)
        else:
            print(f"[!] Method '{method}' tidak didukung.")
            return

        gdb_output = gdb_process.stdout.decode('utf-8', 'ignore') + gdb_process.stderr.decode('utf-8', 'ignore')

        if debug:
            print(f"\n{'='*20}  OUTPUT MENTAH GDB (DEBUG MODE)  {'='*20}")
            print(gdb_output)
            print("="*70 + "\n")

        # Analyze crash
        crash_info = analyze_crash_pattern(gdb_output, payload)
        
        print(f"\n{'='*60}")
        print("HASIL ANALISIS CRASH")
        print("="*60)
        print(f"Crash Type: {crash_info['crash_type']}")
        print(f"Exploitability: {crash_info['exploitability']}")
        
        if crash_info['registers']:
            print(f"\nRegister States:")
            for reg, value in crash_info['registers'].items():
                print(f"  {reg}: {value}")

        if crash_info.get('controlled_registers'):
            print("\n[+] Register yang cocok dengan payload:")
            for reg, offset in crash_info['controlled_registers']:
                print(f"  {reg}: offset {offset}")
        
        if crash_info['crash_type'] == 'segmentation_fault':
            print("\n[!!!] CRASH TERDETEKSI! (Segmentation Fault)")
            
            # Check if instruction pointer is controlled
            ip_reg = None
            ip_value = None
            
            if 'EIP' in crash_info['registers']:
                ip_reg, ip_value = 'EIP', crash_info['registers']['EIP']
            elif 'RIP' in crash_info['registers']:
                ip_reg, ip_value = 'RIP', crash_info['registers']['RIP']
            
            if ip_reg and ip_value:
                print(f"[+] Instruction Pointer ({ip_reg}) bernilai: {ip_value}")
                
                # Find offset
                offset, arch, endian = find_offset(ip_value, payload)
                if offset is not None:
                    print(f"[+] 🎯 Offset kerentanan berhasil ditemukan: {offset}")
                    print(f"[+] Arsitektur: {arch}-bit ({endian})")
                    
                    # Generate exploit template
                    print(f"\n[+] REKOMENDASI EKSPLOITASI:")
                    print(f"  1. Buat skrip PoC: python {sys.argv[0]} poc {binary_path} --offset {offset}")
                    print(f"  2. Gunakan offset {offset} untuk mengontrol {ip_reg}")
                    
                    if protections['canary']:
                        print(f"  3. ⚠️  Stack canary aktif - perlu bypass atau leak canary")
                    if protections['nx']:
                        print(f"  4. ⚠️  NX/DEP aktif - gunakan ROP chains")
                    if protections['pie']:
                        print(f"  5. ⚠️  PIE aktif - perlu information leak untuk alamat base")
                    
                    # Suggest payload structure
                    print(f"\n[+] STRUKTUR PAYLOAD YANG DISARANKAN:")
                    print(f"  payload = b'A' * {offset} + p32/p64(return_address)")
                    if protections['canary']:
                        print(f"  # Perlu leak canary dan masukkan di offset yang tepat")
                    if protections['nx']:
                        print(f"  # Tambahkan ROP chain setelah return address")
                    
                else:
                    print(f"[-] {ip_reg} = {ip_value} tidak cocok dengan payload pattern")
                    print(f"    Kemungkinan: transformasi data, encoding, atau indirect overwrite")
                    for reg, controlled_offset in crash_info['controlled_registers']:
                        print(f"[+] Register {reg} berisi payload pattern pada offset {controlled_offset}")
                        if reg in ('RBP', 'EBP'):
                            ptr_size = 8 if reg == 'RBP' else 4
                            return_offset = controlled_offset + ptr_size
                            print(f"[+] Saved frame pointer terkontrol; return address biasanya di offset {return_offset}")
                            print(f"    Buat skrip PoC: python {sys.argv[0]} poc {binary_path} --offset {return_offset}")
            else:
                print(f"[-] Crash terdeteksi tapi instruction pointer tidak terkontrol")
                print(f"    Kemungkinan penyebab: stack canary, heap overflow, atau protection mechanism")
        
        elif crash_info['crash_type'] == 'stack_smashing':
            print("\n[!!!] STACK SMASHING TERDETEKSI!")
            print("[*] Stack canary/guard berhasil mendeteksi overflow")
            print("[*] Untuk eksploitasi, perlu bypass stack canary")
            
        elif crash_info['crash_type'] == 'abort_signal':
            print("\n[!!!] ABORT SIGNAL TERDETEKSI!")
            print("[*] Program di-abort, kemungkinan karena heap corruption atau assertion failure")
            
        # Print recommendations
        if crash_info['recommendations']:
            print(f"\n[+] REKOMENDASI KEAMANAN:")
            for i, rec in enumerate(crash_info['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        # Print protection bypass advice
        if active_protections(protections):
            print(f"\n[+] STRATEGI BYPASS PROTEKSI:")
            if protections['canary']:
                print("  - Stack Canary: Cari format string bug atau information leak")
            if protections['nx']:
                print("  - NX/DEP: Gunakan ROP (Return Oriented Programming)")
            if protections['pie']:
                print("  - PIE: Cari information leak untuk menentukan base address")
            if protections['relro'] != 'none':
                print(f"  - RELRO ({protections['relro']}): overwrite GOT hanya jika RELRO tidak full")
            print("  - ASLR: setting sistem-wide; cek /proc/sys/kernel/randomize_va_space")

    except subprocess.TimeoutExpired:
        print("[!] Timeout - proses GDB melebihi batas waktu")
    except Exception as e:
        print(f"[!] Error dalam analisis dinamis: {e}")
        
    print("\n" + "="*60)

## =================================================================
## BAGIAN 3: MODUL PEMBUATAN PROOF OF CONCEPT (POC) DENGAN EXPLOIT TEMPLATES
## =================================================================

def generate_advanced_poc_script(binary_path, offset, arch=32, protections=None):
    """Membuat file exploit.py dengan template yang lebih canggih berdasarkan proteksi binary."""
    if protections is None:
        protections = check_binary_protections(binary_path)
    
    poc_filename = f"exploit_{os.path.basename(binary_path)}.py"
    
    # Determine architecture-specific settings
    if arch == 64:
        addr_format = "Q"
        ptr_size = 8
        sample_addr = "0x0000414141414141"
    else:
        addr_format = "I"
        ptr_size = 4
        sample_addr = "0x41414141"
    
    # Generate exploit template based on protections
    exploit_template = f"""#!/usr/bin/env python3
\"\"\"
BOAR PoC Skeleton
Target: {binary_path}
Offset: {offset}
Architecture: {arch}-bit
Protections: {active_protections(protections)}
Generated by BOAR (Buffer Overflow Analysis & Remediation)
\"\"\"

import subprocess
import struct
import sys

# --- Configuration ---
BINARY_PATH = "{binary_path}"
OFFSET = {offset}
ARCH = {arch}
PROTECTIONS = {protections}

def active_protections():
    return [name for name, value in PROTECTIONS.items() if value not in (False, None, 'none')]

# --- Exploit Functions ---
def p{arch}(addr):
    \"\"\"Pack address for {arch}-bit architecture\"\"\"
    return struct.pack("<{addr_format}", addr)

def build_payload():
    \"\"\"Build the payload skeleton.\"\"\"
    payload = b'A' * OFFSET

    # Replace this placeholder with the address you want to execute.
    # - NX enabled: put the first ROP gadget here (BOAR does not find gadgets).
    # - NX disabled: point this at shellcode placed elsewhere in memory.
    # - Stack canary: leak it first and insert it before the return address.
    target_address = {sample_addr}
    payload += p{arch}(target_address)
    return payload

def exploit():
    \"\"\"Main exploit function\"\"\"
    print("[*] Building exploit payload...")
    payload = build_payload()
    
    print(f"[*] Payload length: {{len(payload)}} bytes")
    print(f"[*] Offset: {{OFFSET}} bytes")
    print(f"[*] Target architecture: {{ARCH}}-bit")
    print(f"[*] Active protections: {{active_protections()}}")
    
    # Launch target
    print(f"[*] Launching target: {{BINARY_PATH}}")
    
    try:
        # Method 1: Direct execution with stdin
        process = subprocess.Popen(
            [BINARY_PATH], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate(input=payload, timeout=10)
        
        print("[+] Payload sent successfully!")
        
        if stdout:
            print(f"[+] STDOUT:\\n{{stdout.decode('utf-8', errors='ignore')}}")
        if stderr:
            print(f"[!] STDERR:\\n{{stderr.decode('utf-8', errors='ignore')}}")
        
        return_code = process.returncode
        print(f"[*] Process exited with code: {{return_code}}")
        
        if return_code < 0:
            print("[+] Process crashed - potential exploitation!")
        
    except subprocess.TimeoutExpired:
        print("[!] Process timeout - might be hanging (good sign!)")
        process.kill()
    except Exception as e:
        print(f"[!] Error during exploitation: {{e}}")

def info():
    \"\"\"Display exploit information\"\"\"
    print("="*60)
    print("EXPLOIT INFORMATION")
    print("="*60)
    print(f"Target Binary: {{BINARY_PATH}}")
    print(f"Buffer Offset: {{OFFSET}} bytes")
    print(f"Architecture: {{ARCH}}-bit")
    print(f"Protections: {{PROTECTIONS}}")
    print()
    print("EXPLOITATION STRATEGY:")
    
    if PROTECTIONS.get('canary'):
        print("  1. ⚠️  Stack Canary: Need to leak canary value first")
    if PROTECTIONS.get('nx'):
        print("  2. ⚠️  NX/DEP: Use ROP chain for code execution")
    if PROTECTIONS.get('pie'):
        print("  3. ⚠️  PIE: Need information leak for base address")
    print("  4. ASLR is system-wide; check /proc/sys/kernel/randomize_va_space")
    
    if not active_protections():
        print("  ✅ No major protections detected - direct exploitation possible")
    
    print()
    print("RECOMMENDED TOOLS:")
    print("  - ropper: Find ROP gadgets")
    print("  - pwntools: Exploitation framework")
    print("  - gdb-peda: Enhanced debugging")
    print("  - checksec: Verify binary protections")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "info":
            info()
        else:
            exploit()
    else:
        print("Usage:")
        print(f"  python3 {{sys.argv[0]}} [info]")
        print("  Default: Run basic exploit")
        exploit()
"""
    
    with open(poc_filename, "w") as f:
        f.write(exploit_template)
    
    print(f"\n[+] 🎯 PoC skeleton generated: '{poc_filename}'")
    print(f"[*] Usage:")
    print(f"  python3 {poc_filename}          # Basic exploit")
    print(f"  python3 {poc_filename} info     # Show exploit info")

def generate_poc_script(binary_path, offset):
    """Legacy function for backward compatibility"""
    # Check binary protections
    protections = check_binary_protections(binary_path)
    
    # Determine architecture (simple heuristic)
    try:
        result = subprocess.run(['file', binary_path], capture_output=True, text=True)
        if '64-bit' in result.stdout:
            arch = 64
        else:
            arch = 32
    except:
        arch = 32  # Default to 32-bit
    
    generate_advanced_poc_script(binary_path, offset, arch, protections)

## =================================================================
## BAGIAN 4: FUNGSI UTAMA DAN PARSER ARGUMEN YANG DISEMPURNAKAN
## =================================================================

def main():
    parser = argparse.ArgumentParser(
        description="🛡️  BOAR - Rule-based Memory-Safety Analysis Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Static analysis with JSON rules
  python BOAR_beta.py static /path/to/code

  # JSON report with a CI severity gate
  python BOAR_beta.py static /path/to/code --format json --fail-on high

  # Dynamic analysis with crash classification
  python BOAR_beta.py dynamic ./vulnerable_binary -l 1000 -m stdin

  # Generate a PoC skeleton
  python BOAR_beta.py poc ./vulnerable_binary -o 268 --advanced
        """
    )
    
    parser.add_argument("--no-banner", "-q", action="store_true",
                        help="Suppress the startup ASCII banner")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Static analysis command
    parser_static = subparsers.add_parser("static", help="Memory-safety static analysis")
    parser_static.add_argument("target", help="File or directory to analyze")
    parser_static.add_argument("--format", "-o", "--output", dest="format",
                              choices=["text", "json", "jsonl", "sarif"], default="text",
                              help="Output format (default: text)")
    parser_static.add_argument("--severity", "-s",
                              choices=['all', 'critical', 'high', 'medium', 'low'],
                              default='all', help="Filter findings by exact severity")
    parser_static.add_argument("--rules", action="append", metavar="PATH",
                              help="Extra JSON rule file or directory (repeatable)")
    parser_static.add_argument("--report", metavar="PATH",
                              help="Write the JSON report to PATH")
    parser_static.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                              help="Exit with status 1 when a finding reaches this severity")

    # Dynamic analysis command
    parser_dynamic = subparsers.add_parser("dynamic", help="Crash and protection analysis")
    parser_dynamic.add_argument("binary", help="Binary file to analyze")
    parser_dynamic.add_argument("-l", "--length", type=int, default=1000, 
                               help="Payload length (default: 1000)")
    parser_dynamic.add_argument("-m", "--method", choices=['stdin', 'argv'], default='stdin',
                               help="Input method (default: stdin)")
    parser_dynamic.add_argument("-d", "--debug", action="store_true", 
                               help="Enable debug mode")
    parser_dynamic.add_argument("--check-protections", action="store_true",
                               help="Check binary security protections")

    # PoC generation command
    parser_poc = subparsers.add_parser("poc", help="Generate a PoC skeleton")
    parser_poc.add_argument("binary", help="Target binary")
    parser_poc.add_argument("-o", "--offset", type=int, required=True, 
                           help="Buffer overflow offset")
    parser_poc.add_argument("--arch", choices=[32, 64], type=int, default=32,
                           help="Target architecture (default: 32)")
    parser_poc.add_argument("--advanced", action="store_true",
                           help="Generate the PoC skeleton with protection context")

    # Info command
    parser_info = subparsers.add_parser("info", help="Show tool information and statistics")

    args = parser.parse_args()

    if not args.no_banner:
        print_dragon_banner()

    try:
        if args.command == "static":
            rules = load_rules(args.rules)
            report = run_static_analysis(
                args.target, rules, args.severity, args.format, args.report,
            )
            if report and reaches_threshold(report["findings"], args.fail_on):
                sys.exit(1)

        elif args.command == "dynamic":
            if args.check_protections:
                protections = check_binary_protections(args.binary)
                print(f"Binary protections: {protections}")
                print(f"Active protections: {active_protections(protections)}")
                return
            run_dynamic_analysis(args.binary, args.length, args.debug, args.method)

        elif args.command == "poc":
            if args.advanced:
                protections = check_binary_protections(args.binary)
                generate_advanced_poc_script(args.binary, args.offset, args.arch, protections)
            else:
                generate_poc_script(args.binary, args.offset)

        elif args.command == "info":
            rules = load_rules()
            print("🔥 BOAR Framework Information:")
            print(f"- Rules: {len(rules)} JSON templates")
            print(f"- Matchers: {len(set(rule['matcher'] for rule in rules))}")
            print("- Supported Architectures: 32-bit, 64-bit")
            print("- Supported Input Methods: stdin, argv")
            print("- Protection Detection: Canary, NX, PIE, RELRO, FORTIFY + host ASLR")
            print("- Output Formats: text, json, jsonl, sarif")

        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n[*] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()