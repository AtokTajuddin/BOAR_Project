import re
import argparse
import os
import sys
import subprocess

# --- BAGIAN 1: FUNGSI-FUNGSI UNTUK MODUL ANALISIS STATIS ---

DANGEROUS_FUNCTIONS = {
    'gets': 'Sangat berbahaya, tidak ada pemeriksaan batas. Mudah sekali di-overflow.',
    'strcpy': 'Tidak memeriksa ukuran buffer tujuan. Gunakan strncpy sebagai gantinya.',
    'strcat': 'Tidak memeriksa ukuran buffer tujuan. Gunakan strncat sebagai gantinya.',
    'sprintf': 'Berbahaya jika format string tidak dikontrol. Gunakan snprintf.',
    'scanf': 'Berbahaya jika menggunakan %s tanpa penentu lebar (width specifier).'
}

def analyze_file(filepath):
    """Menganalisis satu file kode untuk mencari fungsi-fungsi berbahaya."""
    findings = []
    print(f"\n[*] Menganalisis file: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip().startswith(('//', '/*')):
                    continue
                for func, reason in DANGEROUS_FUNCTIONS.items():
                    if re.search(r'\b' + func + r'\s*\(', line):
                        if func == 'scanf' and '%s' not in line:
                            continue
                        findings.append({
                            'line_number': i + 1, 'function': func,
                            'reason': reason, 'line_content': line.strip()
                        })
    except Exception as e:
        print(f"[!] Gagal menganalisis file '{filepath}': {e}")
    return findings

def run_static_analysis(target_path):
    """Fungsi utama untuk menjalankan seluruh proses analisis statis."""
    all_findings = []
    if os.path.isfile(target_path):
        all_findings.extend(analyze_file(target_path))
    elif os.path.isdir(target_path):
        print(f"[*] Memindai direktori: {target_path}")
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.c', '.cpp', '.h')):
                    filepath = os.path.join(root, file)
                    all_findings.extend(analyze_file(filepath))
    else:
        print(f"[!] Error: Target '{target_path}' bukan file atau direktori yang valid.")
        return

    print("\n" + "="*50 + "\n           Laporan Analisis Statis Selesai\n" + "="*50)
    if not all_findings:
        print("\n[+] Tidak ditemukan fungsi berbahaya yang umum. Kode terlihat aman!")
    else:
        print(f"\n[!] Ditemukan {len(all_findings)} potensi kerentanan:")
        for finding in all_findings:
            print(f"\n  - Baris {finding['line_number']}: Penggunaan fungsi `{finding['function']}`")
            print(f"    Alasan: {finding['reason']}")
            print(f"    Kode: `{finding['line_content']}`")
    print("\n" + "="*50)

# --- BAGIAN 2: FUNGSI-FUNGSI UNTUK MODUL ANALISIS DINAMIS ---

def generate_pattern(length):
    """Membuat string unik untuk melacak offset."""
    pattern = ''
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    i = 0
    while len(pattern) < length:
        pattern += chars[i % len(chars)]
        if (len(pattern) + 1) % 4 == 0:
            i += 1
    return pattern[:length]

def run_dynamic_analysis(binary_path, payload_length):
    """Fungsi utama untuk menjalankan seluruh proses analisis dinamis."""
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        print(f"[!] Error: File biner '{binary_path}' tidak ditemukan atau tidak bisa dieksekusi.")
        return

    print(f"[*] Memulai analisis dinamis pada: {binary_path}")
    payload = generate_pattern(payload_length)
    print(f"[*] Membuat payload dengan panjang: {len(payload)} bytes")

    gdb_script_path = "gdb_commands.txt"
    with open(gdb_script_path, "w") as f:
        f.write(f"run {payload}\n")
        f.write("info registers\n")

    print("[*] Menjalankan GDB untuk mendeteksi crash...")
    command = ["gdb", "-batch", "-x", gdb_script_path, binary_path]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr

        if "SIGSEGV" in output:
            print("\n[!!!] CRASH TERDETEKSI! (Segmentation Fault)")
            print("[+] Program berhasil di-overflow. Ini adalah celah yang valid.")
            for line in output.splitlines():
                if 'rip' in line or 'eip' in line:
                    print(f"[+] Bukti Kontrol -> {line.strip()}")
                    if "0x" in line:
                        hex_val = line.split()[1][2:]
                        try:
                            leaked_chars = bytes.fromhex(hex_val).decode('ascii')[::-1]
                            print(f"[+] Karakter yang menimpa Instruction Pointer: '{leaked_chars}'")
                        except: pass
                    break
        else:
            print("\n[+] Program berjalan dan selesai tanpa crash dengan input ini.")
    except Exception as e:
        print(f"[!] Terjadi error saat menjalankan GDB: {e}")
    finally:
        if os.path.exists(gdb_script_path):
            os.remove(gdb_script_path)

# --- BAGIAN 3: FUNGSI UTAMA DAN "SWITCH CASE" ---

def main():
    # Buat parser utama
    parser = argparse.ArgumentParser(
        description="Code Sentinel Framework - Tool Analisis Keamanan Kode Terpadu.",
        formatter_class=argparse.RawTextHelpFormatter # Untuk format teks bantuan yang lebih baik
    )
    # Buat subparser untuk menampung sub-commands
    subparsers = parser.add_subparsers(dest="command", required=True, help="Pilih mode analisis yang akan digunakan.")

    # Buat parser untuk command 'static'
    parser_static = subparsers.add_parser("static", help="Menjalankan analisis statis pada source code C/C++.")
    parser_static.add_argument("target", help="File atau direktori source code yang akan dianalisis.")

    # Buat parser untuk command 'dynamic'
    parser_dynamic = subparsers.add_parser("dynamic", help="Menjalankan analisis dinamis untuk mendeteksi buffer overflow.")
    parser_dynamic.add_argument("binary", help="Path ke file biner yang akan diuji.")
    parser_dynamic.add_argument("-l", "--length", type=int, default=500, help="Panjang payload untuk overflow (default: 500).")

    # Ambil argumen dari command line
    args = parser.parse_args()

    # Ini adalah "Switch Case" kita
    if args.command == "static":
        run_static_analysis(args.target)
    elif args.command == "dynamic":
        run_dynamic_analysis(args.binary, args.length)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()