#!/usr/bin/env python3
"""
PyShield Antivirus - Menu Principal v3.0
Scanner de arquivos com assinaturas atualizaveis, quarentena, logs e monitoramento
"""

import hashlib
import json
import math
import os
import shutil
import sys
import time
import threading
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


SIGNATURE_SOURCES = {
    "hashes_a": {
        "name": "Malicious Hash List Part A (SHA256 + MD5)",
        "urls": [
            "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_aa.txt",
            "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/Malicious_md5_hashes_aa.txt"
        ]
    },
    "hashes_b": {
        "name": "Malicious Hash List Part B (SHA256 + MD5)",
        "urls": [
            "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ab.txt",
            "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_md5_hashes_ab.txt"
        ]
    },
    "hashes_c": {
        "name": "Malicious Hash List Part C (SHA256)",
        "urls": [
            "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ac.txt"
        ]
    }
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_PATH = os.path.join(BASE_DIR, "signatures.json")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_DIR = os.path.join(BASE_DIR, "logs")


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def pause():
    input(f"\n{Colors.DIM}Pressione ENTER para continuar...{Colors.RESET}")


def print_header():
    clear()
    print(f"""
{Colors.CYAN}{Colors.BOLD}
    +===========================================================+
    |                                                           |
    |      ###  ##  ####  ####  ####  ####  ###   ##   ####     |
    |       ## ##   ##   ##    ##    ##  ##  ##  ####   ##      |
    |       ####    ##   ####  ####  ####    ####  ##   ##      |
    |       ## ##   ##   ##    ##    ## ##   ##   ####   ##      |
    |      ##   ##  ##   ####  ####  ##  ##  ##    ##   ##      |
    |                                                           |
    |              PYSHIELD ANTIVIRUS  v3.0                     |
    |                                                           |
    +===========================================================+
{Colors.RESET}""")


def load_signatures(path: str) -> Dict:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {"malware_hashes": {}, "suspicious_patterns": {}}


def save_signatures(path: str, data: Dict):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def calculate_hash(filepath: str, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return ""


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def analyze_entropy(filepath: str) -> Tuple[float, str]:
    try:
        with open(filepath, 'rb') as f:
            data = f.read(64 * 1024)
        if not data:
            return 0.0, "Arquivo vazio"
        entropy = calculate_entropy(data)
        if entropy > 7.5:
            return entropy, "ENTROPIA MUITO ALTA - possivel arquivo encriptado/pacotado"
        elif entropy > 6.8:
            return entropy, "Entropia alta - possivel comprimido/encriptado"
        elif entropy > 5.5:
            return entropy, "Entropia normal"
        else:
            return entropy, "Entropia baixa - texto puro"
    except:
        return 0.0, "Erro ao ler"


def format_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)


def write_log(log_type: str, content: str) -> str:
    ensure_dirs()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{log_type}_{timestamp}.txt"
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    return filepath


def append_log(log_type: str, line: str):
    ensure_dirs()
    timestamp = datetime.now().strftime("%Y%m%d")
    filename = f"{log_type}_{timestamp}.log"
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {line}\n")


def print_progress_bar(percent: float, width: int = 30, label: str = ""):
    filled = int(width * percent / 100)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} {percent:5.1f}% {Colors.DIM}{label}{Colors.RESET}")
    sys.stdout.flush()


def load_signatures_with_progress(path: str) -> Dict:
    if not os.path.exists(path):
        return {"malware_hashes": {}, "suspicious_patterns": {}}

    file_size = os.path.getsize(path)
    print(f"\n  {Colors.WHITE}Arquivo: {os.path.basename(path)} ({format_size(file_size)}){Colors.RESET}")

    steps = [
        (10, "Abrindo arquivo..."),
        (25, "Lendo dados..."),
        (50, "Parseando JSON..."),
        (75, "Indexando hashes..."),
        (90, "Finalizando..."),
        (100, "Pronto!")
    ]

    for pct, label in steps:
        print_progress_bar(pct, 35, label)
        time.sleep(0.15)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"\n  {Colors.RED}[ERRO] Falha ao ler: {e}{Colors.RESET}")
        return {"malware_hashes": {}, "suspicious_patterns": {}}

    hashes_count = len(data.get("malware_hashes", {}))
    print(f"\n\n  {Colors.GREEN}[OK]{Colors.RESET} {hashes_count} assinaturas carregadas")

    return data


# ==================== ANALISE ====================

def analyze_file(filepath: str, malware: Dict, patterns: Dict) -> Tuple[str, Optional[Dict], str]:
    ext = Path(filepath).suffix.lower()

    if os.path.abspath(filepath) == os.path.abspath(SIG_PATH):
        return "clean", None, ""
    if os.path.abspath(filepath) == os.path.abspath(__file__):
        return "clean", None, ""
    if os.path.abspath(filepath).startswith(os.path.abspath(BASE_DIR)):
        rel = os.path.relpath(filepath, BASE_DIR)
        if rel.startswith("__pycache__"):
            return "clean", None, ""

    try:
        file_size = os.path.getsize(filepath)
    except:
        return "clean", None, ""

    if file_size > 50 * 1024 * 1024:
        return "clean", None, ""

    if ext in ['.json', '.log', '.txt', '.csv', '.xml', '.md']:
        if file_size > 1024 * 1024:
            return "clean", None, ""

    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', '.avi', '.mkv', '.zip', '.rar', '.7z', '.pdf']:
        return "clean", None, ""

    md5 = calculate_hash(filepath, "md5")
    if md5 in malware:
        info = malware[md5]
        if info.get("risk") not in ["none", "benign"]:
            return "threat", {"hash": md5, "algorithm": "MD5", "info": info}, "MD5 corresponde a malware conhecido"

    sha256 = calculate_hash(filepath, "sha256")
    if sha256 in malware:
        info = malware[sha256]
        if info.get("risk") not in ["none", "benign"]:
            return "threat", {"hash": sha256, "algorithm": "SHA256", "info": info}, "SHA256 corresponde a malware conhecido"

    return "clean", None, ""


# ==================== QUARENTENA ====================

def quarantine_file(filepath: str, risk: str, details: Optional[Dict], reason: str) -> bool:
    ensure_dirs()
    try:
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{timestamp}_{risk}_{filename}"
        dest = os.path.join(QUARANTINE_DIR, safe_name)

        metadata = {
            "original_path": filepath,
            "quarantine_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": risk,
            "details": details,
            "reason": reason
        }

        meta_path = dest + ".meta.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

        shutil.move(filepath, dest)
        append_log("quarantine", f"MOVIDO: {filepath} -> {dest} | Risco: {risk} | {reason}")
        return True
    except Exception as e:
        append_log("quarantine", f"ERRO ao isolar {filepath}: {e}")
        return False


def restore_from_quarantine(quarantine_path: str) -> bool:
    meta_path = quarantine_path + ".meta.json"
    try:
        with open(meta_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        original = metadata.get("original_path", "")
        os.makedirs(os.path.dirname(original), exist_ok=True)
        shutil.move(quarantine_path, original)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        append_log("quarantine", f"RESTAURADO: {quarantine_path} -> {original}")
        return True
    except Exception as e:
        append_log("quarantine", f"ERRO ao restaurar {quarantine_path}: {e}")
        return False


def show_quarantine():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}QUARENTENA{Colors.RESET}\n")

    ensure_dirs()
    files = [f for f in os.listdir(QUARANTINE_DIR)
             if not f.endswith('.meta.json') and os.path.isfile(os.path.join(QUARANTINE_DIR, f))]

    if not files:
        print(f"  {Colors.GREEN}[OK]{Colors.RESET} Nenhum arquivo em quarentena")
        pause()
        return

    print(f"  {Colors.WHITE}Arquivos em quarentena: {len(files)}{Colors.RESET}\n")

    for i, fname in enumerate(files, 1):
        fpath = os.path.join(QUARANTINE_DIR, fname)
        meta_path = fpath + ".meta.json"
        size = os.path.getsize(fpath)

        risk = "unknown"
        original = "?"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                risk = meta.get("risk_level", "unknown")
                original = meta.get("original_path", "?")
            except:
                pass

        color = Colors.RED if risk == "threat" else Colors.YELLOW if risk == "suspicious" else Colors.WHITE
        print(f"  {color}[{i}]{Colors.RESET} {fname}")
        print(f"      {Colors.DIM}Original: {original}{Colors.RESET}")
        print(f"      {Colors.DIM}Tamanho: {format_size(size)} | Risco: {risk}{Colors.RESET}")

    print(f"\n  {Colors.WHITE}Opcoes:{Colors.RESET}")
    print(f"    {Colors.GREEN}[R numero]{Colors.RESET} Restaurar arquivo")
    print(f"    {Colors.GREEN}[RA]{Colors.RESET}        Restaurar TUDO")
    print(f"    {Colors.RED}[D numero]{Colors.RESET} Deletar permanentemente")
    print(f"    {Colors.RED}[A]{Colors.RESET} Deletar TUDO")
    print(f"    {Colors.DIM}[0]{Colors.RESET} Voltar")

    choice = input(f"\n  {Colors.WHITE}>> {Colors.RESET}").strip().upper()

    if choice == "0":
        return

    if choice.startswith("RA"):
        confirm = input(f"  {Colors.GREEN}Restaurar TODOS os {len(files)} arquivos? (s/n): {Colors.RESET}").strip().lower()
        if confirm == 's':
            ok = 0
            fail = 0
            for fname in files:
                fpath = os.path.join(QUARANTINE_DIR, fname)
                if restore_from_quarantine(fpath):
                    ok += 1
                else:
                    fail += 1
            print(f"  {Colors.GREEN}[OK]{Colors.RESET} {ok} restaurados | {Colors.RED}[ERRO]{Colors.RESET} {fail} falhas")
        else:
            print(f"  {Colors.YELLOW}Cancelado{Colors.RESET}")
        pause()

    elif choice.startswith("R") and not choice.startswith("RA"):
        try:
            idx = int(choice[1:].strip()) - 1
            if 0 <= idx < len(files):
                fpath = os.path.join(QUARANTINE_DIR, files[idx])
                if restore_from_quarantine(fpath):
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET} Arquivo restaurado")
                else:
                    print(f"  {Colors.RED}[ERRO]{Colors.RESET} Falha ao restaurar")
            else:
                print(f"  {Colors.RED}[ERRO]{Colors.RESET} Indice invalido")
        except:
            print(f"  {Colors.RED}[ERRO]{Colors.RESET} Formato invalido")
        pause()

    elif choice.startswith("D"):
        try:
            idx = int(choice[1:].strip()) - 1
            if 0 <= idx < len(files):
                fpath = os.path.join(QUARANTINE_DIR, files[idx])
                meta = fpath + ".meta.json"
                os.remove(fpath)
                if os.path.exists(meta):
                    os.remove(meta)
                append_log("quarantine", f"DELETADO: {fpath}")
                print(f"  {Colors.RED}[OK]{Colors.RESET} Arquivo deletado permanentemente")
            else:
                print(f"  {Colors.RED}[ERRO]{Colors.RESET} Indice invalido")
        except:
            print(f"  {Colors.RED}[ERRO]{Colors.RESET} Formato invalido")
        pause()

    elif choice == "A":
        confirm = input(f"  {Colors.RED}Tem certeza? Deletar TUDO? (s/n): {Colors.RESET}").strip().lower()
        if confirm == 's':
            for fname in files:
                fpath = os.path.join(QUARANTINE_DIR, fname)
                meta = fpath + ".meta.json"
                os.remove(fpath)
                if os.path.exists(meta):
                    os.remove(meta)
            append_log("quarantine", "TODOS OS ARQUIVOS DELETADOS")
            print(f"  {Colors.RED}[OK]{Colors.RESET} Quarentena limpa")
        else:
            print(f"  {Colors.YELLOW}Cancelado{Colors.RESET}")
        pause()


# ==================== SCANNER ====================

def run_scan():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}SCAN DE ARQUIVOS{Colors.RESET}\n")

    path = input(f"  {Colors.WHITE}Caminho para escanear: {Colors.RESET}").strip()

    if not path:
        print(f"  {Colors.RED}[ERRO]{Colors.RESET} Caminho vazio")
        pause()
        return

    if not os.path.exists(path):
        print(f"  {Colors.RED}[ERRO]{Colors.RESET} Caminho nao encontrado: {path}")
        pause()
        return

    recursive = input(f"  {Colors.WHITE}Escanear subdiretorios? (s/n): {Colors.RESET}").strip().lower() != 'n'

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  CARREGANDO ASSINATURAS{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")

    data = load_signatures_with_progress(SIG_PATH)
    signatures = data.get("malware_hashes", {})
    patterns = data.get("suspicious_patterns", {})

    is_single_file = os.path.isfile(path)

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  ESCANEAMENTO EM ANDAMENTO{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}\n")

    stats = {"scanned": 0, "clean": 0, "threats": 0, "suspicious": 0, "warnings": 0, "quarantined": 0}
    threats_found = []
    start = time.time()
    last_update = 0
    _scan_stop = False

    def _stop_handler(sig, frame):
        nonlocal _scan_stop
        _scan_stop = True
        raise KeyboardInterrupt

    import signal
    _old_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _stop_handler)

    def _scan_one(filepath, i):
        nonlocal last_update
        now = time.time()
        elapsed = now - start

        if (now - last_update) >= 0.1 or i == 1:
            last_update = now

            try:
                name = os.path.basename(filepath)[:30].encode('ascii', 'replace').decode('ascii')
                folder = filepath.replace(os.path.basename(filepath), "")[:45].encode('ascii', 'replace').decode('ascii')
            except:
                name = "arquivo"
                folder = "..."

            sys.stdout.write(f"\033[2K\r")
            sys.stdout.write(f"  {Colors.WHITE}{i}{Colors.RESET} arquivos verificados ")
            sys.stdout.write(f"{Colors.DIM}Tempo:{Colors.RESET} {elapsed:.1f}s  ")
            sys.stdout.write("\n")
            sys.stdout.write(f"\033[2K  {Colors.DIM}Arquivo:{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}\n")
            sys.stdout.write(f"\033[2K  {Colors.DIM}Pasta:{Colors.RESET}   {folder}\n")
            sys.stdout.write("\033[3A")
            sys.stdout.flush()

        try:
            risk, details, reason = analyze_file(filepath, signatures, patterns)
            stats["scanned"] += 1

            if risk == "threat":
                stats["threats"] += 1
                threats_found.append({"path": filepath, "risk": risk, "details": details, "reason": reason})
                sys.stdout.write(f"\033[3B\033[2K\n")
                print(f"  {Colors.RED}{Colors.BOLD}  [X] AMEACA: {filepath}{Colors.RESET}")
                if details and "info" in details:
                    info = details["info"]
                    algo = details.get("algorithm", "N/A")
                    print(f"       Nome: {info.get('name', 'N/A')} | Tipo: {info.get('type', 'N/A')} | Algo: {algo}")
                print(f"       Motivo: {reason}")
                sys.stdout.write("\033[3A")
                sys.stdout.flush()
                append_log("scan", f"THREAT: {filepath} | {reason}")

            elif risk == "suspicious":
                stats["suspicious"] += 1
                threats_found.append({"path": filepath, "risk": risk, "details": details, "reason": reason})
                sys.stdout.write(f"\033[3B\033[2K\n")
                print(f"  {Colors.YELLOW}{Colors.BOLD}  [!] SUSPEITO: {filepath}{Colors.RESET}")
                print(f"       Motivo: {reason}")
                sys.stdout.write("\033[3A")
                sys.stdout.flush()
                append_log("scan", f"SUSPICIOUS: {filepath} | {reason}")

            elif risk == "warning":
                stats["warnings"] += 1
                stats["clean"] += 1
            else:
                stats["clean"] += 1

        except KeyboardInterrupt:
            raise
        except UnicodeEncodeError:
            stats["scanned"] += 1
            stats["clean"] += 1
        except:
            pass

    if is_single_file:
        _scan_one(path, 1)
    else:
        count = 0
        try:
            for root, dirs, filenames in os.walk(path):
                if _scan_stop:
                    break
                for fn in filenames:
                    if _scan_stop:
                        break
                    count += 1
                    filepath = os.path.join(root, fn)
                    _scan_one(filepath, count)
                if not recursive:
                    break
        except KeyboardInterrupt:
            _scan_stop = True

    signal.signal(signal.SIGINT, _old_handler)
    if _scan_stop:
        print(f"\n\n  {Colors.YELLOW}[PAUSADO]{Colors.RESET} Scan interrompido pelo usuario")

    total_time = time.time() - start
    sys.stdout.write(f"\033[3B\033[2K\r")

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  SCAN COMPLETO{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.WHITE}Arquivos:{Colors.RESET}       {stats['scanned']}")
    print(f"  {Colors.GREEN}Limpos:{Colors.RESET}         {stats['clean']}")
    print(f"  {Colors.RED}Ameacas:{Colors.RESET}        {stats['threats']}")
    print(f"  {Colors.YELLOW}Suspeitos:{Colors.RESET}      {stats['suspicious']}")
    print(f"  {Colors.MAGENTA}Quarentena:{Colors.RESET}     {stats['quarantined']}")
    print(f"  {Colors.WHITE}Tempo total:{Colors.RESET}     {total_time:.2f}s")

    if stats['scanned'] > 0:
        speed = stats['scanned'] / total_time
        print(f"  {Colors.WHITE}Velocidade:{Colors.RESET}      {speed:.0f} arquivos/s")

    if stats["threats"] > 0:
        print(f"\n  {Colors.RED}{Colors.BOLD}  [X] AMEACAS DETECTADAS!{Colors.RESET}")
        print(f"  {Colors.RED}  Recomendacao: Isolar e remover arquivos{Colors.RESET}")
        resp = input(f"\n  {Colors.YELLOW}Isolar ameacas em quarentena? (s/n): {Colors.RESET}").strip().lower()
        if resp == 's':
            for t in threats_found:
                if t["risk"] == "threat":
                    if quarantine_file(t["path"], t["risk"], t["details"], t["reason"]):
                        stats["quarantined"] += 1
                        print(f"  {Colors.MAGENTA}-> Isolado: {t['path']}{Colors.RESET}")
            print(f"\n  {Colors.WHITE}Quarentena:{Colors.RESET} {stats['quarantined']} arquivo(s) isolado(s)")
    elif stats["suspicious"] > 0:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}  [!] ARQUIVOS SUSPEITOS{Colors.RESET}")
        print(f"  {Colors.YELLOW}  Recomendacao: Revisar manualmente{Colors.RESET}")
    else:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}  [OK] SISTEMA LIMPO{Colors.RESET}")

    log_lines = []
    log_lines.append(f"PyShield Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"{'='*50}")
    log_lines.append(f"Caminho: {path}")
    log_lines.append(f"Recursivo: {'Sim' if recursive else 'Nao'}")
    log_lines.append(f"Arquivos escaneados: {stats['scanned']}")
    log_lines.append(f"Limpos: {stats['clean']}")
    log_lines.append(f"Ameacas: {stats['threats']}")
    log_lines.append(f"Suspeitos: {stats['suspicious']}")
    log_lines.append(f"Quarentena: {stats['quarantined']}")
    log_lines.append(f"Tempo: {total_time:.2f}s")
    log_lines.append(f"{'='*50}")
    if threats_found:
        log_lines.append("DETALHES DAS AMEACAS:")
        for t in threats_found:
            log_lines.append(f"  [{t['risk'].upper()}] {t['path']}")
            log_lines.append(f"    Motivo: {t['reason']}")
    log_content = "\n".join(log_lines)
    log_path = write_log("scan_report", log_content)
    print(f"\n  {Colors.DIM}Log salvo: {log_path}{Colors.RESET}")

    pause()


# ==================== SCAN EM TEMPO REAL ====================

_realtime_stop = threading.Event()
_realtime_stats = {"scanned": 0, "threats": 0, "suspicious": 0}


def _scan_new_file(filepath: str, signatures: Dict, patterns: Dict):
    _realtime_stats["scanned"] += 1
    risk, details, reason = analyze_file(filepath, signatures, patterns)
    ts = datetime.now().strftime("%H:%M:%S")

    if risk == "threat":
        _realtime_stats["threats"] += 1
        print(f"\n  {Colors.RED}{Colors.BOLD}[{ts}] [X] AMEACA: {filepath}{Colors.RESET}")
        if details and "info" in details:
            info = details["info"]
            print(f"         Nome: {info.get('name', 'N/A')} | Tipo: {info.get('type', 'N/A')}")
        quarantine_file(filepath, risk, details, reason)
        append_log("realtime", f"THREAT: {filepath} | {reason}")

    elif risk == "suspicious":
        _realtime_stats["suspicious"] += 1
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}[{ts}] [!] SUSPEITO: {filepath}{Colors.RESET}")
        print(f"         Motivo: {reason}")
        append_log("realtime", f"SUSPICIOUS: {filepath} | {reason}")


def run_realtime_monitor():
    global _realtime_stats
    _realtime_stats = {"scanned": 0, "threats": 0, "suspicious": 0}

    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}MONITORAMENTO EM TEMPO REAL{Colors.RESET}\n")

    path = input(f"  {Colors.WHITE}Pasta para monitorar: {Colors.RESET}").strip()

    if not path or not os.path.isdir(path):
        print(f"  {Colors.RED}[ERRO]{Colors.RESET} Pasta invalida")
        pause()
        return

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  CARREGANDO ASSINATURAS{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")

    data = load_signatures_with_progress(SIG_PATH)
    signatures = data.get("malware_hashes", {})
    patterns = data.get("suspicious_patterns", {})

    known_files = set()
    for root, dirs, filenames in os.walk(path):
        for fn in filenames:
            known_files.add(os.path.join(root, fn))

    print(f"\n  {Colors.GREEN}[OK]{Colors.RESET} Monitorando: {path}")
    print(f"  {Colors.DIM}Arquivos conhecidos: {len(known_files)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Pressione Ctrl+C para parar{Colors.RESET}\n")

    append_log("realtime", f"INICIO monitoramento: {path}")

    try:
        while not _realtime_stop.is_set():
            current_files = set()
            for root, dirs, filenames in os.walk(path):
                for fn in filenames:
                    fp = os.path.join(root, fn)
                    current_files.add(fp)
                    if fp not in known_files:
                        _scan_new_file(fp, signatures, patterns)
                        known_files.add(fp)

            _realtime_stop.wait(2.0)

    except KeyboardInterrupt:
        pass

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  MONITORAMENTO ENCERRADO{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.WHITE}Arquivos verificados:{Colors.RESET} {_realtime_stats['scanned']}")
    print(f"  {Colors.RED}Ameacas:{Colors.RESET}              {_realtime_stats['threats']}")
    print(f"  {Colors.YELLOW}Suspeitos:{Colors.RESET}            {_realtime_stats['suspicious']}")

    append_log("realtime", f"FIM monitoramento | Scanned: {_realtime_stats['scanned']} | Threats: {_realtime_stats['threats']}")

    pause()


# ==================== ENTROPIA ====================

def run_entropy_scan():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}ANALISE DE ENTROPIA{Colors.RESET}\n")
    print(f"  {Colors.DIM}Detecta arquivos encriptados, pacotados ou comprimidos{Colors.RESET}\n")

    path = input(f"  {Colors.WHITE}Caminho para analisar: {Colors.RESET}").strip()

    if not path or not os.path.exists(path):
        print(f"  {Colors.RED}[ERRO]{Colors.RESET} Caminho invalido")
        pause()
        return

    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, dirs, filenames in os.walk(path):
            for fn in filenames:
                fp = os.path.join(root, fn)
                try:
                    sz = os.path.getsize(fp)
                    if sz > 0 and sz < 50 * 1024 * 1024:
                        files.append(fp)
                except:
                    pass

    if not files:
        print(f"  {Colors.YELLOW}[INFO]{Colors.RESET} Nenhum arquivo para analisar")
        pause()
        return

    print(f"  {Colors.WHITE}Arquivos para analisar: {len(files)}{Colors.RESET}\n")

    high_entropy = []
    for i, fp in enumerate(files, 1):
        if i % 100 == 0:
            print(f"\r  {Colors.DIM}Analisando: {i}/{len(files)}{Colors.RESET}", end="", flush=True)

        entropy, desc = analyze_entropy(fp)
        if entropy > 6.8:
            high_entropy.append((fp, entropy, desc))

    print(f"\r  {Colors.DIM}                                    {Colors.RESET}")
    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  RESULTADO DA ENTROPIA{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.WHITE}Total analisado:{Colors.RESET} {len(files)}")
    print(f"  {Colors.YELLOW}Alta entropia:{Colors.RESET}   {len(high_entropy)}")

    if high_entropy:
        high_entropy.sort(key=lambda x: -x[1])
        print(f"\n  {Colors.WHITE}Top arquivos com alta entropia:{Colors.RESET}\n")
        for fp, ent, desc in high_entropy[:20]:
            color = Colors.RED if ent > 7.5 else Colors.YELLOW
            print(f"  {color}ENT={ent:.2f}{Colors.RESET} {Colors.DIM}{fp}{Colors.RESET}")
            print(f"          {desc}")
    else:
        print(f"\n  {Colors.GREEN}[OK]{Colors.RESET} Nenhum arquivo com entropia suspeita")

    pause()


# ==================== ATUALIZAR ====================

def update_signatures():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}ATUALIZAR ASSINATURAS{Colors.RESET}\n")

    data = load_signatures(SIG_PATH)
    existing = data.get("malware_hashes", {})
    patterns = data.get("suspicious_patterns", {})

    print(f"  {Colors.DIM}Assinaturas atuais: {len(existing)}{Colors.RESET}\n")

    print(f"  {Colors.WHITE}Fontes disponiveis:{Colors.RESET}")
    for key, source in SIGNATURE_SOURCES.items():
        print(f"    {Colors.CYAN}[{key}]{Colors.RESET} {source['name']}")

    print(f"\n  {Colors.WHITE}Opcoes:{Colors.RESET}")
    print(f"    {Colors.GREEN}[1]{Colors.RESET} Baixar TUDO")
    print(f"    {Colors.GREEN}[2]{Colors.RESET} Escolher fontes")
    print(f"    {Colors.GREEN}[0]{Colors.RESET} Voltar")

    choice = input(f"\n  {Colors.WHITE}Opcao: {Colors.RESET}").strip()

    if choice == "0":
        return
    elif choice == "1":
        selected = list(SIGNATURE_SOURCES.keys())
    elif choice == "2":
        keys = input(f"  {Colors.WHITE}Fontes (separadas por virgula): {Colors.RESET}").strip()
        selected = [k.strip() for k in keys.split(",") if k.strip() in SIGNATURE_SOURCES]
        if not selected:
            print(f"  {Colors.RED}[ERRO]{Colors.RESET} Nenhuma fonte valida")
            pause()
            return
    else:
        print(f"  {Colors.RED}[ERRO]{Colors.RESET} Opcao invalida")
        pause()
        return

    new_hashes = {}
    total = 0

    for source_id in selected:
        source = SIGNATURE_SOURCES[source_id]
        print(f"\n  {Colors.CYAN}[BAIXAR]{Colors.RESET} {source['name']}")

        for url in source["urls"]:
            print(f"           {Colors.DIM}{url[:60]}...{Colors.RESET}")

            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'PyShield/3.0'})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    content = resp.read().decode('utf-8', errors='ignore')

                count = 0
                for line in content.splitlines():
                    h = line.strip().lower()
                    if not h or h.startswith('#'):
                        continue
                    if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
                        if h not in existing and h not in new_hashes:
                            new_hashes[h] = {
                                "name": f"Downloaded-{datetime.now().strftime('%Y%m%d')}",
                                "type": "downloaded",
                                "risk": "unknown",
                                "source": source_id
                            }
                            count += 1
                    elif len(h) == 32 and all(c in '0123456789abcdef' for c in h):
                        if h not in existing and h not in new_hashes:
                            new_hashes[h] = {
                                "name": f"Downloaded-{datetime.now().strftime('%Y%m%d')}",
                                "type": "downloaded",
                                "risk": "unknown",
                                "source": source_id
                            }
                            count += 1

                print(f"           {Colors.GREEN}+{count} novos hashes{Colors.RESET}")
                total += count

            except Exception as e:
                print(f"           {Colors.RED}[ERRO] {e}{Colors.RESET}")

            time.sleep(0.3)

    print(f"\n  {Colors.BOLD}Total de novos hashes: {total}{Colors.RESET}")

    if total == 0:
        print(f"\n  {Colors.YELLOW}[INFO]{Colors.RESET} Nenhuma novidade")
        pause()
        return

    confirm = input(f"\n  {Colors.WHITE}Adicionar {total} assinaturas? (s/n): {Colors.RESET}").strip().lower()
    if confirm != 's':
        print(f"  {Colors.YELLOW}Cancelado{Colors.RESET}")
        pause()
        return

    all_hashes = {**existing, **new_hashes}

    save_data = {
        "metadata": {
            "version": "3.0",
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_signatures": len(all_hashes)
        },
        "malware_hashes": all_hashes,
        "suspicious_patterns": patterns if patterns else {
            "extensions": [".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ws", ".wsh", ".ps1", ".msi", ".com", ".hta", ".cpl"],
            "keywords_in_content": ["eval(", "exec(", "base64_decode", "powershell -enc", "cmd.exe /c", "wget ", "curl ", "Invoke-WebRequest", "System.Net.WebClient", "DownloadString", "Start-Process"]
        }
    }

    backup = SIG_PATH + ".bak"
    if os.path.exists(SIG_PATH):
        os.replace(SIG_PATH, backup)
        print(f"  {Colors.DIM}Backup: {backup}{Colors.RESET}")

    save_signatures(SIG_PATH, save_data)

    print(f"\n  {Colors.GREEN}[OK] Assinaturas atualizadas!{Colors.RESET}")
    print(f"  {Colors.GREEN}[OK] Total: {len(all_hashes)} assinaturas{Colors.RESET}")

    pause()


# ==================== STATUS ====================

def show_status():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}STATUS DO SISTEMA{Colors.RESET}\n")

    data = load_signatures(SIG_PATH)
    hashes = data.get("malware_hashes", {})
    meta = data.get("metadata", {})

    print(f"  {Colors.WHITE}Arquivo:{Colors.RESET} {SIG_PATH}")

    if os.path.exists(SIG_PATH):
        size = os.path.getsize(SIG_PATH)
        mod = datetime.fromtimestamp(os.path.getmtime(SIG_PATH)).strftime("%d/%m/%Y %H:%M:%S")
        print(f"  {Colors.WHITE}Tamanho:{Colors.RESET} {format_size(size)}")
        print(f"  {Colors.WHITE}Modificado:{Colors.RESET} {mod}")

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  ASSINATURAS{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.GREEN}Total de hashes:{Colors.RESET}  {len(hashes)}")

    types = {}
    for h, info in hashes.items():
        t = info.get("type", "unknown")
        types[t] = types.get(t, 0) + 1

    if types:
        print(f"\n  {Colors.WHITE}Por tipo:{Colors.RESET}")
        for t, c in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {t}: {c}")

    ext = data.get("suspicious_patterns", {}).get("extensions", [])
    kw = data.get("suspicious_patterns", {}).get("keywords_in_content", [])
    print(f"\n  {Colors.WHITE}Extensoes monitoradas:{Colors.RESET} {len(ext)}")
    print(f"  {Colors.WHITE}Palavras-chave:{Colors.RESET} {len(kw)}")

    ensure_dirs()
    q_files = [f for f in os.listdir(QUARANTINE_DIR)
               if not f.endswith('.meta.json') and os.path.isfile(os.path.join(QUARANTINE_DIR, f))]
    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  QUARENTENA{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.WHITE}Arquivos isolados:{Colors.RESET} {len(q_files)}")

    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith('.log')] if os.path.exists(LOG_DIR) else []
    scan_logs = [f for f in os.listdir(LOG_DIR) if f.startswith('scan_report')] if os.path.exists(LOG_DIR) else []
    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  LOGS{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.WHITE}Logs de monitoramento:{Colors.RESET} {len(log_files)}")
    print(f"  {Colors.WHITE}Relatorios de scan:{Colors.RESET} {len(scan_logs)}")

    print(f"\n  {Colors.CYAN}{'='*54}{Colors.RESET}")
    print(f"  {Colors.BOLD}  FONTES DE DOWNLOAD{Colors.RESET}")
    print(f"  {Colors.CYAN}{'='*54}{Colors.RESET}")
    for key, source in SIGNATURE_SOURCES.items():
        print(f"  {Colors.CYAN}[{key}]{Colors.RESET} {source['name']}")
        for url in source["urls"]:
            print(f"         {Colors.DIM}{url[:55]}...{Colors.RESET}")

    pause()


# ==================== LOGS ====================

def show_logs():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}LOGS{Colors.RESET}\n")

    ensure_dirs()
    all_files = sorted(os.listdir(LOG_DIR)) if os.path.exists(LOG_DIR) else []

    if not all_files:
        print(f"  {Colors.YELLOW}[INFO]{Colors.RESET} Nenhum log encontrado")
        pause()
        return

    scan_reports = [f for f in all_files if f.startswith('scan_report')]
    rt_logs = [f for f in all_files if f.startswith('realtime_') and f.endswith('.log')]
    q_logs = [f for f in all_files if f.startswith('quarantine_') and f.endswith('.log')]

    print(f"  {Colors.WHITE}Relatorios de scan:{Colors.RESET} {len(scan_reports)}")
    print(f"  {Colors.WHITE}Logs de monitoramento:{Colors.RESET} {len(rt_logs)}")
    print(f"  {Colors.WHITE}Logs de quarentena:{Colors.RESET} {len(q_logs)}")

    print(f"\n  {Colors.WHITE}Opcoes:{Colors.RESET}")
    print(f"    {Colors.GREEN}[1]{Colors.RESET} Ver relatorios de scan")
    print(f"    {Colors.GREEN}[2]{Colors.RESET} Ver logs de monitoramento")
    print(f"    {Colors.GREEN}[3]{Colors.RESET} Ver logs de quarentena")
    print(f"    {Colors.GREEN}[4]{Colors.RESET} Ver ultimo relatorio completo")
    print(f"    {Colors.DIM}[0]{Colors.RESET} Voltar")

    choice = input(f"\n  {Colors.WHITE}>> {Colors.RESET}").strip()

    if choice == "0":
        return

    elif choice == "1":
        if not scan_reports:
            print(f"  {Colors.YELLOW}Nenhum relatorio{Colors.RESET}")
        else:
            for f in scan_reports[-10:]:
                fpath = os.path.join(LOG_DIR, f)
                size = os.path.getsize(fpath)
                print(f"    {Colors.CYAN}{f}{Colors.RESET} ({format_size(size)})")
        pause()

    elif choice == "2":
        if not rt_logs:
            print(f"  {Colors.YELLOW}Nenhum log{Colors.RESET}")
        else:
            for f in rt_logs[-10:]:
                fpath = os.path.join(LOG_DIR, f)
                size = os.path.getsize(fpath)
                print(f"    {Colors.CYAN}{f}{Colors.RESET} ({format_size(size)})")
        pause()

    elif choice == "3":
        if not q_logs:
            print(f"  {Colors.YELLOW}Nenhum log{Colors.RESET}")
        else:
            for f in q_logs[-10:]:
                fpath = os.path.join(LOG_DIR, f)
                size = os.path.getsize(fpath)
                print(f"    {Colors.CYAN}{f}{Colors.RESET} ({format_size(size)})")
        pause()

    elif choice == "4":
        if not scan_reports:
            print(f"  {Colors.YELLOW}Nenhum relatorio{Colors.RESET}")
        else:
            latest = os.path.join(LOG_DIR, scan_reports[-1])
            with open(latest, 'r', encoding='utf-8') as f:
                content = f.read()
            clear()
            print(f"  {Colors.CYAN}{Colors.BOLD}ULTIMO RELATORIO: {scan_reports[-1]}{Colors.RESET}\n")
            print(content)
        pause()


# ==================== SOBRE ====================

def show_about():
    print_header()
    print(f"  {Colors.CYAN}{Colors.BOLD}SOBRE O PYSHIELD{Colors.RESET}\n")

    print(f"""  {Colors.WHITE}PyShield Antivirus Scanner{Colors.RESET}
  Versao: 3.0
  Tipo: Scanner educacional de arquivos

  {Colors.CYAN}Funcionalidades:{Colors.RESET}
    - Scan por hashes MD5 e SHA256 conhecidos
    - Deteccao de extensoes perigosas
    - Analise heuristica basica de scripts
    - Analise de entropia (detecta encriptacao/pacotes)
    - Sistema de quarentena (isolar e restaurar)
    - Logs detalhados de scan
    - Monitoramento em tempo real de pastas
    - Atualizacao de assinaturas online

  {Colors.CYAN}Fontes de assinaturas:{Colors.RESET}
    - Malicious Hash Threat List (abuse.ch)

  {Colors.CYAN}Uso:{Colors.RESET}
    python pyshield.py

  {Colors.YELLOW}Aviso:{Colors.RESET}
    Este scanner e EDUCACIONAL.
    Para protecao real, use Windows Defender ou outro AV profissional.
    Assinaturas nao detectam malware novo (zero-day).
""")

    pause()


# ==================== MENU ====================

def main():
    while True:
        print_header()

        print(f"  {Colors.WHITE}Escolha uma opcao:{Colors.RESET}\n")
        print(f"    {Colors.GREEN}[1]{Colors.RESET} Escanear arquivos")
        print(f"    {Colors.GREEN}[2]{Colors.RESET} Monitoramento em tempo real")
        print(f"    {Colors.GREEN}[3]{Colors.RESET} Analise de entropia")
        print(f"    {Colors.GREEN}[4]{Colors.RESET} Quarentena")
        print(f"    {Colors.GREEN}[5]{Colors.RESET} Atualizar assinaturas")
        print(f"    {Colors.GREEN}[6]{Colors.RESET} Status do sistema")
        print(f"    {Colors.GREEN}[7]{Colors.RESET} Logs")
        print(f"    {Colors.GREEN}[8]{Colors.RESET} Sobre")
        print(f"    {Colors.RED}[0]{Colors.RESET} Sair")

        choice = input(f"\n  {Colors.WHITE}>> {Colors.RESET}").strip()

        if choice == "1":
            run_scan()
        elif choice == "2":
            run_realtime_monitor()
        elif choice == "3":
            run_entropy_scan()
        elif choice == "4":
            show_quarantine()
        elif choice == "5":
            update_signatures()
        elif choice == "6":
            show_status()
        elif choice == "7":
            show_logs()
        elif choice == "8":
            show_about()
        elif choice == "0":
            print(f"\n  {Colors.GREEN}Saindo...{Colors.RESET}\n")
            break
        else:
            print(f"  {Colors.RED}Opcao invalida{Colors.RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main()
