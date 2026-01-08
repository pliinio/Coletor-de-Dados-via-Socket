import socket
from datetime import datetime
import hashlib

TIMEOUT = 1

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

SENSITIVE_PORTS = [21, 23, 3389]


def identify_service(port):
    return COMMON_SERVICES.get(port, "Desconhecido")


def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))

        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "Não foi possível capturar o banner"

        sock.close()

        return {
            "porta": port,
            "servico": identify_service(port),
            "banner": banner,
            "sensivel": port in SENSITIVE_PORTS
        }

    except:
        return None


def generate_report(target, results):
    filename = f"relatorio_scan_{target.replace('.', '_')}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("==============================================\n")
        f.write(" RELATÓRIO DE ENUMERAÇÃO DE SERVIÇOS TCP\n")
        f.write("==============================================\n\n")

        f.write(f"Alvo analisado : {target}\n")
        f.write(f"Data do scan   : {datetime.now()}\n\n")

        f.write("----------------------------------------------\n")
        f.write(" PORTAS ABERTAS IDENTIFICADAS\n")
        f.write("----------------------------------------------\n\n")

        for r in results:
            f.write(f"[+] Porta: {r['porta']}\n")
            f.write(f"    Serviço : {r['servico']}\n")
            f.write(f"    Banner  : {r['banner']}\n")

            if r["sensivel"]:
                f.write("    ALERTA  : Serviço sensível exposto!\n")

            f.write("\n")

        f.write("----------------------------------------------\n")
        f.write(" RESUMO\n")
        f.write("----------------------------------------------\n")
        f.write(f"Total de portas abertas: {len(results)}\n\n")

        f.write("Observações:\n")
        f.write("- Este relatório foi gerado automaticamente por uma ferramenta Python\n")

    print(f"[✔] Relatório salvo como: {filename}")
    return filename


def generate_hash(filename):
    with open(filename, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"[✔] Hash SHA256 do relatório: {file_hash}")


# EXECUÇÃO

target = "exemplo.com"

ports_to_scan = [
    21, 22, 23, 25, 53, 80, 110,
    143, 443, 3306, 3389
]

print(f"\n[+] Iniciando scan em {target}...\n")

scan_results = []

for port in ports_to_scan:
    result = scan_port(target, port)
    if result:
        print(f"[ABERTA] Porta {port} ({result['servico']})")
        scan_results.append(result)

if scan_results:
    report_file = generate_report(target, scan_results)
    generate_hash(report_file)
else:
    print("\n[-] Nenhuma porta aberta encontrada.")
