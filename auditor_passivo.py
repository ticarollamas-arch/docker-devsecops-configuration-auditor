"""
Auditor de Configurações Docker DevSecOps
Ferramenta defensiva para análise de conformidade e higiene digital de arquivos Docker e Docker Compose.
"""
import os
import sys
import re
import json
import argparse

try:
    import yaml
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] Erro: Instale as dependências executando: pip install -r requirements.txt")
    sys.exit(1)

BANNER = """\033[36m
    ____             __              ____                  _____              
   / __ \____  _____/ /_____  _____ / __ \___ _   _______ / ___/____  ______ ___
  / / / / __ \/ ___/ //_/ _ \/ ___// / / / _ \ | / / ___/ \__ \/ __ \/ ___/ __ `/
 / /_/ / /_/ / /__/ ,< /  __/ /   / /_/ /  __/ |/ (__  ) ___/ / /_/ / /__/ /_/ / 
/_____/\____/\___/_/|_|\___/_/    /_____/\___/|___/____/ /____/\____/\___/\__,_/  
                                                                                  \033[0m"""

class DockerAuditor:
    def __init__(self):
        self.dockerfile_rules = self.load_rules("rules/dockerfile_rules.json")
        self.compose_rules = self.load_rules("rules/docker_compose_rules.json")
        self.findings = []

    def load_rules(self, path):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f).get("rules", [])
        return []

    def audit_dockerfile(self, filepath):
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[!] Arquivo Dockerfile não encontrado: {filepath}")
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines()

        # Regra DOCK-001: Tag latest ou ausente
        from_lines = [line for line in lines if line.strip().upper().startswith("FROM")]
        for line in from_lines:
            if ":latest" in line or ":" not in line:
                rule = next((r for r in self.dockerfile_rules if r["id"] == "DOCK-001"), None)
                if rule:
                    self.findings.append({"file": filepath, "line": line.strip(), "rule": rule})

        # Regra DOCK-002: Rodando como root (ausência de USER)
        has_user = any(line.strip().upper().startswith("USER") for line in lines)
        if not has_user:
            rule = next((r for r in self.dockerfile_rules if r["id"] == "DOCK-002"), None)
            if rule:
                self.findings.append({"file": filepath, "line": "N/A (Ausência da instrução USER)", "rule": rule})

        # Regra DOCK-003: Atualização sem limpeza de cache
        run_lines = [line for line in lines if line.strip().upper().startswith("RUN")]
        for line in run_lines:
            if ("apt-get upgrade" in line or "apt-get update" in line) and "rm -rf /var/lib/apt/lists" not in line:
                rule = next((r for r in self.dockerfile_rules if r["id"] == "DOCK-003"), None)
                if rule:
                    self.findings.append({"file": filepath, "line": line.strip(), "rule": rule})

    def audit_compose(self, filepath):
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[!] Arquivo Docker Compose não encontrado: {filepath}")
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"{Fore.RED}[!] Erro ao parsear YAML: {e}")
                return

        if not data or "services" not in data:
            return

        services = data.get("services", {})
        for service_name, config in services.items():
            # Regra COMP-001: Privileged
            if config.get("privileged") is True:
                rule = next((r for r in self.compose_rules if r["id"] == "COMP-001"), None)
                if rule:
                    self.findings.append({"file": filepath, "line": f"serviço: {service_name} (privileged: true)", "rule": rule})

            # Regra COMP-002: Portas expostas globalmente
            ports = config.get("ports", [])
            for port in ports:
                port_str = str(port)
                # Verifica se expõe portas sensíveis globalmente (ex: 0.0.0.0:22 ou apenas "22:22")
                sensitive_ports = ["22", "3306", "5432", "6379", "27017", "8080"]
                for sp in sensitive_ports:
                    if f":{sp}" in port_str or port_str.startswith(f"{sp}:"):
                        if "127.0.0.1" not in port_str:
                            rule = next((r for r in self.compose_rules if r["id"] == "COMP-002"), None)
                            if rule:
                                self.findings.append({"file": filepath, "line": f"serviço: {service_name} (porta: {port_str})", "rule": rule})

            # Regra COMP-003: docker.sock montado
            volumes = config.get("volumes", [])
            for vol in volumes:
                vol_str = str(vol)
                if "docker.sock" in vol_str:
                    rule = next((r for r in self.compose_rules if r["id"] == "COMP-003"), None)
                    if rule:
                        self.findings.append({"file": filepath, "line": f"serviço: {service_name} (volume: {vol_str})", "rule": rule})

    def print_report(self, json_output=False):
        if json_output:
            print(json.dumps(self.findings, indent=2, ensure_ascii=False))
            return

        print(f"\n{Fore.CYAN}=== RELATÓRIO DE AUDITORIA DE CONFORMIDADE ===\n")
        if not self.findings:
            print(f"{Fore.GREEN}[+] Nenhuma inconformidade crítica detectada! Excelente higiene digital.")
            return

        for finding in self.findings:
            severity = finding["rule"]["severity"]
            color = Fore.RED if severity in ["CRITICAL", "HIGH"] else (Fore.YELLOW if severity == "MEDIUM" else Fore.BLUE)
            
            print(f"{color}[{severity}] {finding['rule']['id']} - {finding['rule']['title']}")
            print(f"  {Fore.WHITE}Arquivo: {finding['file']}")
            print(f"  {Fore.WHITE}Trecho: {finding['line']}")
            print(f"  {Fore.WHITE}Descrição: {finding['rule']['description']}")
            print(f"  {Fore.GREEN}Correção: {finding['rule']['remediation']}")
            print(f"  {Fore.WHITE}CVSS: {finding['rule']['cvss']}")
            print("-" * 80)

        print(f"\n{Fore.YELLOW}[i] Total de inconformidades encontradas: {len(self.findings)}")

if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="Auditor de Configurações Docker DevSecOps")
    parser.add_argument("-d", "--dockerfile", help="Caminho do Dockerfile")
    parser.add_argument("-c", "--compose", help="Caminho do docker-compose.yml")
    parser.add_argument("-j", "--json", action="store_true", help="Saída em formato JSON")
    
    args = parser.parse_args()
    
    if not args.dockerfile and not args.compose:
        parser.print_help()
        sys.exit(1)
        
    auditor = DockerAuditor()
    
    if args.dockerfile:
        auditor.audit_dockerfile(args.dockerfile)
    if args.compose:
        auditor.audit_compose(args.compose)
        
    auditor.print_report(json_output=args.json)