```
    ____             __              ____                  _____              
   / __ \____  _____/ /_____  _____ / __ \___ _   _______ / ___/____  ______ ___
  / / / / __ \/ ___/ //_/ _ \/ ___// / / / _ \ | / / ___/ \__ \/ __ \/ ___/ __ `/
 / /_/ / /_/ / /__/ ,< /  __/ /   / /_/ /  __/ |/ (__  ) ___/ / /_/ / /__/ /_/ / 
/_____/\____/\___/_/|_|\___/_/    /_____/\___/|___/____/ /____/\____/\___/\__,_/  
                                                                                  
```

# Docker DevSecOps Configuration Auditor

> **Objetivo:** Análise estática e passiva de arquivos de configuração Docker e Docker Compose para identificação de desvios de conformidade e riscos de segurança.

## Sobre o Projeto
Análise estática e passiva de arquivos de configuração Docker e Docker Compose para identificação de desvios de conformidade e riscos de segurança.

## 🛠️ Tecnologias e Módulos

- **Linguagens principais:** Python
- **Módulos nativos recomendados:** json, os, sys, re, argparse
- **Dependências Externas:**
  - `PyYAML` (^6.0.1): Análise estruturada e segura de arquivos docker-compose.yml
  - `colorama` (^0.4.6): Formatação visual e colorida dos relatórios de conformidade no terminal

## 🔒 Configurações de Segurança & Higiene Digital

- **Abordagem defensiva:** `DEFENSIVO`
- **Práticas de higiene digital:** Higiene digital e análise passiva de conformidade de infraestrutura
### Medidas de Mitigação Implementadas:
- **Risco / Ameaça:** Execução de comandos arbitrários via container comprometido → **Plano de Mitigação:** Forçar a diretiva USER não-root no Dockerfile
- **Risco / Ameaça:** Vulnerabilidades conhecidas em pacotes desatualizados → **Plano de Mitigação:** Fixar tags específicas e seguras de imagens base
- **Risco / Ameaça:** Exposição de portas administrativas para a internet → **Plano de Mitigação:** Auditar mapeamentos de portas no docker-compose.yml para evitar bind em 0.0.0.0

## 💻 Interface de Linha de Comando (CLI)

- **Pre-requisito / Comando:** `python auditor_passivo.py`
- **Instruções de Inicialização:** `python auditor_passivo.py --dockerfile <caminho> --compose <caminho>`
### Argumentos & Flags Configurados:
- `-d, --dockerfile` (string): Caminho para o arquivo Dockerfile a ser analisado (Exemplo: `--dockerfile ./Dockerfile`)
- `-c, --compose` (string): Caminho para o arquivo docker-compose.yml a ser analisado (Exemplo: `--compose ./docker-compose.yml`)
- `-j, --json` (flag): Exporta o resultado da análise em formato JSON estruturado (Exemplo: `--json`)

## 📂 Estrutura de Arquivos Criada

Este repositório foi construído de forma limpa e descompactada contendo os seguintes módulos funcionais:

- `rules/dockerfile_rules.json`
- `rules/docker_compose_rules.json`
- `auditor_passivo.py`
- `Dockerfile`
- `requirements.txt`
- `README.md`

---
*Blueprint gerado com orgulho através do Senior Software Architecture Hub no AI Studio.*