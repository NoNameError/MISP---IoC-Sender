en-US

MISP IOC Automation Script
Automates the submission of IOCs (Indicators of Compromise) to a MISP instance, including custom pivoting-based data collection.
It connects to MISP via API, creates an event, and pushes IOCs (hashes, IPs, domains, etc.) automatically with proper type detection.

Features

Automated MISP event creation

IOC type auto-detection (IP, MD5, SHA1, SHA256, JA3)

Interactive IOC input

Ideal for CTI workflows and pivot-based infrastructure analysis

Usage

Configure your MISP credentials inside the script:

MISP_URL = "https://<your-misp-ip>"
MISP_KEY = "<your-api-key>"


Run:

python misp_ioc_automation.py

pt-BR

Automatiza o envio de IOCs (Indicadores de Comprometimento) para uma instância MISP, incluindo coleta personalizada baseada em pivoting.
O script conecta-se ao MISP via API, cria um evento e envia automaticamente os IOCs (hashes, IPs, domínios, etc.) com detecção apropriada de tipo.

Recursos

Criação automatizada de eventos no MISP

Detecção automática do tipo de IOC (MD5, SHA1, SHA256, JA3, texto)

Entrada interativa de IOCs

Ideal para fluxos de CTI e análises de infraestrutura maliciosa baseadas em pivoting

Uso

Configure suas credenciais do MISP dentro do script:

MISP_URL = "https://<seu-ip-do-misp>"
MISP_KEY = "<sua-api-key>"


Execute:

python misp_ioc_automation.py

