# 🕵️ Packet Sniffer com Python + Scapy + Docker

Este projeto é um aplicativo simples de captura e análise de pacotes de rede. Ele permite que o usuário escolha uma interface de rede, defina a quantidade de pacotes a capturar e armazena os dados em um banco SQLite. O ambiente é isolado via Docker para facilitar a instalação e execução.

---

## 🚀 Funcionalidades

- Captura pacotes de rede em tempo real.
- Armazena IP de origem, destino, protocolo e tamanho no banco SQLite.
- Exibe estatísticas básicas:
- Total de pacotes
- Quantidade por protocolo (TCP, UDP, ICMP, etc.)
- IPs de origem e destino
- Executado em container Docker com rede real (host)
- Banco de dados salvo no host (`packets.db`)

---

## 🧰 Tecnologias Utilizadas

- Python 3.12
- [Scapy](https://scapy.net/)
- SQLite
- Docker / Docker Compose

---

## 📦 Requisitos

- Docker e Docker Compose instalados
- Permissões para executar containers com `NET_RAW` (ou `sudo`)
- Interface de rede com tráfego (ex: `eth0`, `wlp1s0`, etc.)

---

## 📁 Estrutura do Projeto

packet-sniffer/
├── sniffer.py
├── Dockerfile
├── docker-compose.yml
└── packets.db 

## 🛠️ Como Usar

```
1. Clone o repositório
bash
git clone https://github.com/seu-usuario/packet-sniffer.git
cd packet-sniffer


2. Construa a imagem Docker
bash
docker-compose build --no-cache


3. Execute o aplicativo
docker-compose run --rm sniffer

Informe:

Interface de rede (ex: wlp1s0)

Número de pacotes a capturar (ex: 50)

🔎 Consultar os Pacotes Capturados
Com o SQLite3 instalado:

bash
sqlite3 packets.db
Dentro do prompt SQLite:

sql
.tables
SELECT COUNT(*) FROM packets;
SELECT * FROM packets LIMIT 10;
.exit


🧹 Limpeza
Para remover containers órfãos:
bash
docker-compose down --remove-orphans

📌 Observações
O banco packets.db será salvo na pasta do projeto automaticamente.
É necessário rodar com permissões elevadas se for exigido pelo sistema para capturar pacotes.
A interface de rede pode ser verificada com ip link ou ifconfig.

🤝 Contribuição
Sinta-se livre para abrir issues ou enviar pull requests com melhorias, correções ou novas funcionalidades.
