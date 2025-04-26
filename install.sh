#!/bin/bash

# Script de instalação do MTM Agent
# Este script deve ser executado como root

# Verificar se está sendo executado como root
if [ "$(id -u)" != "0" ]; then
   echo "Este script deve ser executado como root" 1>&2
   exit 1
fi

echo "Iniciando instalação do MTM Agent..."

# Instalar dependências
echo "Instalando dependências..."
apt-get update
apt-get install -y git golang-go

# Parar o serviço se estiver em execução
echo "Parando serviço atual se estiver em execução..."
systemctl stop mtm-agent.service || true

# Remover diretório anterior completamente
echo "Removendo instalação anterior..."
rm -rf /opt/mtm_agent

# Criar novo diretório de instalação
echo "Criando diretório de instalação..."
mkdir -p /opt/mtm_agent
cd /opt/mtm_agent

# Baixar o código do repositório
echo "Baixando código fonte..."
git clone https://github.com/MakeToMe/agent.git .
# Ou usar wget para baixar um release específico:
# wget -O mtm_agent.tar.gz https://github.com/seu-usuario/mtm_agent/archive/refs/tags/v1.0.0.tar.gz
# tar -xzf mtm_agent.tar.gz --strip-components=1
# rm mtm_agent.tar.gz

# Compilar o código
echo "Compilando o código..."
go mod tidy
go build -o mtm_agent

# Verificar se o arquivo de serviço existe
echo "Configurando serviço systemd..."
if [ -f "mtm-agent.service" ]; then
    cp mtm-agent.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable mtm-agent.service
    systemctl start mtm-agent.service
else
    echo "ERRO: Arquivo mtm-agent.service não encontrado!"
    exit 1
fi

# Verificar status do serviço
echo "Verificando status do serviço..."
systemctl status mtm-agent.service

echo "Instalação concluída com sucesso!"
echo "O MTM Agent está rodando como um serviço e será iniciado automaticamente na inicialização do sistema."
echo "Para verificar os logs: journalctl -u mtm-agent.service -f"
