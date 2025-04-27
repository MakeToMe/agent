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
apt-get install -y git ipset wget

# Verificar a versão atual do Go
GO_VERSION="1.21.0"
if command -v go &> /dev/null; then
    CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g')
    echo "Versão atual do Go: $CURRENT_GO_VERSION"
    
    # Comparar versões (simplificado)
    if [[ "$CURRENT_GO_VERSION" == 1.* ]] && [[ "${CURRENT_GO_VERSION:2:2}" -lt 21 ]]; then
        echo "Versão do Go muito antiga, instalando Go $GO_VERSION..."
        INSTALL_GO=true
    else
        echo "Versão do Go já é adequada."
        INSTALL_GO=false
    fi
else
    echo "Go não encontrado, instalando Go $GO_VERSION..."
    INSTALL_GO=true
fi

# Instalar Go 1.21 se necessário
if [ "$INSTALL_GO" = true ]; then
    echo "Baixando e instalando Go $GO_VERSION..."
    wget https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    rm go$GO_VERSION.linux-amd64.tar.gz
    
    # Configurar PATH para Go
    if ! grep -q 'export PATH=$PATH:/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    # Aplicar PATH para a sessão atual
    export PATH=$PATH:/usr/local/go/bin
    echo "Go $GO_VERSION instalado com sucesso!"
fi

# VERIFICAÇÃO: O projeto já existe?
if [ -d "/opt/mtm_agent" ] || [ -f "/etc/systemd/system/mtm-agent.service" ]; then
    echo "Instalação existente detectada. Removendo..."
    
    # Parar o serviço se estiver em execução
    echo "Parando serviço..."
    systemctl stop mtm-agent.service || true
    
    # Desabilitar o serviço
    echo "Desabilitando serviço..."
    systemctl disable mtm-agent.service || true
    
    # Remover arquivo de serviço
    echo "Removendo arquivo de serviço..."
    rm -f /etc/systemd/system/mtm-agent.service
    systemctl daemon-reload
    
    # Remover diretório de instalação
    echo "Removendo diretório de instalação..."
    rm -rf /opt/mtm_agent
fi

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
go build -o mtm-agent

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

# Configurar ipset para persistência após reinicialização
echo "Configurando ipset para persistência..."
if [ ! -f "/etc/network/if-pre-up.d/ipset" ]; then
    cat > /etc/network/if-pre-up.d/ipset << 'EOF'
#!/bin/sh
if [ -f /etc/ipset.conf ]; then
    ipset restore < /etc/ipset.conf
fi
exit 0
EOF
    chmod +x /etc/network/if-pre-up.d/ipset
    echo "Script de persistência do ipset criado em /etc/network/if-pre-up.d/ipset"
fi

# Verificar status do serviço
echo "Verificando status do serviço..."
systemctl status mtm-agent.service

echo "Instalação concluída com sucesso!"
echo "O MTM Agent está rodando como um serviço e será iniciado automaticamente na inicialização do sistema."
echo "Para verificar os logs: journalctl -u mtm-agent.service -f"
