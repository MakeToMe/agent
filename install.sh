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
apt-get install -y git ipset wget sysstat

# Verificar se o sysstat foi instalado corretamente
if ! command -v mpstat &> /dev/null; then
    echo "ERRO: O comando mpstat não está disponível mesmo após a instalação do sysstat."
    echo "Tentando instalar novamente..."
    apt-get install -y --reinstall sysstat
    
    if ! command -v mpstat &> /dev/null; then
        echo "AVISO: Não foi possível instalar o mpstat. O agente usará o método alternativo para coletar métricas de CPU."
    else
        echo "mpstat instalado com sucesso!"
    fi
else
    echo "mpstat verificado e disponível!"
fi

# Remover versão antiga do Go para evitar conflitos
echo "Removendo versões antigas do Go..."
apt-get remove -y golang-go
apt-get autoremove -y

# Forçar a instalação do Go 1.21
GO_VERSION="1.21.0"
echo "Instalando Go $GO_VERSION para garantir compatibilidade..."
INSTALL_GO=true

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
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -o mtm-agent

# Verificar se o binário foi criado com sucesso
if [ ! -f "mtm-agent" ]; then
    echo "ERRO: Falha ao compilar o binário mtm-agent!"
    exit 1
fi
echo "Binário compilado com sucesso: $(pwd)/mtm-agent"

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

# Coletar e enviar informações do sistema para a API
echo "Coletando informações do sistema..."

# Obter o IP da VM
IP_VM=$(hostname -I | awk '{print $1}')
if [ -z "$IP_VM" ]; then
    IP_VM="127.0.0.1"
    echo "Não foi possível obter o IP da VM, usando localhost como fallback."
fi
echo "IP detectado: $IP_VM"

# Obter número de cores da CPU
CPU_CORES=$(grep -c ^processor /proc/cpuinfo)
echo "Número de cores CPU: $CPU_CORES"

# Obter quantidade total de RAM em GB
RAM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
RAM_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_TOTAL/1024}")
echo "Memória RAM total: $RAM_GB GB"

# Obter espaço total em disco em GB
DISK_TOTAL=$(df -BG / | awk 'NR==2 {print $2}' | sed 's/G//')
echo "Espaço em disco total: $DISK_TOTAL GB"

# Obter informações do sistema operacional
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME $VERSION_ID"
else
    OS_NAME="Linux $(uname -r)"
fi
echo "Sistema operacional: $OS_NAME"

# Criar JSON com as informações
JSON_DATA="{\
  \"ip\": \"$IP_VM\",\
  \"cpu\": $CPU_CORES,\
  \"ram\": $RAM_GB,\
  \"storage\": $DISK_TOTAL,\
  \"sistema\": \"$OS_NAME\"\
}"

# Salvar JSON em arquivo temporário
echo "$JSON_DATA" > /tmp/system_config.json
echo "JSON de configuração criado:"
cat /tmp/system_config.json

# Enviar dados para a API
echo "Enviando informações do sistema para a API..."
API_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d @/tmp/system_config.json http://170.205.37.204:8081/config)
API_STATUS=$?

if [ $API_STATUS -eq 0 ]; then
    echo "Informações do sistema enviadas com sucesso!"
    echo "Resposta da API: $API_RESPONSE"
else
    echo "Erro ao enviar informações do sistema para a API. Código: $API_STATUS"
fi

# Remover arquivo temporário
rm -f /tmp/system_config.json

echo "Instalação concluída com sucesso!"
echo "O MTM Agent está rodando como um serviço e será iniciado automaticamente na inicialização do sistema."
echo "Para verificar os logs: journalctl -u mtm-agent.service -f"
