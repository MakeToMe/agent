# MTM Agent

O MTM Agent é um serviço que monitora tentativas de login falhas no sistema Linux e envia a lista de IPs suspeitos para uma API central. Também fornece endpoints HTTP locais para banir ou desbanir IPs específicos.

## Funcionalidades

- Detecta o IP local do servidor
- Monitora tentativas de login falhas usando o comando `lastb`
- Agrega e ordena IPs por quantidade de falhas
- Envia IPs suspeitos (com 3 ou mais falhas) para API central
- Fornece endpoints HTTP locais para banir/desbanir IPs

## Instalação Rápida

Para instalar o MTM Agent, execute o seguinte comando como root:

```bash
wget -O - https://raw.githubusercontent.com/MakeToMe/agent/main/install.sh | bash
```

Ou baixe e execute o script manualmente:

```bash
wget https://raw.githubusercontent.com/MakeToMe/agent/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

## Instalação Manual

1. Clone o repositório:
   ```bash
   git clone https://github.com/MakeToMe/agent.git
   cd agent
   ```

2. Compile o código:
   ```bash
   go mod tidy
   go build -o mtm_agent
   ```

3. Configure o serviço systemd:
   ```bash
   sudo cp mtm-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable mtm-agent.service
   sudo systemctl start mtm-agent.service
   ```

## Uso

O serviço inicia automaticamente após a instalação e na inicialização do sistema. Ele executa as seguintes ações:

1. A cada 5 minutos, verifica tentativas de login falhas e envia IPs suspeitos para a API central
2. Fornece endpoints HTTP na porta 9000:
   - `POST /ban` - Banir um IP específico
   - `POST /unban` - Desbanir um IP específico
   - `GET /status` - Verificar status do serviço

## Monitoramento

Para verificar o status do serviço:
```bash
sudo systemctl status mtm-agent.service
```

Para ver os logs:
```bash
sudo journalctl -u mtm-agent.service -f
```

## Segurança

- O serviço deve ser executado como root para acessar os logs de login e manipular regras de firewall
- Os endpoints HTTP só estão disponíveis localmente (localhost:9000)
