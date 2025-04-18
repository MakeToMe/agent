# Integração MTM Guardian x MTM Agent

Este documento descreve todos os detalhes necessários para a integração entre o projeto **mtm_guardian** (responsável por monitoramento, lógica e registro de banimentos) e o **mtm_agent** (responsável por executar comandos de firewall no host).

---

## Visão Geral

- **mtm_guardian** roda em container Docker/Swarm, monitora logs, detecta ameaças e gerencia registros no Supabase.
- **mtm_agent** roda como serviço no host (fora do Docker), com acesso root, e executa comandos sensíveis como banir/desbanir IPs.
- A comunicação entre os dois é feita via HTTP local (localhost), usando endpoints REST simples e seguros.

---

## Como funciona a integração

1. O **mtm_guardian** detecta a necessidade de banir/desbanir um IP.
2. Ele envia uma requisição HTTP (POST) para o **mtm_agent** rodando em `localhost:9000`.
3. O **mtm_agent** executa o comando de firewall (ex: iptables) no host.
4. O **mtm_guardian** registra o evento no Supabase e segue o fluxo normalmente.

---

## Endpoints expostos pelo mtm_agent

- `POST /ban`   → Banir IP
- `POST /unban` → Desbanir IP
- (Opcional) `GET /status` → Healthcheck

### Exemplo de requisição para banir IP

```
POST http://localhost:9000/ban
Content-Type: application/json

{
  "ip": "1.2.3.4"
}
```

### Exemplo de requisição para desbanir IP

```
POST http://localhost:9000/unban
Content-Type: application/json

{
  "ip": "1.2.3.4"
}
```

### Resposta esperada

```json
{
  "status": "ok",
  "message": "IP banned: 1.2.3.4"
}
```

---

## Exemplo de integração no código Go do mtm_guardian

```go
import (
    "bytes"
    "net/http"
)

func BanIP(ip string) error {
    payload := []byte(`{"ip":"` + ip + `"}`)
    resp, err := http.Post("http://localhost:9000/ban", "application/json", bytes.NewBuffer(payload))
    // Tratar resposta e erros
    return err
}

func UnbanIP(ip string) error {
    payload := []byte(`{"ip":"` + ip + `"}`)
    resp, err := http.Post("http://localhost:9000/unban", "application/json", bytes.NewBuffer(payload))
    // Tratar resposta e erros
    return err
}
```

---

## Requisitos para integração

- O **mtm_agent** deve estar rodando no host, escutando em `localhost:9000`.
- O **mtm_agent** deve rodar como root para manipular iptables/ufw.
- O **mtm_guardian** deve ter permissão de rede para acessar `localhost:9000` no host (em Docker, use network_mode: host OU configure para acessar via host.docker.internal, se disponível).
- O agente nunca deve escutar em portas públicas (apenas localhost/sockets).

---

## Segurança

- Recomenda-se autenticação por token entre guardian e agent (pode ser via header HTTP ou query param).
- O agente deve logar todas as ações para auditoria.
- O agente só deve aceitar comandos de localhost.

---

## Troubleshooting

- Se o guardian não conseguir banir, verifique se o agente está rodando e escutando na porta correta.
- Verifique logs do agente para erros de permissão ou comandos inválidos.
- Certifique-se que o agente tem permissão root.

---

## Roadmap futuro

- Adicionar autenticação JWT ou token.
- Suporte a outros firewalls além do iptables.
- Endpoint para listar IPs atualmente banidos.
- Monitoramento de saúde do agente.

---

## Contato

Dúvidas ou problemas: consulte o README de cada projeto ou abra uma issue no repositório correspondente.
