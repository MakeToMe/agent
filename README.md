# MTM Agent - Módulo Supabase (Golang)

Este módulo inicializa a conexão segura com o Supabase utilizando variáveis sensíveis em um arquivo `.env` (não versionado), garantindo que a chave secret não fique exposta publicamente.

## Dependências
- [supabase-community/supabase-go](https://github.com/supabase-community/supabase-go)
- [joho/godotenv](https://github.com/joho/godotenv)

## Como usar

1. Copie o arquivo `.env.example` para `.env` e preencha com as credenciais reais.
2. Instale as dependências:
   ```sh
   go mod tidy
   ```
3. Execute o serviço:
   ```sh
   go run main.go
   ```

## Segurança
- A chave `SUPABASE_SERVICE_KEY` nunca deve ser exposta em código público.
- O arquivo `.env` deve ser adicionado ao `.gitignore`.

## Próximos passos
- Implementar consulta ao IP do servidor e buscar o titular na tabela `servidores`.
- Interagir com a tabela `banned_ips` conforme o fluxo de integração.
