package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/joho/godotenv"
	supabase "github.com/supabase-community/supabase-go"
)

type ServidorInfo struct {
	UID       string
	Titular   string
	ServidorIP string
}

func main() {
	// Carrega variáveis do .env
	err := godotenv.Load()
	if err != nil {
		log.Println("Arquivo .env não encontrado, usando variáveis de ambiente do sistema.")
	}

	supabaseUrl := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_SERVICE_KEY")
	if supabaseUrl == "" || supabaseKey == "" {
		log.Fatal("SUPABASE_URL ou SUPABASE_SERVICE_KEY não definidos.")
	}

	client := supabase.NewClient(supabaseUrl, supabaseKey, nil)
	fmt.Println("Cliente Supabase inicializado com sucesso!")

	// 1. Obter IP da VM
	ip, err := getLocalIP()
	if err != nil {
		log.Fatalf("Erro ao obter IP local: %v", err)
	}
	fmt.Printf("IP local detectado: %s\n", ip)

	// 2. Consultar na tabela servidores pelo IP
	servidor, err := buscarServidorPorIP(client, ip)
	if err != nil {
		log.Fatalf("Erro ao buscar servidor no Supabase: %v", err)
	}
	fmt.Printf("Servidor encontrado: UID=%s, Titular=%s, IP=%s\n", servidor.UID, servidor.Titular, servidor.ServidorIP)

	// 3. Registrar/atualizar status do firewall na tabela firewall_status
	firewallType := detectarTipoFirewall() // placeholder para detecção real
	firewallActive := true                 // placeholder, definir conforme detecção real
	err = registrarStatusFirewall(client, servidor, firewallType, firewallActive)
	if err != nil {
		log.Fatalf("Erro ao registrar status do firewall: %v", err)
	}
	fmt.Println("Status do firewall registrado/atualizado com sucesso!")

	// 4. (Próximo passo) Função para inserir IPs banidos, evitando duplicidade
	// err = registrarBanimento(client, servidor, "1.2.3.4")
	// if err != nil { ... }
}

// detectarTipoFirewall é um placeholder para detectar o tipo real do firewall na VM
func detectarTipoFirewall() string {
	// TODO: implementar detecção real (ufw, iptables, firewalld, etc)
	return "ufw"
}

// registrarStatusFirewall insere ou atualiza o status do firewall para o servidor
func registrarStatusFirewall(client *supabase.Client, servidor *ServidorInfo, firewallType string, active bool) error {
	ctx := context.Background()
	// Verifica se já existe registro para o servidor_id
	resp, err := client.From("firewall_status").Select("id").Eq("servidor_id", servidor.UID).Execute(ctx)
	if err != nil {
		return err
	}
	if strings.Contains(resp.String(), "id") {
		// Já existe, atualiza
		_, err = client.From("firewall_status").Update(map[string]interface{}{
			"firewall_type": firewallType,
			"active":        active,
			"servidor_ip":   servidor.ServidorIP,
			"titular":       servidor.Titular,
			"updated_at":    "now()",
		}).Eq("servidor_id", servidor.UID).Execute(ctx)
		return err
	} else {
		// Não existe, insere
		_, err = client.From("firewall_status").Insert(map[string]interface{}{
			"servidor_id":   servidor.UID,
			"titular":       servidor.Titular,
			"firewall_type": firewallType,
			"active":        active,
			"servidor_ip":   servidor.ServidorIP,
		}).Execute(ctx)
		return err
	}
}


// getLocalIP retorna o primeiro IP não-loopback encontrado na máquina
func getLocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("nenhum IP válido encontrado")
}

// buscarServidorPorIP consulta a tabela 'servidores' pelo IP e retorna UID e Titular
func buscarServidorPorIP(client *supabase.Client, ip string) (*ServidorInfo, error) {
	ctx := context.Background()
	resp, err := client.From("servidores").Select("uid,titular,ip").Eq("ip", ip).Execute(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 || !strings.Contains(resp.String(), "uid") {
		return nil, fmt.Errorf("servidor não encontrado para o IP %s", ip)
	}
	// Parse simples do JSON de resposta (pode ser melhorado com struct)
	uid := extrairValor(resp.String(), "uid")
	titular := extrairValor(resp.String(), "titular")
	servidorIP := extrairValor(resp.String(), "ip")
	return &ServidorInfo{UID: uid, Titular: titular, ServidorIP: servidorIP}, nil
}

// extrairValor é um parse simples para pegar o valor de uma chave em um JSON flat (melhorar para produção)
func extrairValor(json, chave string) string {
	idx := strings.Index(json, chave)
	if idx == -1 {
		return ""
	}
	start := strings.Index(json[idx:], ":")
	if start == -1 {
		return ""
	}
	start += idx + 2
	end := strings.IndexAny(json[start:], ",}\n")
	if end == -1 {
		return strings.Trim(json[start:], "\" ")
	}
	return strings.Trim(json[start:start+end], "\" ")
}

// registrarBanimento (a implementar):
// Recebe o cliente, infos do servidor e um IP a ser banido
// 1. Verifica se já existe banimento ativo para o IP e servidor_id
// 2. Se não existir, insere na tabela banned_ips
// func registrarBanimento(client *supabase.Client, servidor *ServidorInfo, ipBanido string) error {
// 	// TODO
// 	return nil
// }

