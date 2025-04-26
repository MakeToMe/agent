package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Estruturas para API
type BanIP struct {
	IP2Ban string `json:"ip2ban"`
}

type BanList struct {
	IP      string  `json:"ip"`
	BanList []BanIP `json:"ban_list"`
}

// LoginFailure representa uma falha de login com contagem
type LoginFailure struct {
	IP    string
	Count int
}

func main() {
	// Obter IP da VM
	ip, err := getLocalIP()
	if err != nil {
		log.Fatalf("Erro ao obter IP local: %v", err)
	}
	fmt.Printf("IP local detectado: %s\n", ip)

	// Iniciar servidor HTTP para endpoints locais
	go startHTTPServer()

	// Iniciar rotina para executar lastb e enviar lista de IPs banidos a cada 5 minutos
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		// Executar imediatamente na primeira execução
		failedLogins, err := getFailedLogins()
		if err != nil {
			log.Printf("Erro ao obter logins falhos: %v\n", err)
		} else {
			sendBannedIPsList(ip, failedLogins)
		}
		
		for range ticker.C {
			failedLogins, err := getFailedLogins()
			if err != nil {
				log.Printf("Erro ao obter logins falhos: %v\n", err)
				continue
			}
			sendBannedIPsList(ip, failedLogins)
		}
	}()

	// Manter o programa em execução
	select {}
}

// detectarTipoFirewall é um placeholder para detectar o tipo real do firewall na VM
func detectarTipoFirewall() string {
	// TODO: implementar detecção real (ufw, iptables, firewalld, etc)
	return "ufw"
}

// PAUSA - Esta função será refatorada posteriormente
// func registrarStatusFirewall() {
// 	// Implementação futura
// }


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

// startHTTPServer inicia o servidor HTTP para os endpoints locais
func startHTTPServer() {
	// Endpoint para banir IP
	http.HandleFunc("/ban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			IP string `json:"ip"`
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// TODO: Implementar o banimento real do IP usando o firewall
		fmt.Printf("Banindo IP: %s\n", payload.IP)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("IP banned: %s", payload.IP),
		})
	})

	// Endpoint para desbanir IP
	http.HandleFunc("/unban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			IP string `json:"ip"`
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// TODO: Implementar o desbanimento real do IP usando o firewall
		fmt.Printf("Desbanindo IP: %s\n", payload.IP)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("IP unbanned: %s", payload.IP),
		})
	})

	// Endpoint opcional para verificar status
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "MTM Agent está em execução",
		})
	})

	fmt.Println("Servidor HTTP iniciado na porta 9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("Erro ao iniciar servidor HTTP: %v", err)
	}
}

// getFailedLogins obtém a lista de falhas de login do sistema usando lastb e agrega por IP
func getFailedLogins() ([]LoginFailure, error) {
	// Comando shell completo para extrair IPs com 3 ou mais tentativas falhas
	// 1. lastb -i: lista tentativas falhas com IPs
	// 2. grep: extrai apenas os IPs
	// 3. sort e uniq -c: conta ocorrências únicas
	// 4. sort -nr: ordena por número de ocorrências (maior para menor)
	cmd := exec.Command("bash", "-c", 
		"lastb -i | grep -o -E '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sort | uniq -c | sort -nr")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Verificamos se temos alguma saída antes de retornar erro
		if len(output) == 0 {
			return nil, fmt.Errorf("erro ao executar comando de agregação de IPs: %v", err)
		}
	}

	// Processar a saída formatada como "  COUNT IP"
	var failures []LoginFailure
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Formato esperado: "  COUNT IP"
		parts := strings.Fields(line)
		if len(parts) == 2 {
			count := 0
			_, err := fmt.Sscanf(parts[0], "%d", &count)
			if err != nil || count == 0 {
				continue
			}
			
			ip := parts[1]
			failures = append(failures, LoginFailure{IP: ip, Count: count})
		}
	}

	// Ordenar por contagem (maior para menor)
	sort.Slice(failures, func(i, j int) bool {
		return failures[i].Count > failures[j].Count
	})

	// Limitar aos top 1000 IPs com mais falhas
	if len(failures) > 1000 {
		failures = failures[:1000]
	}

	return failures, nil


}

// sendBannedIPsList envia a lista de IPs banidos para a API externa
func sendBannedIPsList(localIP string, failedLogins []LoginFailure) {
	// Converter falhas de login para o formato esperado pela API
	var bannedIPs []BanIP
	for _, failure := range failedLogins {
		// Já filtramos por 3 ou mais falhas no comando shell, mas mantemos a verificação por segurança
		if failure.Count >= 3 {
			bannedIPs = append(bannedIPs, BanIP{IP2Ban: failure.IP})
		}
	}

	// Se não houver IPs para banir, ainda enviamos uma lista vazia
	payload := BanList{
		IP:      localIP,
		BanList: bannedIPs,
	}

	// Log para depuração
	fmt.Printf("Enviando %d IPs suspeitos para API\n", len(bannedIPs))

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Erro ao serializar JSON: %v\n", err)
		return
	}

	resp, err := http.Post("http://170.205.37.204:8081/listbanip", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Erro ao enviar lista de IPs banidos: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Erro ao enviar lista de IPs banidos. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Println("Lista de IPs banidos enviada com sucesso!")
}

