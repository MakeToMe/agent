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

// Variável global para controlar se é o primeiro ciclo
var isFirstCycle = true

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
		// Executar imediatamente na primeira execução - obter todos os IPs históricos
		fmt.Println("Primeiro ciclo: obtendo todos os IPs históricos...")
		failedLogins, err := getFailedLogins(true) // true = primeiro ciclo
		if err != nil {
			log.Printf("Erro ao obter logins falhos: %v\n", err)
		} else {
			sendBannedIPsList(ip, failedLogins)
		}
		
		// Marcar que o primeiro ciclo foi concluído
		isFirstCycle = false
		fmt.Println("Primeiro ciclo concluído. Próximos ciclos usarão filtro de tempo.")
		
		for range ticker.C {
			fmt.Println("Ciclo subsequente: obtendo apenas IPs recentes...")
			failedLogins, err := getFailedLogins(false) // false = ciclos subsequentes
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
func getFailedLogins(isFirstRun bool) ([]LoginFailure, error) {
	var cmd *exec.Cmd
	
	if isFirstRun {
		// Primeiro ciclo: obter todos os IPs históricos
		// 1. lastb -i: lista tentativas falhas com IPs
		// 2. grep: extrai apenas os IPs
		// 3. sort e uniq -c: conta ocorrências únicas
		// 4. sort -nr: ordena por número de ocorrências (maior para menor)
		fmt.Println("Executando comando para obter TODAS as falhas de login históricas...")
		cmd = exec.Command("bash", "-c", 
			"lastb -i | grep -o -E '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sort | uniq -c | sort -nr")
	} else {
		// Ciclos subsequentes: obter apenas IPs dos últimos 8 minutos
		// Usamos o comando date para obter a data/hora de 8 minutos atrás no formato que o lastb aceita
		fmt.Println("Executando comando para obter falhas de login dos últimos 8 minutos...")
		cmd = exec.Command("bash", "-c", 
			"TIMEFILTER=$(date --date='8 minutes ago' '+%Y%m%d%H%M%S') && " +
			"lastb -i -t $TIMEFILTER | grep -o -E '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sort | uniq -c | sort -nr")
	}
	
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

	// Limitar aos top 5000 IPs com mais falhas
	if len(failures) > 5000 {
		failures = failures[:5000]
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

	// Log para depuração detalhado
	fmt.Printf("Encontrados %d IPs com 3 ou mais falhas de login\n", len(bannedIPs))
	fmt.Printf("Enviando %d IPs suspeitos para API (limite configurado: 5000)\n", len(bannedIPs))
	fmt.Printf("Ciclo: %s\n", map[bool]string{true: "PRIMEIRO - todos os IPs históricos", false: "SUBSEQUENTE - apenas IPs recentes"}[isFirstCycle])
	
	// Imprimir os primeiros 5 IPs para depuração
	fmt.Println("Primeiros IPs da lista (até 5):")
	for i, ip := range bannedIPs {
		if i >= 5 {
			break
		}
		fmt.Printf("  - %s\n", ip.IP2Ban)
	}

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

