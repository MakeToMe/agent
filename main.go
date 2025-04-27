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
	"strconv"
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

// FirewallStatus representa o status do firewall para envio à API
type FirewallStatus struct {
	IP           string `json:"ip"`
	FirewallType string `json:"firewall_type"`
	Active       bool   `json:"active"`
}

// FirewallRule representa uma regra de firewall para envio à API
type FirewallRule struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Source      string `json:"source"`
	Active      bool   `json:"active"`
	Priority    int    `json:"priority"`
	FirewallType string `json:"firewall_type"`
}

// DockerWorker representa um nó worker do Docker Swarm
type DockerWorker struct {
	Hostname string
	IP       string
}

// Variáveis globais
var isFirstCycle = true
var dockerWorkers []DockerWorker
var firewallType string
var firewallActive bool
var bannedIPsCache []string

func main() {
	// Obter IP da VM
	localIP, err := getLocalIP()
	if err != nil {
		fmt.Printf("Erro ao obter IP local: %v\n", err)
		localIP = "127.0.0.1" // Fallback para localhost
	}
	fmt.Printf("IP local detectado: %s\n", localIP)

	// Iniciar servidor HTTP para endpoints locais na porta 9001 (evitando conflito com Portainer)
	go startHTTPServer()

	// No primeiro ciclo, configurar o firewall
	if isFirstCycle {
		fmt.Println("Primeiro ciclo: configurando firewall...")
		err := configurarFirewall(localIP)
		if err != nil {
			fmt.Printf("Erro ao configurar firewall: %v\n", err)
		}
	}

	// Iniciar rotina para executar lastb e enviar lista de IPs banidos a cada 5 minutos
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		// Executar imediatamente na primeira execução - obter todos os IPs históricos
		fmt.Println("Primeiro ciclo: obtendo todos os IPs históricos...")
		failedLogins, err := getFailedLogins(true) // true = primeiro ciclo
		if err != nil {
			log.Printf("Erro ao obter logins falhos: %v\n", err)
		} else {
			sendBannedIPsList(localIP, failedLogins)
			
			// Se for o primeiro ciclo, banir os IPs maliciosos no firewall
			if isFirstCycle && firewallActive {
				banirIPsMaliciosos()
			}
		}
		
		// Marcar que o primeiro ciclo foi concluído
		isFirstCycle = false
		fmt.Println("Primeiro ciclo concluído. Próximos ciclos usarão filtro de tempo.")
		
		// Ciclos subsequentes
		for range ticker.C {
			fmt.Println("Ciclo subsequente: obtendo apenas IPs recentes...")
			failedLogins, err := getFailedLogins(false) // false = ciclos subsequentes
			if err != nil {
				log.Printf("Erro ao obter logins falhos: %v\n", err)
				continue
			}
			sendBannedIPsList(localIP, failedLogins)
			
			// Banir novos IPs maliciosos no firewall
			if firewallActive {
				banirIPsMaliciosos()
			}
		}
	}()

	// Manter o programa em execução
	select {}
}

// detectarTipoFirewall detecta o tipo de firewall ativo na VM
func detectarTipoFirewall() (string, bool) {
	// Verificar UFW
	cmdUfw := exec.Command("bash", "-c", "ufw status | grep -q 'Status: active' && echo 'active' || echo 'inactive'")
	outputUfw, _ := cmdUfw.CombinedOutput()
	if strings.TrimSpace(string(outputUfw)) == "active" {
		fmt.Println("Firewall UFW detectado e ativo")
		return "ufw", true
	}

	// Verificar Firewalld
	cmdFirewalld := exec.Command("bash", "-c", "command -v firewall-cmd && firewall-cmd --state 2>/dev/null || echo 'not running'")
	outputFirewalld, _ := cmdFirewalld.CombinedOutput()
	if strings.TrimSpace(string(outputFirewalld)) == "running" {
		fmt.Println("Firewall Firewalld detectado e ativo")
		return "firewalld", true
	}

	// Verificar iptables
	cmdIptables := exec.Command("bash", "-c", "iptables -L -n | grep -q 'Chain' && echo 'configured' || echo 'not configured'")
	outputIptables, _ := cmdIptables.CombinedOutput()
	if strings.TrimSpace(string(outputIptables)) == "configured" {
		// Verificar se há regras além das padrões
		cmdRules := exec.Command("bash", "-c", "iptables -L -n | grep -v '^Chain' | grep -v '^target' | grep -v '^$' | wc -l")
		outputRules, _ := cmdRules.CombinedOutput()
		rulesCount, _ := strconv.Atoi(strings.TrimSpace(string(outputRules)))
		if rulesCount > 0 {
			fmt.Println("Firewall iptables detectado e configurado")
			return "iptables", true
		}
	}

	// Nenhum firewall ativo detectado
	fmt.Println("Nenhum firewall ativo detectado")
	return "iptables", false
}

// verificarDockerSwarm verifica se a VM é um Manager do Docker Swarm e obtém os IPs dos Workers
func verificarDockerSwarm() (bool, error) {
	// Verificar se o Docker está instalado
	cmdDocker := exec.Command("bash", "-c", "command -v docker")
	_, err := cmdDocker.CombinedOutput()
	if err != nil {
		fmt.Println("Docker não encontrado na VM")
		return false, nil
	}

	// Verificar se é um Manager do Docker Swarm
	cmdSwarm := exec.Command("bash", "-c", "docker info | grep -q 'Swarm: active' && echo 'active' || echo 'inactive'")
	outputSwarm, _ := cmdSwarm.CombinedOutput()
	if strings.TrimSpace(string(outputSwarm)) != "active" {
		fmt.Println("Esta VM não é um Manager do Docker Swarm")
		return false, nil
	}

	// Verificar se é um Leader
	cmdLeader := exec.Command("bash", "-c", "docker node ls --format \"{{.ManagerStatus}}\" | grep -q 'Leader' && echo 'leader' || echo 'not leader'")
	outputLeader, _ := cmdLeader.CombinedOutput()
	if strings.TrimSpace(string(outputLeader)) != "leader" {
		fmt.Println("Esta VM é um Manager do Docker Swarm, mas não é o Leader")
		return false, nil
	}

	// Obter IPs dos Workers ativos
	cmdWorkers := exec.Command("bash", "-c", "docker node ls --format \"{{.Hostname}} {{.Status}} {{.ManagerStatus}} {{.Availability}}\" | grep \"Active\" | grep -v \"Leader\" | awk '{print $1}' | xargs -I{} sh -c 'echo \"{} $(docker node inspect --format \"{{.Status.Addr}}\" {})\"'")
	outputWorkers, err := cmdWorkers.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao obter IPs dos Workers: %v\n", err)
		return true, err
	}

	// Processar a saída para extrair os IPs dos Workers
	dockerWorkers = []DockerWorker{}
	lines := strings.Split(string(outputWorkers), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hostname := parts[0]
			ip := parts[1]
			dockerWorkers = append(dockerWorkers, DockerWorker{Hostname: hostname, IP: ip})
		}
	}

	fmt.Printf("Encontrados %d Workers do Docker Swarm\n", len(dockerWorkers))
	for i, worker := range dockerWorkers {
		fmt.Printf("Worker %d: %s (%s)\n", i+1, worker.Hostname, worker.IP)
	}

	return true, nil
}

// configurarFirewall configura o firewall com as regras necessárias
func configurarFirewall(localIP string) error {
	// Detectar tipo de firewall
	var err error
	firewallType, firewallActive = detectarTipoFirewall()

	// Se não houver firewall ativo, ativar o iptables
	if !firewallActive {
		fmt.Println("Ativando firewall iptables...")
		// Limpar regras existentes
		exec.Command("bash", "-c", "iptables -F").Run()
		exec.Command("bash", "-c", "iptables -X").Run()
		
		// Configurar políticas padrão
		exec.Command("bash", "-c", "iptables -P INPUT DROP").Run()
		exec.Command("bash", "-c", "iptables -P FORWARD DROP").Run()
		exec.Command("bash", "-c", "iptables -P OUTPUT ACCEPT").Run()
		
		// Permitir conexões estabelecidas
		exec.Command("bash", "-c", "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT").Run()
		
		// Permitir loopback
		exec.Command("bash", "-c", "iptables -A INPUT -i lo -j ACCEPT").Run()
		
		// Permitir SSH (porta 22)
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 22 -j ACCEPT").Run()
		
		// Permitir HTTP (porta 80)
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 80 -j ACCEPT").Run()
		
		// Permitir HTTPS (porta 443)
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 443 -j ACCEPT").Run()
		
		// Permitir porta da API local (porta 9001)
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 9001 -j ACCEPT").Run()
		
		// Permitir portas para Traefik e Portainer
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 8080 -j ACCEPT").Run()  // Traefik dashboard
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 9000 -j ACCEPT").Run()  // Portainer
		
		// Permitir portas do Docker Swarm
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 2377 -j ACCEPT").Run()  // Gerenciamento do cluster
		exec.Command("bash", "-c", "iptables -A INPUT -p tcp --dport 7946 -j ACCEPT").Run()  // Comunicação entre nós (TCP)
		exec.Command("bash", "-c", "iptables -A INPUT -p udp --dport 7946 -j ACCEPT").Run()  // Comunicação entre nós (UDP)
		exec.Command("bash", "-c", "iptables -A INPUT -p udp --dport 4789 -j ACCEPT").Run()  // Tráfego overlay
		
		firewallActive = true
		firewallType = "iptables"
	} else if firewallType == "ufw" {
		// Se o UFW estiver ativo, garantir que as portas necessárias estejam abertas
		fmt.Println("Configurando regras no UFW existente...")
		
		// Portas essenciais
		exec.Command("bash", "-c", "ufw allow 22/tcp comment 'SSH'").Run()
		exec.Command("bash", "-c", "ufw allow 80/tcp comment 'HTTP'").Run()
		exec.Command("bash", "-c", "ufw allow 443/tcp comment 'HTTPS'").Run()
		exec.Command("bash", "-c", "ufw allow 9001/tcp comment 'API Local'").Run()
		
		// Portas para Traefik e Portainer
		exec.Command("bash", "-c", "ufw allow 8080/tcp comment 'Traefik Dashboard'").Run()
		exec.Command("bash", "-c", "ufw allow 9000/tcp comment 'Portainer'").Run()
		
		// Portas Docker Swarm
		exec.Command("bash", "-c", "ufw allow 2377/tcp comment 'Docker Swarm management'").Run()
		exec.Command("bash", "-c", "ufw allow 7946/tcp comment 'Docker Swarm node communication'").Run()
		exec.Command("bash", "-c", "ufw allow 7946/udp comment 'Docker Swarm node communication'").Run()
		exec.Command("bash", "-c", "ufw allow 4789/udp comment 'Docker Swarm overlay network traffic'").Run()
		
	} else if firewallType == "firewalld" {
		// Se o Firewalld estiver ativo, garantir que as portas necessárias estejam abertas
		fmt.Println("Configurando regras no Firewalld existente...")
		
		// Portas essenciais
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-service=ssh").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-service=http").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-service=https").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=9001/tcp").Run()
		
		// Portas para Traefik e Portainer
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=8080/tcp").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=9000/tcp").Run()
		
		// Portas Docker Swarm
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=2377/tcp").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=7946/tcp").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=7946/udp").Run()
		exec.Command("bash", "-c", "firewall-cmd --permanent --add-port=4789/udp").Run()
		
		// Recarregar para aplicar as mudanças
		exec.Command("bash", "-c", "firewall-cmd --reload").Run()
	}

	// Verificar se é um Manager do Docker Swarm
	isManager, err := verificarDockerSwarm()
	if err != nil {
		fmt.Printf("Erro ao verificar Docker Swarm: %v\n", err)
		// Continuar mesmo com erro
	}

	// Se for um Manager, liberar acesso dos Workers
	if isManager && len(dockerWorkers) > 0 {
		fmt.Println("Configurando regras de firewall para Workers do Docker Swarm...")
		
		for _, worker := range dockerWorkers {
			// Liberar todo o tráfego dos Workers
			switch firewallType {
			case "ufw":
				exec.Command("bash", "-c", fmt.Sprintf("ufw allow from %s comment 'Docker Swarm Worker: %s'", worker.IP, worker.Hostname)).Run()
			case "firewalld":
				exec.Command("bash", "-c", fmt.Sprintf("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=%s accept'", worker.IP)).Run()
				exec.Command("bash", "-c", "firewall-cmd --reload").Run()
			case "iptables":
				exec.Command("bash", "-c", fmt.Sprintf("iptables -A INPUT -s %s -j ACCEPT", worker.IP)).Run()
			}
			
			// Enviar regra para a API
			rule := FirewallRule{
				IP:          localIP,
				Port:        0, // 0 significa todas as portas
				Protocol:    "all",
				Action:      "allow",
				Description: fmt.Sprintf("Docker Swarm Worker: %s", worker.Hostname),
				Source:      worker.IP,
				Active:      true,
				Priority:    10,
				FirewallType: firewallType,
			}
			
			enviarRegraFirewall(rule)
		}
	}

	// Banir IPs maliciosos
	banirIPsMaliciosos()

	// Enviar status do firewall para a API
	status := FirewallStatus{
		IP:           localIP,
		FirewallType: firewallType,
		Active:       firewallActive,
	}
	
	enviarStatusFirewall(status)

	return nil
}

// banirIPsMaliciosos aplica banimento perpétuo para os IPs maliciosos
func banirIPsMaliciosos() {
	// Obter a lista de IPs com falhas de login
	failedLogins, err := getFailedLogins(isFirstCycle)
	if err != nil {
		fmt.Printf("Erro ao obter logins falhos: %v\n", err)
		return
	}

	// Filtrar IPs com 3 ou mais falhas
	var ipsParaBanir []string
	for _, failure := range failedLogins {
		if failure.Count >= 3 {
			ipsParaBanir = append(ipsParaBanir, failure.IP)
		}
	}

	// Limitar aos primeiros 5000 IPs para evitar sobrecarga
	if len(ipsParaBanir) > 5000 {
		ipsParaBanir = ipsParaBanir[:5000]
	}

	// Identificar novos IPs para banir (que não estão no cache)
	var novosIPs []string
	for _, ip := range ipsParaBanir {
		jáBanido := false
		for _, bannedIP := range bannedIPsCache {
			if ip == bannedIP {
				jáBanido = true
				break
			}
		}
		if !jáBanido {
			novosIPs = append(novosIPs, ip)
		}
	}

	// Atualizar o cache com todos os IPs banidos
	bannedIPsCache = ipsParaBanir

	// Banir apenas os novos IPs
	if len(novosIPs) > 0 {
		fmt.Printf("Banindo %d novos IPs maliciosos no firewall...\n", len(novosIPs))
		for _, ip := range novosIPs {
			switch firewallType {
			case "ufw":
				exec.Command("bash", "-c", fmt.Sprintf("ufw deny from %s comment 'IP malicioso'", ip)).Run()
			case "firewalld":
				exec.Command("bash", "-c", fmt.Sprintf("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=%s drop'", ip)).Run()
			case "iptables":
				exec.Command("bash", "-c", fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip)).Run()
			}
		}

		// Recarregar firewalld se necessário
		if firewallType == "firewalld" {
			exec.Command("bash", "-c", "firewall-cmd --reload").Run()
		}
	} else {
		fmt.Println("Nenhum novo IP malicioso para banir no firewall")
	}
}

// enviarStatusFirewall envia o status do firewall para a API
func enviarStatusFirewall(status FirewallStatus) {
	jsonData, err := json.Marshal(status)
	if err != nil {
		fmt.Printf("Erro ao serializar status do firewall: %v\n", err)
		return
	}

	resp, err := http.Post("http://170.205.37.204:8081/firewall_status", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao enviar status do firewall: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erro ao enviar status do firewall. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Println("Status do firewall enviado com sucesso!")
}

// enviarRegraFirewall envia uma regra de firewall para a API
func enviarRegraFirewall(rule FirewallRule) {
	jsonData, err := json.Marshal(rule)
	if err != nil {
		fmt.Printf("Erro ao serializar regra de firewall: %v\n", err)
		return
	}

	resp, err := http.Post("http://170.205.37.204:8081/firewall_rules", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao enviar regra de firewall: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erro ao enviar regra de firewall. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Println("Regra de firewall enviada com sucesso!")
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

	fmt.Println("Servidor HTTP iniciado na porta 9001")
	if err := http.ListenAndServe(":9001", nil); err != nil {
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

