package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	IP      string `json:"ip"`
	BanList []BanIP `json:"ban_list"`
}

type ProcessInfo struct {
	PID        int     `json:"pid"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	RAMPercent float64 `json:"ram_percent"`
	RssKB      int     `json:"rss_kb"`
	Command    string  `json:"command"`
	Rank       int     `json:"rank"`
}

type ServerInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type ProcessMetricsAPI struct {
	ServerInfo   ServerInfo     `json:"server_info"`
	TopProcesses TopProcessList `json:"top_processes"`
	SystemMetrics SystemMetrics `json:"system_metrics"`
}

type TopProcessList struct {
	ByCPU []ProcessInfo `json:"by_cpu"`
	ByRAM []ProcessInfo `json:"by_ram"`
}

type CPUCore struct {
	Core  int     `json:"core"`
	Usage float64 `json:"usage"`
}

type SystemMetrics struct {
	CPUCores   []CPUCore `json:"cpu_cores"`
	CPUTotal   float64   `json:"cpu_total"`
	CPUUsada   float64   `json:"cpu_usada"`
	CPULivre   float64   `json:"cpu_livre"`
	MemTotal   float64   `json:"mem_total"`
	MemUsada   float64   `json:"mem_usada"`
	MemLivre   float64   `json:"mem_livre"`
	DiscoTotal float64   `json:"disco_total"`
	DiscoUsado float64   `json:"disco_usado"`
	DiscoLivre float64   `json:"disco_livre"`
}

type ProcessMetricsDB struct {
	ServerInfo    ServerInfo     `json:"server_info"`
	Processes     ProcessesList  `json:"processes"`
	SystemMetrics SystemMetrics  `json:"system_metrics"`
}

type ProcessesList struct {
	ByCPU []ProcessInfo `json:"by_cpu"`
	ByRAM []ProcessInfo `json:"by_ram"`
}

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

// ContainerStats representa as estatísticas de um container Docker
type ContainerStats struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	CPUPerc     string  `json:"cpu_perc"`
	MemUsage    string  `json:"mem_usage"`
	MemPerc     string  `json:"mem_perc"`
	NetIO       string  `json:"net_io"`
	BlockIO     string  `json:"block_io"`
	PIDs        string  `json:"pids"`
	Container   string  `json:"container"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	PidsCount   int     `json:"pids_count"`
	NetIORXBytes int64   `json:"net_io_rx_bytes_raw"`
	NetIOTXBytes int64   `json:"net_io_tx_bytes_raw"`
	NetIO_RX_Bytes float64 `json:"net_io_rx_bytes"`
	NetIO_TX_Bytes float64 `json:"net_io_tx_bytes"`
	NetIO_RX_Formatted string `json:"net_io_rx_formatted"`
	NetIO_TX_Formatted string `json:"net_io_tx_formatted"`
}

// NetworkStats representa as estatísticas de rede agregadas
type NetworkStats struct {
	TotalRXBytes     int64  `json:"total_rx_bytes"`
	TotalTXBytes     int64  `json:"total_tx_bytes"`
	TotalRXFormatted string `json:"total_rx_formatted"`
	TotalTXFormatted string `json:"total_tx_formatted"`
	TotalBandwidth   string `json:"total_bandwidth"`
}

// DockerStats representa as estatísticas do Docker
type DockerStats struct {
	IP        string          `json:"ip"`
	Stats     json.RawMessage `json:"stats"`
	Timestamp string          `json:"timestamp"`
}

// DockerStatsData representa os dados de estatísticas do Docker
type DockerStatsData struct {
	Containers    int              `json:"containers"`
	Network       NetworkStats     `json:"network"`
	ContainerList []ContainerStats `json:"container_list"`
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
		
		// Adicionar alguns IPs de teste para garantir que o ipset esteja funcionando
		testarBanimentoIPs()
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

	// Iniciar rotina para coletar e enviar métricas de processos a cada 10 segundos
	go coletarEEnviarMetricasProcessos(localIP)

	// Iniciar rotina para coletar e enviar métricas do Docker a cada 5 minutos
	go coletarEEnviarMetricasDocker(localIP)

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
		
		// Enviar regras padrão para a API
		enviarRegrasFirewallPadrao(localIP)
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
	} else if isManager {
		// Se for um Manager mas não tiver Workers, enviar regras padrão
		if len(dockerWorkers) == 0 {
			fmt.Println("VM é um Manager do Docker Swarm, mas não tem Workers. Enviando regras padrão...")
			enviarRegrasFirewallPadrao(localIP)
		} else {
			// Se tiver Workers, liberar acesso deles
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
			
			// Enviar também as regras padrão
			enviarRegrasFirewallPadrao(localIP)
		}
	} else {
		// Não é um Manager, enviar regras padrão
		fmt.Println("VM não é um Manager do Docker Swarm. Enviando regras padrão...")
		enviarRegrasFirewallPadrao(localIP)
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

	// Log do número total de falhas encontradas
	fmt.Printf("Total de falhas de login encontradas: %d\n", len(failedLogins))

	// Filtrar IPs com 3 ou mais falhas
	var ipsParaBanir []string
	for _, failure := range failedLogins {
		if failure.Count >= 3 {
			ipsParaBanir = append(ipsParaBanir, failure.IP)
			fmt.Printf("IP para banir: %s (falhas: %d)\n", failure.IP, failure.Count)
		}
	}

	// Limitar aos primeiros 5000 IPs para evitar sobrecarga
	if len(ipsParaBanir) > 5000 {
		ipsParaBanir = ipsParaBanir[:5000]
	}
	
	// Se não houver IPs para banir, usar a lista do cache
	if len(ipsParaBanir) == 0 && len(bannedIPsCache) > 0 {
		fmt.Println("Nenhum novo IP para banir. Usando lista do cache...")
		ipsParaBanir = bannedIPsCache
	}

	// Verificar se o ipset está instalado
	checkIpsetCmd := exec.Command("bash", "-c", "command -v ipset || echo 'not-installed'")
	ipsetOutput, _ := checkIpsetCmd.CombinedOutput()
	if strings.Contains(string(ipsetOutput), "not-installed") {
		fmt.Println("ipset não está instalado. Instalando...")
		installCmd := exec.Command("bash", "-c", "apt-get update && apt-get install -y ipset")
		installOutput, err := installCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao instalar ipset: %v\n%s\n", err, string(installOutput))
			// Fallback para o método antigo se não conseguir instalar ipset
			banirIPsComIptables(ipsParaBanir)
			return
		}
	}

	// Criar o conjunto ipset se não existir
	exec.Command("bash", "-c", "ipset create -exist mtm-banned-ips hash:ip").Run()

	// Garantir que a regra do iptables que usa o ipset exista
	checkRuleCmd := exec.Command("bash", "-c", "iptables -C INPUT -m set --match-set mtm-banned-ips src -j DROP 2>/dev/null || echo 'not-exists'")
	output, _ := checkRuleCmd.CombinedOutput()
	if strings.Contains(string(output), "not-exists") {
		exec.Command("bash", "-c", "iptables -A INPUT -m set --match-set mtm-banned-ips src -j DROP").Run()
	}

	// Banir cada IP (sem duplicação - o ipset automaticamente evita duplicatas)
	fmt.Printf("Banindo %d IPs maliciosos usando ipset...\n", len(ipsParaBanir))
	for _, ip := range ipsParaBanir {
		// Verificar se o IP é válido
		if net.ParseIP(ip) == nil {
			fmt.Printf("IP inválido, ignorando: %s\n", ip)
			continue
		}
		
		// Adicionar o IP ao ipset e capturar qualquer erro
		cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset add mtm-banned-ips %s", ip))
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao adicionar IP %s ao ipset: %v\n%s\n", ip, err, string(output))
		} else {
			fmt.Printf("IP %s adicionado ao ipset com sucesso\n", ip)
		}
	}

	// Salvar o ipset para persistência
	exec.Command("bash", "-c", "ipset save > /etc/ipset.conf").Run()

	// Atualizar o cache para uso futuro
	bannedIPsCache = ipsParaBanir
}

// banirIPsComIptables é o método de banimento usando apenas iptables
// Usado como fallback se o ipset não estiver disponível
func banirIPsComIptables(ipsParaBanir []string) {
	// Banir cada IP usando o firewall
	fmt.Printf("Banindo %d IPs maliciosos usando iptables (método legado)...\n", len(ipsParaBanir))
	for _, ip := range ipsParaBanir {
		// Verificar se o IP já está banido para evitar duplicação
		checkCmd := exec.Command("bash", "-c", fmt.Sprintf("iptables -C INPUT -s %s -j DROP 2>/dev/null || echo 'not-exists'", ip))
		output, _ := checkCmd.CombinedOutput()
		if strings.Contains(string(output), "not-exists") {
			// Banir o IP usando iptables
			switch firewallType {
			case "ufw":
				exec.Command("bash", "-c", fmt.Sprintf("ufw deny from %s comment 'IP malicioso'", ip)).Run()
			case "firewalld":
				exec.Command("bash", "-c", fmt.Sprintf("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=%s drop'", ip)).Run()
				exec.Command("bash", "-c", "firewall-cmd --reload").Run()
			default: // iptables
				exec.Command("bash", "-c", fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip)).Run()
			}
		}
	}

	// Atualizar o cache para uso futuro
	bannedIPsCache = ipsParaBanir
}

// testarBanimentoIPs adiciona alguns IPs de teste ao ipset para garantir que está funcionando
func testarBanimentoIPs() {
	fmt.Println("Adicionando IPs de teste ao ipset...")
	
	// Verificar se o ipset está instalado
	checkIpsetCmd := exec.Command("bash", "-c", "command -v ipset || echo 'not-installed'")
	ipsetOutput, _ := checkIpsetCmd.CombinedOutput()
	if strings.Contains(string(ipsetOutput), "not-installed") {
		fmt.Println("ipset não está instalado. Instalando...")
		installCmd := exec.Command("bash", "-c", "apt-get update && apt-get install -y ipset")
		installOutput, err := installCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao instalar ipset: %v\n%s\n", err, string(installOutput))
			return
		}
	}
	
	// Criar o conjunto ipset se não existir
	exec.Command("bash", "-c", "ipset create -exist mtm-banned-ips hash:ip").Run()
	
	// Garantir que a regra do iptables que usa o ipset exista
	checkRuleCmd := exec.Command("bash", "-c", "iptables -C INPUT -m set --match-set mtm-banned-ips src -j DROP 2>/dev/null || echo 'not-exists'")
	output, _ := checkRuleCmd.CombinedOutput()
	if strings.Contains(string(output), "not-exists") {
		exec.Command("bash", "-c", "iptables -A INPUT -m set --match-set mtm-banned-ips src -j DROP").Run()
	}
	
	// Lista de IPs de teste para banir
	ipsParaTestar := []string{
		"1.2.3.4",
		"5.6.7.8",
		"9.10.11.12",
		"13.14.15.16",
		"17.18.19.20",
	}
	
	// Adicionar os IPs de teste ao ipset
	for _, ip := range ipsParaTestar {
		cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset add mtm-banned-ips %s", ip))
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao adicionar IP de teste %s ao ipset: %v\n%s\n", ip, err, string(output))
		} else {
			fmt.Printf("IP de teste %s adicionado ao ipset com sucesso\n", ip)
		}
	}
	
	// Verificar se os IPs foram adicionados
	listCmd := exec.Command("bash", "-c", "ipset list mtm-banned-ips")
	listOutput, _ := listCmd.CombinedOutput()
	fmt.Printf("Lista de IPs no ipset:\n%s\n", string(listOutput))
	
	// Verificar se a regra do iptables está funcionando
	iptablesCmd := exec.Command("bash", "-c", "iptables -L INPUT -v -n | grep mtm-banned-ips")
	iptablesOutput, _ := iptablesCmd.CombinedOutput()
	fmt.Printf("Regra do iptables:\n%s\n", string(iptablesOutput))
}

// enviarStatusFirewall envia o status do firewall para a API
func enviarStatusFirewall(status FirewallStatus) {
	// Log detalhado dos dados sendo enviados
	fmt.Printf("Enviando status do firewall para API: IP=%s, Tipo=%s, Ativo=%v\n", 
		status.IP, status.FirewallType, status.Active)
	
	jsonData, err := json.Marshal(status)
	if err != nil {
		fmt.Printf("Erro ao serializar status do firewall: %v\n", err)
		return
	}

	// Log do JSON sendo enviado
	fmt.Printf("JSON do status: %s\n", string(jsonData))
	
	// Usar o endpoint correto
	endpoint := "http://170.205.37.204:8081/firewall_status"
	fmt.Printf("Enviando POST para: %s\n", endpoint)
	
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao enviar status do firewall: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Ler e logar a resposta
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("Resposta da API (status %d): %s\n", resp.StatusCode, string(respBody))
	
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erro ao enviar status do firewall. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Println("Status do firewall enviado com sucesso!")
}

// enviarRegraFirewall envia uma regra de firewall para a API
func enviarRegraFirewall(rule FirewallRule) {
	// Log detalhado dos dados sendo enviados
	fmt.Printf("Enviando regra de firewall: IP=%s, Porta=%d, Protocolo=%s, Ação=%s\n", 
		rule.IP, rule.Port, rule.Protocol, rule.Action)
	
	jsonData, err := json.Marshal(rule)
	if err != nil {
		fmt.Printf("Erro ao serializar regra de firewall: %v\n", err)
		return
	}

	// Log do JSON sendo enviado
	fmt.Printf("JSON da regra: %s\n", string(jsonData))
	
	// Usar o endpoint correto
	endpoint := "http://170.205.37.204:8081/firewall_rules"
	fmt.Printf("Enviando POST para: %s\n", endpoint)
	
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao enviar regra de firewall: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Ler e logar a resposta
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("Resposta da API (status %d): %s\n", resp.StatusCode, string(respBody))
	
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erro ao enviar regra de firewall. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Println("Regra de firewall enviada com sucesso!")
}

// enviarRegrasFirewallPadrao envia as regras padrão do firewall para a API
func enviarRegrasFirewallPadrao(localIP string) {
	// Lista de regras padrão a serem enviadas
	regras := []struct {
		Porta       int
		Protocolo   string
		Descricao   string
		Prioridade  int
	}{
		{22, "tcp", "SSH - Acesso seguro remoto", 100},
		{80, "tcp", "HTTP - Tráfego web não criptografado", 90},
		{443, "tcp", "HTTPS - Tráfego web criptografado", 90},
		{9001, "tcp", "API Local MTM Agent", 80},
		{8080, "tcp", "Traefik Dashboard", 70},
		{9000, "tcp", "Portainer - Gerenciamento de contêineres", 70},
		{2377, "tcp", "Docker Swarm - Gerenciamento do cluster", 60},
		{7946, "tcp", "Docker Swarm - Comunicação entre nós (TCP)", 60},
		{7946, "udp", "Docker Swarm - Comunicação entre nós (UDP)", 60},
		{4789, "udp", "Docker Swarm - Tráfego overlay", 60},
	}

	// Enviar cada regra para a API
	fmt.Println("Enviando regras padrão de firewall para a API...")
	for _, r := range regras {
		rule := FirewallRule{
			IP:          localIP,
			Port:        r.Porta,
			Protocol:    r.Protocolo,
			Action:      "allow",
			Description: r.Descricao,
			Source:      "0.0.0.0/0", // Qualquer origem
			Active:      true,
			Priority:    r.Prioridade,
			FirewallType: firewallType,
		}
		
		enviarRegraFirewall(rule)
	}

	fmt.Println("Todas as regras padrão foram enviadas!")
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
	// Endpoint para gerenciar IPs (banir/desbanir)
	http.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			IP    string `json:"ip"`
			Acao  string `json:"acao"` // "banir" ou "desbanir"
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Verificar se o IP é válido
		if net.ParseIP(payload.IP) == nil {
			http.Error(w, "IP inválido", http.StatusBadRequest)
			return
		}

		// Verificar se a ação é válida
		if payload.Acao != "banir" && payload.Acao != "desbanir" {
			http.Error(w, "Ação inválida. Deve ser 'banir' ou 'desbanir'", http.StatusBadRequest)
			return
		}

		// Verificar se o ipset está instalado
		checkIpsetCmd := exec.Command("bash", "-c", "command -v ipset || echo 'not-installed'")
		ipsetOutput, _ := checkIpsetCmd.CombinedOutput()
		if strings.Contains(string(ipsetOutput), "not-installed") {
			// Instalar ipset se não estiver disponível
			fmt.Println("ipset não está instalado. Instalando...")
			installCmd := exec.Command("bash", "-c", "apt-get update && apt-get install -y ipset")
			installOutput, err := installCmd.CombinedOutput()
			if err != nil {
				fmt.Printf("Erro ao instalar ipset: %v\n%s\n", err, string(installOutput))
				http.Error(w, "Erro ao instalar ipset", http.StatusInternalServerError)
				return
			}
		}

		// Criar o conjunto ipset se não existir
		exec.Command("bash", "-c", "ipset create -exist mtm-banned-ips hash:ip").Run()

		// Garantir que a regra do iptables que usa o ipset exista
		checkRuleCmd := exec.Command("bash", "-c", "iptables -C INPUT -m set --match-set mtm-banned-ips src -j DROP 2>/dev/null || echo 'not-exists'")
		output, _ := checkRuleCmd.CombinedOutput()
		if strings.Contains(string(output), "not-exists") {
			exec.Command("bash", "-c", "iptables -A INPUT -m set --match-set mtm-banned-ips src -j DROP").Run()
		}

		var resultMsg string

		if payload.Acao == "banir" {
			// Adicionar o IP ao ipset
			cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset add mtm-banned-ips %s", payload.IP))
			actionOutput, err := cmd.CombinedOutput()
			if err != nil {
				// Verificar se o erro é porque o IP já está no conjunto
				if strings.Contains(string(actionOutput), "already") {
					resultMsg = fmt.Sprintf("IP já está banido: %s", payload.IP)
				} else {
					fmt.Printf("Erro ao banir IP %s: %v\n%s\n", payload.IP, err, string(actionOutput))
					http.Error(w, fmt.Sprintf("Erro ao banir IP: %v", err), http.StatusInternalServerError)
					return
				}
			} else {
				resultMsg = fmt.Sprintf("IP banido com sucesso: %s", payload.IP)
			}
		} else { // desbanir
			// Remover o IP do ipset
			cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset del mtm-banned-ips %s 2>/dev/null || echo 'not-in-set'", payload.IP))
			actionOutput, err := cmd.CombinedOutput()
			if err != nil && !strings.Contains(string(actionOutput), "not-in-set") {
				fmt.Printf("Erro ao desbanir IP %s: %v\n%s\n", payload.IP, err, string(actionOutput))
				http.Error(w, fmt.Sprintf("Erro ao desbanir IP: %v", err), http.StatusInternalServerError)
				return
			}

			// Verificar se o IP estava no conjunto
			if strings.Contains(string(actionOutput), "not-in-set") {
				resultMsg = fmt.Sprintf("IP não estava banido: %s", payload.IP)
			} else {
				resultMsg = fmt.Sprintf("IP desbanido com sucesso: %s", payload.IP)
			}
		}

		// Salvar o ipset para persistência
		exec.Command("bash", "-c", "ipset save > /etc/ipset.conf").Run()

		fmt.Println(resultMsg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": resultMsg,
		})
	})

	// Endpoint /unban foi substituído pelo /ip com ação "desbanir"

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

	// Endpoint para gerenciar whitelist (adicionar/excluir IPs)
	http.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			IP    string `json:"ip"`
			Acao  string `json:"acao"` // "adicionar" ou "excluir"
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Verificar se o IP é válido
		if net.ParseIP(payload.IP) == nil {
			http.Error(w, "IP inválido", http.StatusBadRequest)
			return
		}

		// Verificar se a ação é válida
		if payload.Acao != "adicionar" && payload.Acao != "excluir" {
			http.Error(w, "Ação inválida. Deve ser 'adicionar' ou 'excluir'", http.StatusBadRequest)
			return
		}

		// Verificar se o ipset está instalado
		checkIpsetCmd := exec.Command("bash", "-c", "command -v ipset || echo 'not-installed'")
		ipsetOutput, _ := checkIpsetCmd.CombinedOutput()
		if strings.Contains(string(ipsetOutput), "not-installed") {
			// Instalar ipset se não estiver disponível
			fmt.Println("ipset não está instalado. Instalando...")
			installCmd := exec.Command("bash", "-c", "apt-get update && apt-get install -y ipset")
			installOutput, err := installCmd.CombinedOutput()
			if err != nil {
				fmt.Printf("Erro ao instalar ipset: %v\n%s\n", err, string(installOutput))
				http.Error(w, "Erro ao instalar ipset", http.StatusInternalServerError)
				return
			}
		}

		// Criar o conjunto whitelist se não existir
		exec.Command("bash", "-c", "ipset create -exist mtm-whitelist hash:ip").Run()

		// Garantir que a regra do iptables que usa a whitelist exista
		checkRuleCmd := exec.Command("bash", "-c", "iptables -C INPUT -m set --match-set mtm-whitelist src -j ACCEPT 2>/dev/null || echo 'not-exists'")
		output, _ := checkRuleCmd.CombinedOutput()
		if strings.Contains(string(output), "not-exists") {
			// Adicionar a regra ANTES da regra de DROP para garantir que IPs na whitelist não sejam bloqueados
			exec.Command("bash", "-c", "iptables -I INPUT 1 -m set --match-set mtm-whitelist src -j ACCEPT").Run()
		}

		var resultMsg string

		if payload.Acao == "adicionar" {
			// Adicionar o IP à whitelist
			cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset add mtm-whitelist %s", payload.IP))
			actionOutput, err := cmd.CombinedOutput()
			if err != nil {
				// Verificar se o erro é porque o IP já está no conjunto
				if strings.Contains(string(actionOutput), "already") {
					resultMsg = fmt.Sprintf("IP já está na whitelist: %s", payload.IP)
				} else {
					fmt.Printf("Erro ao adicionar IP %s à whitelist: %v\n%s\n", payload.IP, err, string(actionOutput))
					http.Error(w, fmt.Sprintf("Erro ao adicionar IP à whitelist: %v", err), http.StatusInternalServerError)
					return
				}
			} else {
				resultMsg = fmt.Sprintf("IP adicionado à whitelist com sucesso: %s", payload.IP)
				
				// Remover o IP da lista de banidos, se estiver lá
				exec.Command("bash", "-c", fmt.Sprintf("ipset del mtm-banned-ips %s 2>/dev/null || true", payload.IP)).Run()
			}
		} else { // excluir
			// Remover o IP da whitelist
			cmd := exec.Command("bash", "-c", fmt.Sprintf("ipset del mtm-whitelist %s 2>/dev/null || echo 'not-in-set'", payload.IP))
			actionOutput, err := cmd.CombinedOutput()
			if err != nil && !strings.Contains(string(actionOutput), "not-in-set") {
				fmt.Printf("Erro ao remover IP %s da whitelist: %v\n%s\n", payload.IP, err, string(actionOutput))
				http.Error(w, fmt.Sprintf("Erro ao remover IP da whitelist: %v", err), http.StatusInternalServerError)
				return
			}

			// Verificar se o IP estava no conjunto
			if strings.Contains(string(actionOutput), "not-in-set") {
				resultMsg = fmt.Sprintf("IP não estava na whitelist: %s", payload.IP)
			} else {
				resultMsg = fmt.Sprintf("IP removido da whitelist com sucesso: %s", payload.IP)
			}
		}

		// Salvar o ipset para persistência
		exec.Command("bash", "-c", "ipset save > /etc/ipset.conf").Run()

		fmt.Println(resultMsg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": resultMsg,
		})
	})

	// Endpoint para gerenciar regras por domínio
	http.HandleFunc("/domain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Domain string `json:"domain"`
			Acao   string `json:"acao"` // "block" ou "allow"
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validar payload
		if payload.Domain == "" {
			http.Error(w, "Domínio não pode ser vazio", http.StatusBadRequest)
			return
		}

		if payload.Acao != "block" && payload.Acao != "allow" {
			http.Error(w, "Ação inválida. Deve ser 'block' ou 'allow'", http.StatusBadRequest)
			return
		}

		// Resolver o domínio para obter os IPs
		ips, err := net.LookupHost(payload.Domain)
		if err != nil {
			fmt.Printf("Erro ao resolver domínio %s: %v\n", payload.Domain, err)
			http.Error(w, fmt.Sprintf("Erro ao resolver domínio: %v", err), http.StatusInternalServerError)
			return
		}

		if len(ips) == 0 {
			http.Error(w, "Não foi possível resolver o domínio para nenhum IP", http.StatusBadRequest)
			return
		}

		// Verificar se o ipset está instalado
		checkIpsetCmd := exec.Command("bash", "-c", "command -v ipset || echo 'not-installed'")
		ipsetOutput, _ := checkIpsetCmd.CombinedOutput()
		if strings.Contains(string(ipsetOutput), "not-installed") {
			// Instalar ipset se não estiver disponível
			fmt.Println("ipset não está instalado. Instalando...")
			installCmd := exec.Command("bash", "-c", "apt-get update && apt-get install -y ipset")
			installOutput, err := installCmd.CombinedOutput()
			if err != nil {
				fmt.Printf("Erro ao instalar ipset: %v\n%s\n", err, string(installOutput))
				http.Error(w, "Erro ao instalar ipset", http.StatusInternalServerError)
				return
			}
		}

		// Nome do conjunto para o domínio (sanitizado para uso no ipset)
		setName := "mtm-domain-" + strings.Replace(strings.Replace(payload.Domain, ".", "-", -1), "_", "-", -1)
		if len(setName) > 31 {
			// ipset tem limite de 31 caracteres para nomes de conjuntos
			setName = setName[:31]
		}

		// Criar o conjunto para o domínio se não existir
		exec.Command("bash", "-c", fmt.Sprintf("ipset create -exist %s hash:ip", setName)).Run()

		// Adicionar todos os IPs do domínio ao conjunto
		for _, ip := range ips {
			exec.Command("bash", "-c", fmt.Sprintf("ipset add %s %s 2>/dev/null || true", setName, ip)).Run()
			fmt.Printf("IP %s adicionado ao conjunto %s\n", ip, setName)
		}

		// Verificar se a regra já existe e removê-la se existir (para evitar duplicação)
		var actionValue string
		if payload.Acao == "block" {
			actionValue = "DROP"
		} else {
			actionValue = "ACCEPT"
		}
		checkRuleCmd := exec.Command("bash", "-c", fmt.Sprintf("iptables -C INPUT -m set --match-set %s src -j %s 2>/dev/null || echo 'not-exists'", 
			setName, actionValue))
		checkOutput, _ := checkRuleCmd.CombinedOutput()
		if !strings.Contains(string(checkOutput), "not-exists") {
			// Remover regra existente
			exec.Command("bash", "-c", fmt.Sprintf("iptables -D INPUT -m set --match-set %s src -j %s", 
				setName, actionValue)).Run()
		}

		// Adicionar a regra de firewall
		action := "DROP"
		if payload.Acao == "allow" {
			action = "ACCEPT"
		}

		// Posição da regra: se for ACCEPT, colocar no início; se for DROP, colocar no final
		position := ""
		if payload.Acao == "allow" {
			position = "-I INPUT 1"
		} else {
			position = "-A INPUT"
		}

		cmd := exec.Command("bash", "-c", fmt.Sprintf("iptables %s -m set --match-set %s src -j %s", 
			position, setName, action))
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao configurar regra para domínio %s: %v\n%s\n", payload.Domain, err, string(output))
			http.Error(w, fmt.Sprintf("Erro ao configurar regra: %v", err), http.StatusInternalServerError)
			return
		}

		// Salvar regras do iptables e ipset para persistência
		exec.Command("bash", "-c", "iptables-save > /etc/iptables/rules.v4").Run()
		exec.Command("bash", "-c", "ipset save > /etc/ipset.conf").Run()

		resultMsg := fmt.Sprintf("Domínio %s configurado com sucesso para %s (%d IPs)", 
			payload.Domain, payload.Acao, len(ips))
		fmt.Println(resultMsg)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": resultMsg,
			"ips":     ips,
			"set_name": setName,
		})
	})

	// Endpoint para abrir/fechar porta
	http.HandleFunc("/port", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Acao     string `json:"acao"` // "open" ou "close"
			Source   string `json:"source"` // opcional, padrão "0.0.0.0/0"
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validar payload
		if payload.Port <= 0 || payload.Port > 65535 {
			http.Error(w, "Porta inválida. Deve estar entre 1 e 65535", http.StatusBadRequest)
			return
		}

		if payload.Protocol != "tcp" && payload.Protocol != "udp" {
			http.Error(w, "Protocolo inválido. Deve ser 'tcp' ou 'udp'", http.StatusBadRequest)
			return
		}

		if payload.Acao != "open" && payload.Acao != "close" {
			http.Error(w, "Ação inválida. Deve ser 'open' ou 'close'", http.StatusBadRequest)
			return
		}

		// Definir source padrão se não especificado
		if payload.Source == "" {
			payload.Source = "0.0.0.0/0"
		}

		// Verificar se a regra já existe
		checkCmd := exec.Command("bash", "-c", fmt.Sprintf("iptables -C INPUT -p %s --dport %d -s %s -j ACCEPT 2>/dev/null || echo 'not-exists'", 
			payload.Protocol, payload.Port, payload.Source))
		checkOutput, _ := checkCmd.CombinedOutput()
		ruleExists := !strings.Contains(string(checkOutput), "not-exists")

		var cmd *exec.Cmd
		var resultMsg string

		if payload.Acao == "open" {
			if ruleExists {
				resultMsg = fmt.Sprintf("Porta %d/%s já está aberta para %s", payload.Port, payload.Protocol, payload.Source)
			} else {
				// Adicionar regra para abrir a porta
				cmd = exec.Command("bash", "-c", fmt.Sprintf("iptables -A INPUT -p %s --dport %d -s %s -j ACCEPT", 
					payload.Protocol, payload.Port, payload.Source))
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("Erro ao abrir porta %d/%s: %v\n%s\n", payload.Port, payload.Protocol, err, string(output))
					http.Error(w, fmt.Sprintf("Erro ao abrir porta: %v", err), http.StatusInternalServerError)
					return
				}
				resultMsg = fmt.Sprintf("Porta %d/%s aberta com sucesso para %s", payload.Port, payload.Protocol, payload.Source)
			}
		} else { // close
			if !ruleExists {
				resultMsg = fmt.Sprintf("Porta %d/%s já está fechada para %s", payload.Port, payload.Protocol, payload.Source)
			} else {
				// Remover regra para fechar a porta
				cmd = exec.Command("bash", "-c", fmt.Sprintf("iptables -D INPUT -p %s --dport %d -s %s -j ACCEPT", 
					payload.Protocol, payload.Port, payload.Source))
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("Erro ao fechar porta %d/%s: %v\n%s\n", payload.Port, payload.Protocol, err, string(output))
					http.Error(w, fmt.Sprintf("Erro ao fechar porta: %v", err), http.StatusInternalServerError)
					return
				}
				resultMsg = fmt.Sprintf("Porta %d/%s fechada com sucesso para %s", payload.Port, payload.Protocol, payload.Source)
			}
		}

		// Salvar regras do iptables para persistência
		exec.Command("bash", "-c", "iptables-save > /etc/iptables/rules.v4").Run()

		fmt.Println(resultMsg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": resultMsg,
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
		// Usar uma abordagem mais eficiente com grep para filtrar por data
		fmt.Println("Executando comando para obter falhas de login dos últimos 8 minutos...")
		
		// Obter o timestamp de 8 minutos atrás no formato que o lastb usa
		timeCmd := exec.Command("bash", "-c", "date -d '8 minutes ago' '+%b %d %H:%M'")
		timeOutput, err := timeCmd.Output()
		if err != nil {
			return nil, fmt.Errorf("erro ao obter timestamp: %v", err)
		}
		timeThreshold := strings.TrimSpace(string(timeOutput))
		
		// Usar grep para filtrar por data antes de extrair IPs
		cmd = exec.Command("bash", "-c", 
			fmt.Sprintf("lastb -i | grep -A1000 \"%s\" | grep -o -E '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sort | uniq -c | sort -nr", 
			timeThreshold))
	}
	
	// Adicionar timeout para garantir que o comando não fique rodando indefinidamente
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Criar um novo comando com o contexto de timeout
	cmdWithContext := exec.CommandContext(ctx, "bash", "-c", cmd.Args[2])
	
	output, err := cmdWithContext.CombinedOutput()
	
	if err != nil {
		// Verificar se o erro é devido ao timeout
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Println("Comando cancelado por timeout após 30 segundos")
			// Retornar dados parciais se disponíveis
			if len(output) == 0 {
				return nil, fmt.Errorf("comando cancelado por timeout sem saída")
			}
		} else if len(output) == 0 {
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

// coletarEEnviarMetricasProcessos coleta e envia métricas de processos a cada 10 segundos
func coletarEEnviarMetricasProcessos(localIP string) {
	// Executar a cada 10 segundos
	ticker := time.NewTicker(10 * time.Second)
	
	for range ticker.C {
		// Obter hostname do servidor
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("Erro ao obter hostname: %v\n", err)
			hostname = "unknown"
		}
		
		// Criar objeto de informações do servidor
		serverInfo := ServerInfo{
			IP:       localIP,
			Hostname: hostname,
		}
		
		// Coletar top processos por CPU
		cmdCPU := exec.Command("bash", "-c", "ps -eo pid,user,pcpu,pmem,rss,cmd --sort=-pcpu | head -n 21")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmdCPU = exec.CommandContext(ctx, "bash", "-c", "ps -eo pid,user,pcpu,pmem,rss,cmd --sort=-pcpu | head -n 21")
		outputCPU, err := cmdCPU.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao coletar estatísticas de CPU: %v\n", err)
			continue
		}
		
		// Coletar top processos por RAM
		cmdRAM := exec.Command("bash", "-c", "ps -eo pid,user,pcpu,pmem,rss,cmd --sort=-pmem | head -n 21")
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		cmdRAM = exec.CommandContext(ctx2, "bash", "-c", "ps -eo pid,user,pcpu,pmem,rss,cmd --sort=-pmem | head -n 21")
		outputRAM, err := cmdRAM.CombinedOutput()
		if err != nil {
			fmt.Printf("Erro ao coletar estatísticas de RAM: %v\n", err)
			continue
		}
		
		// Processar saídas
		processosCPU := processarSaidaPS(string(outputCPU), "cpu")
		processosRAM := processarSaidaPS(string(outputRAM), "ram")
		
		// Coletar métricas do sistema (CPU, memória, disco)
		systemMetrics, err := coletarMetricasSistema()
		if err != nil {
			fmt.Printf("Erro ao coletar métricas do sistema: %v\n", err)
			// Continuar mesmo com erro, usando uma estrutura vazia
			systemMetrics = SystemMetrics{}
		}
		
		// Montar objeto final no formato esperado pela API
		metricas := ProcessMetricsAPI{
			ServerInfo: serverInfo,
			TopProcesses: TopProcessList{
				ByCPU: processosCPU,
				ByRAM: processosRAM,
			},
			SystemMetrics: systemMetrics,
		}
		
		// Verificar se temos dados de CPU cores para enviar
		if len(systemMetrics.CPUCores) == 0 {
			// Adicionar pelo menos um core para evitar null no banco de dados
			systemMetrics.CPUCores = []CPUCore{{
				Core:  0,
				Usage: systemMetrics.CPUUsada,
			}}
			metricas.SystemMetrics.CPUCores = systemMetrics.CPUCores
		} else {
			// Garantir que os valores de uso estão corretos
			metricas.SystemMetrics = systemMetrics
		}
		
		// Imprimir detalhes das métricas de CPU antes de enviar
		fmt.Printf("CPU Total: %.2f, CPU Usada: %.2f, CPU Livre: %.2f\n", 
			metricas.SystemMetrics.CPUTotal, metricas.SystemMetrics.CPUUsada, metricas.SystemMetrics.CPULivre)
		fmt.Printf("Cores de CPU (%d cores):\n", len(metricas.SystemMetrics.CPUCores))
		for _, core := range metricas.SystemMetrics.CPUCores {
			fmt.Printf("  Core %d: %.2f%%\n", core.Core, core.Usage)
		}
		
		// Não precisamos mais serializar as métricas originais, pois agora usamos o objeto unificado
		
		// Criar objeto unificado para enviar ao banco de dados
		metricasDB := ProcessMetricsDB{
			ServerInfo:    serverInfo,
			Processes:     ProcessesList{
				ByCPU: processosCPU,
				ByRAM: processosRAM,
			},
			SystemMetrics: metricas.SystemMetrics,
		}
		
		// Serializar para JSON o objeto unificado
		jsonDataDB, err := json.Marshal(metricasDB)
		if err != nil {
			fmt.Printf("Erro ao serializar métricas para DB: %v\n", err)
			continue
		}
		
		// Imprimir JSON para debug (remover em produção)
		// fmt.Printf("JSON enviado: %s\n", string(jsonDataDB))
		
		// Enviar para a API (uma única linha com todos os dados)
		resp, err := http.Post("http://170.205.37.204:8081/process_metrics", 
						  "application/json", 
						  bytes.NewBuffer(jsonDataDB))
		if err != nil {
			fmt.Printf("Erro ao enviar métricas unificadas: %v\n", err)
			continue
		}
		defer resp.Body.Close()
		
		// Verificar resposta
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Erro ao enviar métricas unificadas. Status: %d, Resposta: %s\n", 
				resp.StatusCode, string(respBody))
		} else {
			fmt.Println("Métricas unificadas enviadas com sucesso")
		}
	}
}

// processarSaidaPS processa a saída do comando ps
func processarSaidaPS(saida string, tipo string) []ProcessInfo {
	linhas := strings.Split(saida, "\n")
	if len(linhas) < 2 {
		return []ProcessInfo{}
	}
	
	// Ignorar a primeira linha (cabeçalho)
	var resultados []ProcessInfo
	
	for i := 1; i < len(linhas) && i <= 20; i++ { // Limitar a 20 processos
		linha := strings.TrimSpace(linhas[i])
		if linha == "" {
			continue
		}
		
		campos := strings.Fields(linha)
		if len(campos) < 6 {
			continue
		}
		
		pid, _ := strconv.Atoi(campos[0])
		cpuPercent, _ := strconv.ParseFloat(campos[2], 64)
		ramPercent, _ := strconv.ParseFloat(campos[3], 64)
		rssKB, _ := strconv.Atoi(campos[4])
		
		// Reconstruir o comando (pode conter espaços)
		cmd := strings.Join(campos[5:], " ")
		
		processo := ProcessInfo{
			PID:        pid,
			User:       campos[1],
			CPUPercent: cpuPercent,
			RAMPercent: ramPercent,
			RssKB:      rssKB,
			Command:    cmd,
			Rank:       i, // Posição no ranking
		}
		
		resultados = append(resultados, processo)
	}
	
	return resultados
}

// coletarMetricasCPU coleta métricas de CPU do sistema usando mpstat
func coletarMetricasCPU() (SystemMetrics, error) {
	var metrics SystemMetrics
	
	// Executar o comando mpstat para obter uso de CPU por core
	cmdCPU := exec.Command("bash", "-c", "mpstat -P ALL 1 1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmdCPU = exec.CommandContext(ctx, "bash", "-c", "mpstat -P ALL 1 1")
	outputCPU, err := cmdCPU.CombinedOutput()
	if err != nil {
		// Tentar alternativa se mpstat falhar
		return coletarMetricasCPUAlternativa(0)
	}
	
	// Processar saída do mpstat
	linhas := strings.Split(string(outputCPU), "\n")
	var cpuCores []CPUCore
	var cpuTotal float64
	
	// Mapa para rastrear quais cores já foram processados
	coresProcessados := make(map[int]bool)
	
	// Primeiro, vamos verificar o número real de cores usando nproc
	cmdNproc := exec.Command("bash", "-c", "nproc")
	ctxNproc, cancelNproc := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelNproc()
	cmdNproc = exec.CommandContext(ctxNproc, "bash", "-c", "nproc")
	outputNproc, err := cmdNproc.CombinedOutput()
	
	// Número de cores físicos
	numCores := 1 // Valor padrão se não conseguir determinar
	if err == nil {
		n, err := strconv.Atoi(strings.TrimSpace(string(outputNproc)))
		if err == nil && n > 0 {
			numCores = n
		}
	}
	
	// Processar linhas do mpstat (ignorar cabeçalhos e médias)
	processandoPrimeiroBloco := true
	for _, linha := range linhas {
		linha = strings.TrimSpace(linha)
		
		// Pular linhas vazias, cabeçalhos e médias
		if linha == "" || 
		   strings.Contains(linha, "Linux") || 
		   strings.Contains(linha, "CPU") || 
		   strings.Contains(linha, "Average") {
			continue
		}
		
		// Se encontrarmos a linha "Average:", estamos no segundo bloco
		if strings.HasPrefix(linha, "Average:") {
			processandoPrimeiroBloco = false
			continue
		}
		
		// Só processar o primeiro bloco de dados
		if !processandoPrimeiroBloco {
			continue
		}
		
		campos := strings.Fields(linha)
		if len(campos) < 4 { // Precisamos de pelo menos CPU, %usr
			continue
		}
		
		// Extrair o ID do core e o valor de uso (%usr)
		var coreID int
		var err error
		
		// O campo 1 é o identificador do core (all, 0, 1, 2, etc.)
		if campos[1] == "all" {
			coreID = -1 // Representa o total de todas as CPUs
		} else {
			coreID, err = strconv.Atoi(campos[1])
			if err != nil {
				continue // Pular se não conseguir extrair o número
			}
		}
		
		// O campo 2 é o valor de %usr (destacado em vermelho na captura de tela)
		usage, err := strconv.ParseFloat(campos[2], 64)
		if err != nil {
			continue
		}
		
		// Adicionar outros componentes de uso se disponíveis
		if len(campos) >= 5 {
			// Adicionar %sys (campo 4)
			sys, err := strconv.ParseFloat(campos[4], 64)
			if err == nil {
				usage += sys
			}
		}
		
		// Garantir que o valor está entre 0 e 100
		if usage < 0 {
			usage = 0
		} else if usage > 100 {
			usage = 100
		}
		
		fmt.Printf("Core %d: %%usr=%.2f%%\n", coreID, usage)
		
		if coreID == -1 {
			// Total de todas as CPUs
			cpuTotal = usage
		} else if coreID < numCores && !coresProcessados[coreID] {
			// Adicionar à lista de métricas por núcleo
			cpuCores = append(cpuCores, CPUCore{
				Core:  coreID,
				Usage: usage,
			})
			coresProcessados[coreID] = true
		}
	}
	
	metrics.CPUCores = cpuCores
	metrics.CPUTotal = 100.0 // Capacidade total sempre é 100%
	metrics.CPUUsada = cpuTotal
	metrics.CPULivre = 100.0 - cpuTotal
	
	// Ordenar os cores por ID para garantir a ordem correta
	sort.Slice(metrics.CPUCores, func(i, j int) bool {
		return metrics.CPUCores[i].Core < metrics.CPUCores[j].Core
	})
	
	return metrics, nil
}

// coletarMetricasCPUAlternativa coleta métricas de CPU usando /proc/stat como backup
func coletarMetricasCPUAlternativa(numCores int) (SystemMetrics, error) {
	var metrics SystemMetrics
	
	// Se não temos o número de cores, tentar descobrir
	if numCores <= 0 {
		// Tentar obter o número de cores usando nproc
		cmdNproc := exec.Command("bash", "-c", "nproc")
		ctxNproc, cancelNproc := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelNproc()
		cmdNproc = exec.CommandContext(ctxNproc, "bash", "-c", "nproc")
		outputNproc, err := cmdNproc.CombinedOutput()
		
		if err == nil {
			n, err := strconv.Atoi(strings.TrimSpace(string(outputNproc)))
			if err == nil && n > 0 {
				numCores = n
			} else {
				numCores = 1 // Valor padrão se não conseguir determinar
			}
		} else {
			numCores = 1 // Valor padrão se não conseguir determinar
		}
	}
	
	// Ler /proc/stat para obter informações de CPU
	conteudo, err := os.ReadFile("/proc/stat")
	if err != nil {
		return metrics, fmt.Errorf("erro ao ler /proc/stat: %v", err)
	}
	
	linhas := strings.Split(string(conteudo), "\n")
	var cpuCores []CPUCore
	var cpuTotal float64
	
	// Mapa para rastrear quais cores já foram processados
	coresProcessados := make(map[int]bool)
	
	// Processar linhas do /proc/stat
	for _, linha := range linhas {
		linha = strings.TrimSpace(linha)
		if !strings.HasPrefix(linha, "cpu") {
			continue
		}
		
		campos := strings.Fields(linha)
		if len(campos) < 8 {
			continue
		}
		
		// Extrair o ID do core do nome (ex: cpu0 -> 0)
		cpuName := campos[0]
		
		// Calcular uso de CPU baseado nos valores de /proc/stat
		// Formato: cpu user nice system idle iowait irq softirq steal guest guest_nice
		user, _ := strconv.ParseFloat(campos[1], 64)
		// nice não é usado no cálculo atual
		system, _ := strconv.ParseFloat(campos[3], 64)
		
		// Calcular o uso como a soma de user + system (similar ao %usr + %sys do mpstat)
		usage := user + system
		
		// Garantir que o valor está entre 0 e 100
		if usage < 0 {
			usage = 0
		} else if usage > 100 {
			usage = 100
		}
		
		if cpuName == "cpu" {
			// Total de todas as CPUs
			cpuTotal = usage
			fmt.Printf("CPU Total (alternativo): %.2f%%\n", usage)
		} else if strings.HasPrefix(cpuName, "cpu") {
			// Core específico (cpu0, cpu1, etc.)
			coreID, err := strconv.Atoi(strings.TrimPrefix(cpuName, "cpu"))
			if err == nil && coreID < numCores && !coresProcessados[coreID] {
				cpuCores = append(cpuCores, CPUCore{
					Core:  coreID,
					Usage: usage,
				})
				coresProcessados[coreID] = true
				fmt.Printf("Core %d (alternativo): %.2f%%\n", coreID, usage)
			}
		}
	}
	
	metrics.CPUCores = cpuCores
	metrics.CPUTotal = 100.0 // Capacidade total sempre é 100%
	metrics.CPUUsada = cpuTotal
	metrics.CPULivre = 100.0 - cpuTotal
	
	// Ordenar os cores por ID para garantir a ordem correta
	sort.Slice(metrics.CPUCores, func(i, j int) bool {
		return metrics.CPUCores[i].Core < metrics.CPUCores[j].Core
	})
	
	return metrics, nil
}

// coletarMetricasMemoria coleta métricas de memória do sistema
func coletarMetricasMemoria() (SystemMetrics, error) {
	var metrics SystemMetrics
	
	// Executar o comando free para obter informações de memória
	cmdMem := exec.Command("bash", "-c", "free -m | grep Mem")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmdMem = exec.CommandContext(ctx, "bash", "-c", "free -m | grep Mem")
	outputMem, err := cmdMem.CombinedOutput()
	if err != nil {
		return metrics, fmt.Errorf("erro ao executar free: %v", err)
	}
	
	// Processar saída do free
	campos := strings.Fields(string(outputMem))
	if len(campos) < 7 {
		return metrics, fmt.Errorf("formato inesperado na saída do free")
	}
	
	// Campos: "Mem:", total, used, free, shared, buff/cache, available
	total, _ := strconv.ParseFloat(campos[1], 64)
	usada, _ := strconv.ParseFloat(campos[2], 64)
	livre, _ := strconv.ParseFloat(campos[3], 64)
	
	metrics.MemTotal = total
	metrics.MemUsada = usada
	metrics.MemLivre = livre
	
	return metrics, nil
}

// coletarMetricasDisco coleta métricas de disco do sistema
func coletarMetricasDisco() (SystemMetrics, error) {
	var metrics SystemMetrics
	
	// Executar o comando df para obter informações de disco
	cmdDisk := exec.Command("bash", "-c", "df -m / | tail -1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmdDisk = exec.CommandContext(ctx, "bash", "-c", "df -m / | tail -1")
	outputDisk, err := cmdDisk.CombinedOutput()
	if err != nil {
		return metrics, fmt.Errorf("erro ao executar df: %v", err)
	}
	
	// Processar saída do df
	campos := strings.Fields(string(outputDisk))
	if len(campos) < 6 {
		return metrics, fmt.Errorf("formato inesperado na saída do df")
	}
	
	// Campos: filesystem, 1K-blocks, used, available, use%, mounted-on
	total, _ := strconv.ParseFloat(campos[1], 64)
	usado, _ := strconv.ParseFloat(campos[2], 64)
	livre, _ := strconv.ParseFloat(campos[3], 64)
	
	metrics.DiscoTotal = total
	metrics.DiscoUsado = usado
	metrics.DiscoLivre = livre
	
	return metrics, nil
}

// coletarMetricasSistema coleta todas as métricas do sistema
func coletarMetricasSistema() (SystemMetrics, error) {
	var metrics SystemMetrics
	
	// Coletar métricas de CPU
	cpuMetrics, err := coletarMetricasCPU()
	if err != nil {
		fmt.Printf("Erro ao coletar métricas de CPU: %v\n", err)
		// Continuar mesmo com erro
	} else {
		metrics.CPUCores = cpuMetrics.CPUCores
		metrics.CPUTotal = cpuMetrics.CPUTotal
		metrics.CPUUsada = cpuMetrics.CPUUsada
		metrics.CPULivre = cpuMetrics.CPULivre
	}
	
	// Coletar métricas de memória
	memMetrics, err := coletarMetricasMemoria()
	if err != nil {
		fmt.Printf("Erro ao coletar métricas de memória: %v\n", err)
		// Continuar mesmo com erro
	} else {
		metrics.MemTotal = memMetrics.MemTotal
		metrics.MemUsada = memMetrics.MemUsada
		metrics.MemLivre = memMetrics.MemLivre
	}
	
	// Coletar métricas de disco
	diskMetrics, err := coletarMetricasDisco()
	if err != nil {
		fmt.Printf("Erro ao coletar métricas de disco: %v\n", err)
		// Continuar mesmo com erro
	} else {
		metrics.DiscoTotal = diskMetrics.DiscoTotal
		metrics.DiscoUsado = diskMetrics.DiscoUsado
		metrics.DiscoLivre = diskMetrics.DiscoLivre
	}
	
	return metrics, nil
}

// sendBannedIPsList envia a lista de IPs banidos para a API externa
func sendBannedIPsList(localIP string, failedLogins []LoginFailure) {
	// Filtrar apenas IPs com 3 ou mais falhas
	var bannedIPs []BanIP
	for _, failure := range failedLogins {
		if failure.Count >= 3 {
			bannedIPs = append(bannedIPs, BanIP{IP2Ban: failure.IP})
		}
	}
	
	// Se não houver IPs para enviar, não fazer nada
	if len(bannedIPs) == 0 {
		fmt.Println("Nenhum IP com 3 ou mais falhas para enviar")
		return
	}
	
	// Criar objeto para enviar
	payload := BanList{
		IP:      localIP,
		BanList: bannedIPs,
	}
	
	// Serializar para JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Erro ao serializar lista de IPs banidos: %v\n", err)
		return
	}
	
	// Enviar para a API
	resp, err := http.Post("http://170.205.37.204:8081/listbanip", 
					  "application/json", 
					  bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao enviar lista de IPs banidos: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	// Verificar resposta
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erro ao enviar lista de IPs banidos. Status: %d, Resposta: %s\n", 
			resp.StatusCode, string(respBody))
	} else {
		fmt.Printf("Lista de %d IPs banidos enviada com sucesso\n", len(bannedIPs))
	}
}

// dockerEstaDisponivel verifica se o Docker está instalado e em execução
func dockerEstaDisponivel() bool {
	// Comando para verificar se o Docker está em execução
	cmd := exec.Command("sh", "-c", "docker info")
	
	// Executar o comando e capturar a saída para debug
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[DOCKER] Erro ao verificar Docker: %v\n", err)
		fmt.Printf("[DOCKER] Saída do comando: %s\n", string(output))
		return false
	}
	
	return true
}

// converterParaBytes converte valores como "7.28GB" ou "156MB" para bytes
func converterParaBytes(tamanhoStr string) int64 {
	tamanhoStr = strings.TrimSpace(tamanhoStr)
	if tamanhoStr == "" || tamanhoStr == "0B" {
		return 0
	}
	
	// Extrair o valor numérico e a unidade
	var valor float64
	var unidade string
	
	// Encontrar o índice onde começa a unidade
	indiceUnidade := -1
	for i, c := range tamanhoStr {
		if c < '0' || (c > '9' && c != '.' && c != ',') {
			indiceUnidade = i
			break
		}
	}
	
	if indiceUnidade == -1 {
		// Sem unidade, assumir bytes
		valor, _ = strconv.ParseFloat(tamanhoStr, 64)
		return int64(valor)
	}
	
	// Extrair valor e unidade
	valorStr := tamanhoStr[:indiceUnidade]
	// Substituir vírgula por ponto para parsing correto
	valorStr = strings.Replace(valorStr, ",", ".", -1)
	valor, _ = strconv.ParseFloat(valorStr, 64)
	unidade = tamanhoStr[indiceUnidade:]
	
	// Converter para bytes baseado na unidade
	switch strings.ToUpper(unidade) {
	case "B":
		return int64(valor)
	case "KB", "KIB":
		return int64(valor * 1024)
	case "MB", "MIB":
		return int64(valor * 1024 * 1024)
	case "GB", "GIB":
		return int64(valor * 1024 * 1024 * 1024)
	case "TB", "TIB":
		return int64(valor * 1024 * 1024 * 1024 * 1024)
	default:
		// Unidade desconhecida, retornar o valor original
		return int64(valor)
	}
}

// formatarBytes formata bytes para uma representação legível
func formatarBytes(bytes int64) string {
	const (
		_          = iota
		KB float64 = 1 << (10 * iota)
		MB
		GB
		TB
	)
	
	var valor float64
	var unidade string
	
	switch {
	case bytes >= int64(TB):
		valor = float64(bytes) / TB
		unidade = "TB"
	case bytes >= int64(GB):
		valor = float64(bytes) / GB
		unidade = "GB"
	case bytes >= int64(MB):
		valor = float64(bytes) / MB
		unidade = "MB"
	case bytes >= int64(KB):
		valor = float64(bytes) / KB
		unidade = "KB"
	default:
		valor = float64(bytes)
		unidade = "B"
	}
	
	return fmt.Sprintf("%.2f%s", valor, unidade)
}

// processarEstatisticasRede processa as estatísticas de rede dos containers
func processarEstatisticasRede(containers []ContainerStats) NetworkStats {
	var totalRXBytes, totalTXBytes int64
	
	for i := range containers {
		// Extrair informações de rede (NetIO)
		if containers[i].NetIO != "" {
			parts := strings.Split(containers[i].NetIO, "/")
			if len(parts) == 2 {
				rxStr := strings.TrimSpace(parts[0])
				txStr := strings.TrimSpace(parts[1])
				
				// Converter para bytes
				rxBytes := converterParaBytes(rxStr)
				txBytes := converterParaBytes(txStr)
				
				// Armazenar valores no formato antigo
				containers[i].NetIORXBytes = rxBytes
				containers[i].NetIOTXBytes = txBytes
				containers[i].NetIO_RX_Bytes = float64(rxBytes)
				containers[i].NetIO_TX_Bytes = float64(txBytes)
				containers[i].NetIO_RX_Formatted = rxStr
				containers[i].NetIO_TX_Formatted = txStr
				
				// Acumular totais
				totalRXBytes += rxBytes
				totalTXBytes += txBytes
			}
		}
	}
	
	// Formatar os totais para exibição
	totalRXFormatted := formatarBytes(totalRXBytes)
	totalTXFormatted := formatarBytes(totalTXBytes)
	totalBandwidth := formatarBytes(totalRXBytes + totalTXBytes)
	
	return NetworkStats{
		TotalRXBytes:     totalRXBytes,
		TotalTXBytes:     totalTXBytes,
		TotalRXFormatted: totalRXFormatted,
		TotalTXFormatted: totalTXFormatted,
		TotalBandwidth:   totalBandwidth,
	}
}

// coletarDockerStats coleta estatísticas dos containers Docker
func coletarDockerStats() ([]ContainerStats, error) {
	// Verificar se o Docker está disponível
	if !dockerEstaDisponivel() {
		return nil, fmt.Errorf("Docker não está disponível")
	}
	
	// Executar o comando docker stats para obter estatísticas
	cmd := exec.Command("sh", "-c", "docker stats --no-stream --format '{{json .}}'")
	
	// Executar o comando e capturar a saída
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[DOCKER] Erro ao executar 'docker stats': %v\n", err)
		fmt.Printf("[DOCKER] Saída do comando: %s\n", string(output))
		return nil, fmt.Errorf("erro ao executar docker stats: %v", err)
	}
	
	// Imprimir a saída para debug
	fmt.Printf("[DOCKER] Saída do comando 'docker stats': %s\n", string(output))
	
	// Processar a saída linha por linha
	lines := strings.Split(string(output), "\n")
	containers := make([]ContainerStats, 0)
	
	fmt.Printf("[DOCKER] Processando %d linhas de saída\n", len(lines))
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		fmt.Printf("[DOCKER] Processando linha %d: %s\n", i+1, line)
		
		// Processar o JSON
		var container map[string]string
		err := json.Unmarshal([]byte(line), &container)
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao decodificar JSON: %v, linha: %s\n", err, line)
			continue
		}
		
		// Imprimir as chaves encontradas para debug
		fmt.Printf("[DOCKER] Container JSON decodificado com sucesso. Chaves encontradas: ")
		for k := range container {
			fmt.Printf("%s, ", k)
		}
		fmt.Println()
		
		// Extrair informações básicas do container
		containerStats := ContainerStats{
			ID:        container["ID"],
			Name:      container["Name"],
			MemUsage:  container["MemUsage"],
			NetIO:     container["NetIO"],
			BlockIO:   container["BlockIO"],
			Container: container["ID"],  // Campo adicional para compatibilidade
			CPUPerc:   container["CPUPerc"],
			MemPerc:   container["MemPerc"],
			PIDs:      container["PIDs"],
		}
		
		// Processar CPU% (armazenar como float para cálculos internos)
		if cpuStr, ok := container["CPUPerc"]; ok {
			cpuStr = strings.TrimSuffix(cpuStr, "%")
			cpuPercent, err := strconv.ParseFloat(cpuStr, 64)
			if err == nil {
				containerStats.CPUPercent = cpuPercent
			}
		}
		
		// Processar MEM% (armazenar como float para cálculos internos)
		if memStr, ok := container["MemPerc"]; ok {
			memStr = strings.TrimSuffix(memStr, "%")
			memPercent, err := strconv.ParseFloat(memStr, 64)
			if err == nil {
				containerStats.MemPercent = memPercent
			}
		}
		
		// Processar PIDs (armazenar como int para cálculos internos)
		if pidsStr, ok := container["PIDs"]; ok {
			pids, err := strconv.Atoi(pidsStr)
			if err == nil {
				containerStats.PidsCount = pids
			}
		}
		
		containers = append(containers, containerStats)
	}
	
	return containers, nil
}

// coletarEEnviarMetricasDocker coleta e envia métricas do Docker a cada 10 segundos
func coletarEEnviarMetricasDocker(localIP string) {
	// Executar a cada 10 segundos
	ticker := time.NewTicker(10 * time.Second)
	
	// Função para coletar e enviar métricas
	coletarEEnviar := func() {
		fmt.Println("====================================================")
		fmt.Println("[DOCKER] Verificando disponibilidade do Docker...")
		
		// Verificar se o Docker está disponível
		if !dockerEstaDisponivel() {
			fmt.Println("[DOCKER] Docker não está disponível, pulando coleta de métricas")
			return
		}
		
		fmt.Println("[DOCKER] Docker disponível, prosseguindo com a coleta")
		
		// Obter hostname do servidor (apenas para log)
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao obter hostname: %v\n", err)
			hostname = "unknown"
		}
		
		fmt.Printf("[DOCKER] Hostname do servidor: %s\n", hostname)
		
		fmt.Println("[DOCKER] Iniciando coleta de estatísticas dos containers...")
		
		// Coletar estatísticas dos containers
		containers, err := coletarDockerStats()
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao coletar estatísticas do Docker: %v\n", err)
			return
		}
		
		// Se não houver containers, não enviar métricas
		if len(containers) == 0 {
			fmt.Println("[DOCKER] Nenhum container em execução, pulando envio de métricas")
			return
		}
		
		fmt.Printf("[DOCKER] Encontrados %d containers em execução\n", len(containers))
		
		// Listar os containers encontrados
		fmt.Println("[DOCKER] Lista de containers:")
		for i, container := range containers {
			fmt.Printf("[DOCKER]   %d. %s (CPU: %s, MEM: %s)\n", 
				i+1, container.Name, container.CPUPerc, container.MemPerc)
		}
		
		// Processar estatísticas de rede
		fmt.Println("[DOCKER] Processando estatísticas de rede...")
		networkStats := processarEstatisticasRede(containers)
		
		// Obter timestamp atual
		timestamp := time.Now().Format(time.RFC3339)
		
		// Primeiro, criar e serializar os dados de estatísticas
		statsData := DockerStatsData{
			Containers:    len(containers),
			Network:       networkStats,
			ContainerList: containers,
		}
		
		// Serializar os dados de estatísticas para JSON
		statsJSON, err := json.Marshal(statsData)
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao serializar dados de estatísticas: %v\n", err)
			return
		}
		
		// Criar objeto final para enviar à API seguindo o formato exato do exemplo
		dockerStats := DockerStats{
			IP:        localIP,
			Stats:     json.RawMessage(statsJSON),
			Timestamp: timestamp,
		}
		
		// Serializar para JSON
		fmt.Println("[DOCKER] Serializando dados para JSON...")
		fmt.Printf("[DOCKER] IP da máquina: %s, Timestamp: %s\n", localIP, timestamp)
		jsonData, err := json.Marshal(dockerStats)
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao serializar estatísticas do Docker: %v\n", err)
			return
		}
		
		// Imprimir os primeiros 500 caracteres do JSON para debug
		jsonStr := string(jsonData)
		if len(jsonStr) > 500 {
			fmt.Printf("[DOCKER] JSON (primeiros 500 caracteres): %s...\n", jsonStr[:500])
		} else {
			fmt.Printf("[DOCKER] JSON completo: %s\n", jsonStr)
		}
		
		// Imprimir resumo para debug
		fmt.Printf("[DOCKER] Coletadas estatísticas de %d containers\n", len(containers))
		fmt.Printf("[DOCKER] Tráfego de rede total: RX=%s, TX=%s\n", 
			networkStats.TotalRXFormatted, networkStats.TotalTXFormatted)
		
		// Mostrar o JSON final completo que será enviado para a API
		fmt.Println("[DOCKER] JSON FINAL ENVIADO PARA API:")
		fmt.Println(string(jsonData))
		
		// Enviar para a API
		fmt.Println("[DOCKER] Enviando estatísticas para a API...")
		// Criar uma requisição HTTP com o endpoint correto
		req, err := http.NewRequest("POST", "http://170.205.37.204:8081/docker_stats", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao criar requisição HTTP: %v\n", err)
			return
		}
		
		// Definir explicitamente o Content-Type como application/json
		req.Header.Set("Content-Type", "application/json")
		
		// Enviar a requisição
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[DOCKER] Erro ao enviar estatísticas do Docker: %v\n", err)
			return
		}
		defer resp.Body.Close()
		
		// Verificar resposta
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[DOCKER] Erro ao enviar estatísticas do Docker. Status: %d, Resposta: %s\n", 
				resp.StatusCode, string(respBody))
		} else {
			fmt.Println("[DOCKER] Estatísticas do Docker enviadas com sucesso")
		}
		
		fmt.Println("[DOCKER] Ciclo de coleta e envio concluído")
		fmt.Println("====================================================")
	}
	
	// Executar imediatamente na primeira vez
	fmt.Println("[DOCKER] Iniciando primeira coleta de métricas Docker...")
	coletarEEnviar()
	
	// Depois executar a cada tick
	fmt.Println("[DOCKER] Agendando coletas periódicas a cada 10 segundos")
	for range ticker.C {
		coletarEEnviar()
	}
}
