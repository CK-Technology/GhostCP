// Firewall management with iptables/nftables and Fail2ban integration
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallManager {
    backend: FirewallBackend,
    fail2ban_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Uuid,
    pub name: String,
    pub chain: String,
    pub action: FirewallAction,
    pub protocol: Protocol,
    pub source: IpRange,
    pub destination: IpRange,
    pub port: Option<PortRange>,
    pub interface: Option<String>,
    pub enabled: bool,
    pub priority: i32,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
    Log,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Any,
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    pub ip: Option<IpAddr>,
    pub cidr: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fail2banJail {
    pub name: String,
    pub enabled: bool,
    pub port: String,
    pub protocol: String,
    pub filter: String,
    pub logpath: String,
    pub maxretry: u32,
    pub findtime: u32,
    pub bantime: u32,
    pub action: String,
}

impl FirewallManager {
    pub fn new(backend: FirewallBackend) -> Self {
        Self {
            backend,
            fail2ban_enabled: true,
        }
    }

    // Initialize firewall with basic rules
    pub async fn initialize(&self) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.init_iptables().await,
            FirewallBackend::Nftables => self.init_nftables().await,
        }
    }

    async fn init_iptables(&self) -> Result<()> {
        // Basic iptables setup
        let commands = vec![
            // Flush existing rules
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            
            // Default policies
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP", 
            "iptables -P OUTPUT ACCEPT",
            
            // Allow loopback
            "iptables -I INPUT -i lo -j ACCEPT",
            
            // Allow established connections
            "iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            
            // Allow SSH (be careful!)
            "iptables -I INPUT -p tcp --dport 22 -j ACCEPT",
            
            // Allow HTTP/HTTPS
            "iptables -I INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -I INPUT -p tcp --dport 443 -j ACCEPT",
            
            // Allow GhostCP admin panel
            "iptables -I INPUT -p tcp --dport 2083 -j ACCEPT",
            
            // Allow DNS
            "iptables -I INPUT -p tcp --dport 53 -j ACCEPT",
            "iptables -I INPUT -p udp --dport 53 -j ACCEPT",
            
            // Allow mail services
            "iptables -I INPUT -p tcp --dport 25 -j ACCEPT",   // SMTP
            "iptables -I INPUT -p tcp --dport 587 -j ACCEPT",  // Submission
            "iptables -I INPUT -p tcp --dport 993 -j ACCEPT",  // IMAPS
            "iptables -I INPUT -p tcp --dport 995 -j ACCEPT",  // POP3S
            
            // Save rules
            "iptables-save > /etc/iptables/rules.v4",
        ];

        for cmd in commands {
            let output = Command::new("sh")
                .args(&["-c", cmd])
                .output()?;
                
            if !output.status.success() {
                eprintln!("Warning: Command failed: {}", cmd);
                eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        Ok(())
    }

    async fn init_nftables(&self) -> Result<()> {
        let nft_config = r#"#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter
        policy drop

        # Allow loopback
        iif "lo" accept

        # Allow established connections
        ct state established,related accept

        # Allow SSH
        tcp dport 22 accept

        # Allow HTTP/HTTPS
        tcp dport { 80, 443 } accept

        # Allow GhostCP admin
        tcp dport 2083 accept

        # Allow DNS
        tcp dport 53 accept
        udp dport 53 accept

        # Allow mail
        tcp dport { 25, 587, 993, 995 } accept

        # Drop everything else
        drop
    }

    chain forward {
        type filter hook forward priority filter
        policy drop
    }

    chain output {
        type filter hook output priority filter
        policy accept
    }
}
"#;

        std::fs::write("/etc/nftables.conf", nft_config)?;
        
        let output = Command::new("nft")
            .args(&["-f", "/etc/nftables.conf"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to apply nftables rules: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Add firewall rule
    pub async fn add_rule(&self, rule: &FirewallRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.add_iptables_rule(rule).await,
            FirewallBackend::Nftables => self.add_nftables_rule(rule).await,
        }
    }

    async fn add_iptables_rule(&self, rule: &FirewallRule) -> Result<()> {
        let mut args = vec!["-A".to_string(), rule.chain.clone()];

        // Add protocol
        match rule.protocol {
            Protocol::TCP => {
                args.push("-p".to_string());
                args.push("tcp".to_string());
            },
            Protocol::UDP => {
                args.push("-p".to_string());
                args.push("udp".to_string());
            },
            Protocol::ICMP => {
                args.push("-p".to_string());
                args.push("icmp".to_string());
            },
            Protocol::ICMPv6 => {
                args.push("-p".to_string());
                args.push("icmpv6".to_string());
            },
            Protocol::Custom(ref proto) => {
                args.push("-p".to_string());
                args.push(proto.clone());
            },
            Protocol::Any => {},
        }

        // Add source
        if let Some(ip) = rule.source.ip {
            args.push("-s".to_string());
            if let Some(cidr) = rule.source.cidr {
                args.push(format!("{}/{}", ip, cidr));
            } else {
                args.push(ip.to_string());
            }
        }

        // Add destination
        if let Some(ip) = rule.destination.ip {
            args.push("-d".to_string());
            if let Some(cidr) = rule.destination.cidr {
                args.push(format!("{}/{}", ip, cidr));
            } else {
                args.push(ip.to_string());
            }
        }

        // Add port
        if let Some(ref port) = rule.port {
            args.push("--dport".to_string());
            if let Some(end) = port.end {
                args.push(format!("{}:{}", port.start, end));
            } else {
                args.push(port.start.to_string());
            }
        }

        // Add interface
        if let Some(ref interface) = rule.interface {
            args.push("-i".to_string());
            args.push(interface.clone());
        }

        // Add action
        args.push("-j".to_string());
        match rule.action {
            FirewallAction::Accept => args.push("ACCEPT".to_string()),
            FirewallAction::Drop => args.push("DROP".to_string()),
            FirewallAction::Reject => args.push("REJECT".to_string()),
            FirewallAction::Log => args.push("LOG".to_string()),
            FirewallAction::Return => args.push("RETURN".to_string()),
        }

        // Add comment
        if let Some(ref comment) = rule.comment {
            args.push("-m".to_string());
            args.push("comment".to_string());
            args.push("--comment".to_string());
            args.push(comment.clone());
        }

        // Execute iptables command
        let output = std::process::Command::new("iptables")
            .args(&args)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("iptables command failed: {}",
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    async fn add_nftables_rule(&self, rule: &FirewallRule) -> Result<()> {
        // Implementation for nftables rule addition
        // This is a simplified implementation
        println!("Adding nftables rule: {:?}", rule.name);
        Ok(())
    }

    pub async fn remove_rule(&self, rule_id: &Uuid) -> Result<()> {
        // In a real implementation, you'd need to track rules by ID
        // For now, this is a placeholder
        Ok(())
    }

    // Block IP address
    pub async fn block_ip(&self, ip: IpAddr, duration: Option<u32>) -> Result<()> {
        let rule = FirewallRule {
            id: Uuid::new_v4(),
            name: format!("Block {}", ip),
            chain: "INPUT".to_string(),
            action: FirewallAction::Drop,
            protocol: Protocol::Any,
            source: IpRange { ip: Some(ip), cidr: None },
            destination: IpRange { ip: None, cidr: None },
            port: None,
            interface: None,
            enabled: true,
            priority: 1000,
            comment: Some(format!("Auto-blocked IP: {}", ip)),
            created_at: Utc::now(),
        };
        
        self.add_rule(&rule).await?;
        
        // If duration is specified, schedule removal
        if let Some(seconds) = duration {
            // In a real implementation, you'd schedule this with a job queue
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(seconds as u64)).await;
                // Remove the rule
            });
        }
        
        Ok(())
    }

    // Unblock IP address
    pub async fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => {
                let output = Command::new("iptables")
                    .args(&["-D", "INPUT", "-s", &ip.to_string(), "-j", "DROP"])
                    .output()?;
                    
                if !output.status.success() {
                    return Err(anyhow!("Failed to unblock IP"));
                }
            },
            FirewallBackend::Nftables => {
                // Find and remove the rule
                let cmd = format!("nft list ruleset | grep '{}'", ip);
                let output = Command::new("sh")
                    .args(&["-c", &cmd])
                    .output()?;
                    
                // Parse output and remove matching rules
                // This is a simplified implementation
            }
        }
        
        Ok(())
    }

    // Setup Fail2ban
    pub async fn setup_fail2ban(&self) -> Result<()> {
        // Install fail2ban if not present
        let output = Command::new("which")
            .arg("fail2ban-server")
            .output()?;
            
        if !output.status.success() {
            Command::new("apt-get")
                .args(&["update", "&&", "apt-get", "install", "-y", "fail2ban"])
                .output()?;
        }
        
        // Create jail configurations
        self.create_fail2ban_jails().await?;
        
        // Start fail2ban
        Command::new("systemctl")
            .args(&["enable", "--now", "fail2ban"])
            .output()?;
            
        Ok(())
    }

    async fn create_fail2ban_jails(&self) -> Result<()> {
        let jails = vec![
            Fail2banJail {
                name: "sshd".to_string(),
                enabled: true,
                port: "ssh".to_string(),
                protocol: "tcp".to_string(),
                filter: "sshd".to_string(),
                logpath: "/var/log/auth.log".to_string(),
                maxretry: 5,
                findtime: 600,
                bantime: 3600,
                action: "iptables[name=SSH, port=ssh, protocol=tcp]".to_string(),
            },
            Fail2banJail {
                name: "nginx-http-auth".to_string(),
                enabled: true,
                port: "http,https".to_string(),
                protocol: "tcp".to_string(),
                filter: "nginx-http-auth".to_string(),
                logpath: "/var/log/nginx/*error.log".to_string(),
                maxretry: 5,
                findtime: 600,
                bantime: 3600,
                action: "iptables[name=NoAuthFailures, port=\"http,https\", protocol=tcp]".to_string(),
            },
            Fail2banJail {
                name: "nginx-noscript".to_string(),
                enabled: true,
                port: "http,https".to_string(),
                protocol: "tcp".to_string(),
                filter: "nginx-noscript".to_string(),
                logpath: "/var/log/nginx/*access.log".to_string(),
                maxretry: 6,
                findtime: 600,
                bantime: 3600,
                action: "iptables[name=NoScript, port=\"http,https\", protocol=tcp]".to_string(),
            },
            Fail2banJail {
                name: "postfix".to_string(),
                enabled: true,
                port: "smtp,submission".to_string(),
                protocol: "tcp".to_string(),
                filter: "postfix".to_string(),
                logpath: "/var/log/mail.log".to_string(),
                maxretry: 3,
                findtime: 600,
                bantime: 3600,
                action: "iptables[name=Postfix, port=\"smtp,submission\", protocol=tcp]".to_string(),
            },
        ];
        
        let mut jail_config = String::from("[DEFAULT]\n");
        jail_config.push_str("bantime = 3600\n");
        jail_config.push_str("findtime = 600\n");
        jail_config.push_str("maxretry = 5\n");
        jail_config.push_str("backend = systemd\n\n");
        
        for jail in jails {
            jail_config.push_str(&format!("[{}]\n", jail.name));
            jail_config.push_str(&format!("enabled = {}\n", jail.enabled));
            jail_config.push_str(&format!("port = {}\n", jail.port));
            jail_config.push_str(&format!("protocol = {}\n", jail.protocol));
            jail_config.push_str(&format!("filter = {}\n", jail.filter));
            jail_config.push_str(&format!("logpath = {}\n", jail.logpath));
            jail_config.push_str(&format!("maxretry = {}\n", jail.maxretry));
            jail_config.push_str(&format!("findtime = {}\n", jail.findtime));
            jail_config.push_str(&format!("bantime = {}\n", jail.bantime));
            jail_config.push_str(&format!("action = {}\n\n", jail.action));
        }
        
        std::fs::write("/etc/fail2ban/jail.local", jail_config)?;
        
        Ok(())
    }

    // Get blocked IPs
    pub async fn get_blocked_ips(&self) -> Result<Vec<IpAddr>> {
        let output = Command::new("fail2ban-client")
            .args(&["status"])
            .output()?;
            
        if !output.status.success() {
            return Ok(vec![]);
        }
        
        let status = String::from_utf8_lossy(&output.stdout);
        let mut blocked_ips = Vec::new();
        
        // Parse fail2ban status to extract blocked IPs
        // This is a simplified implementation
        for line in status.lines() {
            if line.contains("Currently banned:") {
                // Extract IP addresses
                // Implementation would parse the actual output
            }
        }
        
        Ok(blocked_ips)
    }

    // Port management
    pub async fn open_port(&self, port: u16, protocol: Protocol) -> Result<()> {
        let rule = FirewallRule {
            id: Uuid::new_v4(),
            name: format!("Open port {}/{:?}", port, protocol),
            chain: "INPUT".to_string(),
            action: FirewallAction::Accept,
            protocol,
            source: IpRange { ip: None, cidr: None },
            destination: IpRange { ip: None, cidr: None },
            port: Some(PortRange { start: port, end: None }),
            interface: None,
            enabled: true,
            priority: 500,
            comment: Some(format!("Auto-opened port {}", port)),
            created_at: Utc::now(),
        };
        
        self.add_rule(&rule).await
    }

    pub async fn close_port(&self, port: u16, protocol: Protocol) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => {
                let proto = match protocol {
                    Protocol::TCP => "tcp",
                    Protocol::UDP => "udp",
                    _ => return Err(anyhow!("Unsupported protocol for port operation")),
                };
                
                let output = Command::new("iptables")
                    .args(&["-D", "INPUT", "-p", proto, "--dport", &port.to_string(), "-j", "ACCEPT"])
                    .output()?;
                    
                if !output.status.success() {
                    return Err(anyhow!("Failed to close port"));
                }
            },
            FirewallBackend::Nftables => {
                // Implementation for nftables
            }
        }
        
        Ok(())
    }

    // Get firewall status
    pub async fn get_status(&self) -> Result<FirewallStatus> {
        match self.backend {
            FirewallBackend::Iptables => {
                let output = Command::new("iptables")
                    .args(&["-L", "-n", "--line-numbers"])
                    .output()?;
                    
                let rules_output = String::from_utf8_lossy(&output.stdout);
                
                Ok(FirewallStatus {
                    backend: self.backend.clone(),
                    active: true,
                    rules_count: rules_output.lines().count() as u32,
                    blocked_ips: self.get_blocked_ips().await?,
                    fail2ban_active: self.is_fail2ban_active().await?,
                })
            },
            FirewallBackend::Nftables => {
                let output = Command::new("nft")
                    .args(&["list", "ruleset"])
                    .output()?;
                    
                let rules_output = String::from_utf8_lossy(&output.stdout);
                
                Ok(FirewallStatus {
                    backend: self.backend.clone(),
                    active: true,
                    rules_count: rules_output.lines().count() as u32,
                    blocked_ips: self.get_blocked_ips().await?,
                    fail2ban_active: self.is_fail2ban_active().await?,
                })
            }
        }
    }

    async fn is_fail2ban_active(&self) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(&["is-active", "fail2ban"])
            .output()?;
            
        Ok(output.status.success())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub backend: FirewallBackend,
    pub active: bool,
    pub rules_count: u32,
    pub blocked_ips: Vec<IpAddr>,
    pub fail2ban_active: bool,
}