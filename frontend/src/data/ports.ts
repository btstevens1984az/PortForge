export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Protocol = 'TCP' | 'UDP' | 'TCP/UDP'
export type PortCategory =
  | 'web'
  | 'remote'
  | 'directory'
  | 'database'
  | 'mail'
  | 'file'
  | 'monitoring'
  | 'security'
  | 'messaging'
  | 'legacy'
  | 'cloud'
  | 'healthcare'

export interface PortEntry {
  port: number
  proto: Protocol
  service: string
  risk: RiskLevel
  category: PortCategory
  note: string
  aliases?: string[]
  related?: number[]
  guidance: string
}

export const PORTS: PortEntry[] = [
  { port: 20, proto: 'TCP', service: 'FTP-DATA', risk: 'high', category: 'file', note: 'Active FTP data channel', guidance: 'Prefer SFTP/SCP. If required, restrict to known hosts and use FTPS.', aliases: ['ftp-data'] },
  { port: 21, proto: 'TCP', service: 'FTP', risk: 'high', category: 'file', note: 'Cleartext credentials — use SFTP', guidance: 'Block at perimeter. Migrate to SFTP (22) or FTPS (990).', aliases: ['ftp'], related: [20, 22, 990] },
  { port: 22, proto: 'TCP', service: 'SSH', risk: 'low', category: 'remote', note: 'Secure remote admin', guidance: 'Key auth only, disable password login, fail2ban / rate-limit, jump-host recommended.', aliases: ['ssh', 'scp', 'sftp'] },
  { port: 23, proto: 'TCP', service: 'Telnet', risk: 'critical', category: 'legacy', note: 'Cleartext — disable', guidance: 'Never allow. Replace with SSH. Audit for leftover listeners.', aliases: ['telnet'] },
  { port: 25, proto: 'TCP', service: 'SMTP', risk: 'medium', category: 'mail', note: 'Relay restrictions required', guidance: 'Auth + TLS submission preferred (587). Block open relay. SPF/DKIM/DMARC outbound.', aliases: ['smtp'], related: [465, 587] },
  { port: 53, proto: 'TCP/UDP', service: 'DNS', risk: 'low', category: 'directory', note: 'Amplification if open to internet', guidance: 'Recursive DNS only on internal resolvers. Rate-limit external queries.', aliases: ['dns'], related: [853] },
  { port: 67, proto: 'UDP', service: 'DHCP Server', risk: 'medium', category: 'directory', note: 'LAN-only bootstrap', guidance: 'Never expose beyond L2/L3 segment. Rogue DHCP detection recommended.', aliases: ['dhcp'] },
  { port: 68, proto: 'UDP', service: 'DHCP Client', risk: 'low', category: 'directory', note: 'Client DHCP responses', guidance: 'Normal client traffic; no inbound ACL needed at perimeter.', aliases: ['dhcp-client'] },
  { port: 80, proto: 'TCP', service: 'HTTP', risk: 'medium', category: 'web', note: 'Redirect to HTTPS', guidance: 'Allow only for ACME / redirect. Terminate TLS at load balancer.', aliases: ['http', 'www'], related: [443] },
  { port: 88, proto: 'TCP/UDP', service: 'Kerberos', risk: 'low', category: 'directory', note: 'AD authentication', guidance: 'Internal AD only. Never internet-facing. Pair with time sync (NTP).', aliases: ['kerberos'], related: [389, 636] },
  { port: 110, proto: 'TCP', service: 'POP3', risk: 'high', category: 'mail', note: 'Cleartext mail', guidance: 'Use POP3S 995. Prefer modern mail APIs over POP.', aliases: ['pop3'], related: [995] },
  { port: 123, proto: 'UDP', service: 'NTP', risk: 'low', category: 'directory', note: 'Time sync — AD dependency', guidance: 'Allow to trusted NTP stratum. Disable monlist (amplification).', aliases: ['ntp'] },
  { port: 135, proto: 'TCP', service: 'RPC Endpoint Mapper', risk: 'high', category: 'remote', note: 'Block at perimeter', guidance: 'Required for some AD/WMI internally. Block WAN. Prefer WinRM over RPC where possible.', aliases: ['epmap', 'msrpc'], related: [445, 5985] },
  { port: 137, proto: 'UDP', service: 'NetBIOS Name', risk: 'high', category: 'legacy', note: 'Legacy name service', guidance: 'Disable NetBIOS over TCP/IP on modern Windows. Block WAN.', aliases: ['netbios-ns'] },
  { port: 138, proto: 'UDP', service: 'NetBIOS Datagram', risk: 'high', category: 'legacy', note: 'Legacy browse traffic', guidance: 'Block at WAN edge. Internal only if legacy apps require it.', aliases: ['netbios-dgm'] },
  { port: 139, proto: 'TCP', service: 'NetBIOS Session', risk: 'high', category: 'legacy', note: 'SMB legacy — block WAN', guidance: 'Prefer SMB over 445. Disable SMBv1 everywhere.', aliases: ['netbios-ssn'], related: [445] },
  { port: 143, proto: 'TCP', service: 'IMAP', risk: 'medium', category: 'mail', note: 'Use IMAPS 993', guidance: 'Require STARTTLS or migrate to 993. MFA-backed mail gateways preferred.', aliases: ['imap'], related: [993] },
  { port: 161, proto: 'UDP', service: 'SNMP', risk: 'high', category: 'monitoring', note: 'Community strings often weak', guidance: 'SNMPv3 only. Never default communities. ACL to NMS only.', aliases: ['snmp'], related: [162] },
  { port: 162, proto: 'UDP', service: 'SNMP Trap', risk: 'medium', category: 'monitoring', note: 'Inbound traps to NMS', guidance: 'Allow only from managed devices to NMS. Prefer SNMPv3 informs.', aliases: ['snmptrap'] },
  { port: 389, proto: 'TCP/UDP', service: 'LDAP', risk: 'medium', category: 'directory', note: 'Use LDAPS 636', guidance: 'Signing/channel binding. Prefer LDAPS. Internal AD only.', aliases: ['ldap'], related: [636, 3268] },
  { port: 443, proto: 'TCP', service: 'HTTPS', risk: 'low', category: 'web', note: 'Standard web TLS', guidance: 'Modern cipher suites, HSTS, WAF for public apps. Certificate monitoring.', aliases: ['https', 'ssl'], related: [80] },
  { port: 445, proto: 'TCP', service: 'SMB', risk: 'high', category: 'file', note: 'Never expose to internet', guidance: 'Internal file shares only. Disable guest/null sessions. SMB signing.', aliases: ['smb', 'cifs'], related: [139] },
  { port: 464, proto: 'TCP/UDP', service: 'Kerberos Password', risk: 'low', category: 'directory', note: 'Password change / set', guidance: 'AD domain controllers only. Never internet.', aliases: ['kpasswd'] },
  { port: 465, proto: 'TCP', service: 'SMTPS', risk: 'low', category: 'mail', note: 'Implicit TLS SMTP', guidance: 'Authenticated submission. Prefer 587 STARTTLS for clients.', aliases: ['smtps'], related: [25, 587] },
  { port: 514, proto: 'UDP', service: 'Syslog', risk: 'medium', category: 'monitoring', note: 'Cleartext log shipping', guidance: 'Prefer TLS syslog (6514) or agent-based collectors.', aliases: ['syslog'], related: [6514] },
  { port: 587, proto: 'TCP', service: 'SMTP Submission', risk: 'low', category: 'mail', note: 'Authenticated mail submit', guidance: 'Require auth + STARTTLS. Rate-limit per mailbox.', aliases: ['submission'], related: [25, 465] },
  { port: 636, proto: 'TCP', service: 'LDAPS', risk: 'low', category: 'directory', note: 'Secure LDAP', guidance: 'Preferred for apps binding to AD/LDAP. Valid certs required.', aliases: ['ldaps'], related: [389] },
  { port: 853, proto: 'TCP', service: 'DNS over TLS', risk: 'low', category: 'directory', note: 'Encrypted DNS', guidance: 'Good for privacy-sensitive resolvers. Validate upstream trust.', aliases: ['dot'] },
  { port: 990, proto: 'TCP', service: 'FTPS', risk: 'medium', category: 'file', note: 'FTP over TLS', guidance: 'Better than clear FTP but SFTP still preferred for ops.', aliases: ['ftps'], related: [21] },
  { port: 993, proto: 'TCP', service: 'IMAPS', risk: 'low', category: 'mail', note: 'IMAP over TLS', guidance: 'Standard secure mailbox access.', aliases: ['imaps'], related: [143] },
  { port: 995, proto: 'TCP', service: 'POP3S', risk: 'low', category: 'mail', note: 'POP3 over TLS', guidance: 'Secure POP if legacy clients require it.', aliases: ['pop3s'], related: [110] },
  { port: 1433, proto: 'TCP', service: 'MSSQL', risk: 'high', category: 'database', note: 'Restrict to app tier', guidance: 'Private VLAN + Windows auth / strong SQL auth. No public exposure.', aliases: ['mssql', 'sqlserver'], related: [1434] },
  { port: 1434, proto: 'UDP', service: 'MSSQL Browser', risk: 'high', category: 'database', note: 'Instance discovery', guidance: 'Disable if named instances not needed. Block WAN.', aliases: ['sqlbrowser'] },
  { port: 1521, proto: 'TCP', service: 'Oracle DB', risk: 'high', category: 'database', note: 'Enterprise DB listener', guidance: 'App-tier only. Use TCPS where supported. Patch aggressively.', aliases: ['oracle', 'tnslsnr'] },
  { port: 2049, proto: 'TCP/UDP', service: 'NFS', risk: 'high', category: 'file', note: 'Network filesystem', guidance: 'Kerberos NFS preferred. Never internet. Export ACLs tight.', aliases: ['nfs'] },
  { port: 2375, proto: 'TCP', service: 'Docker API', risk: 'critical', category: 'cloud', note: 'Unauthenticated Docker socket', guidance: 'Never expose. Use TLS socket (2376) or local unix only.', aliases: ['docker'], related: [2376] },
  { port: 2376, proto: 'TCP', service: 'Docker TLS', risk: 'high', category: 'cloud', note: 'Docker API with TLS', guidance: 'mTLS client certs required. Prefer orchestration control plane.', aliases: ['docker-tls'] },
  { port: 2379, proto: 'TCP', service: 'etcd Client', risk: 'critical', category: 'cloud', note: 'K8s cluster state', guidance: 'Control-plane only. mTLS. Never public.', aliases: ['etcd'], related: [2380] },
  { port: 2380, proto: 'TCP', service: 'etcd Peer', risk: 'critical', category: 'cloud', note: 'etcd peer replication', guidance: 'Control-plane VLAN only.', aliases: ['etcd-peer'] },
  { port: 3128, proto: 'TCP', service: 'HTTP Proxy', risk: 'medium', category: 'web', note: 'Common forward proxy', guidance: 'Auth required. Block CONNECT abuse. Logging mandatory.', aliases: ['squid', 'proxy'] },
  { port: 3268, proto: 'TCP', service: 'Global Catalog', risk: 'medium', category: 'directory', note: 'AD GC LDAP', guidance: 'Internal forest only. Prefer 3269 LDAPS GC.', aliases: ['gc'], related: [3269] },
  { port: 3269, proto: 'TCP', service: 'Global Catalog SSL', risk: 'low', category: 'directory', note: 'Secure AD GC', guidance: 'Preferred GC binding for multi-domain forests.', aliases: ['gc-ssl'] },
  { port: 3306, proto: 'TCP', service: 'MySQL', risk: 'high', category: 'database', note: 'Bind localhost or private VLAN', guidance: 'TLS connections, least-privilege users, no root remote.', aliases: ['mysql', 'mariadb'], related: [33060] },
  { port: 3389, proto: 'TCP', service: 'RDP', risk: 'critical', category: 'remote', note: 'VPN/NLA required — top attack vector', guidance: 'Never public. NLA, MFA gateway (RDG/ZTNA), lockout policy.', aliases: ['rdp', 'ms-wbt'], related: [443] },
  { port: 4500, proto: 'UDP', service: 'IPsec NAT-T', risk: 'low', category: 'security', note: 'VPN NAT traversal', guidance: 'Pair with 500/ESP. Restrict to VPN concentrators.', aliases: ['ipsec-natt'], related: [500] },
  { port: 500, proto: 'UDP', service: 'ISAKMP / IKE', risk: 'low', category: 'security', note: 'IPsec key exchange', guidance: 'Strong ciphers only. Restrict peer IPs when possible.', aliases: ['ike', 'isakmp'], related: [4500] },
  { port: 5060, proto: 'TCP/UDP', service: 'SIP', risk: 'high', category: 'messaging', note: 'VoIP signaling — often scanned', guidance: 'SBC in front. Prefer TLS SIP (5061). Auth + ACLs.', aliases: ['sip'], related: [5061] },
  { port: 5061, proto: 'TCP', service: 'SIP-TLS', risk: 'medium', category: 'messaging', note: 'Encrypted SIP', guidance: 'Preferred for VoIP trunks. Certificate validation.', aliases: ['sips'] },
  { port: 5432, proto: 'TCP', service: 'PostgreSQL', risk: 'high', category: 'database', note: 'Private network only', guidance: 'scram-sha-256, TLS, pg_hba lockdown. No public.', aliases: ['postgres', 'postgresql'] },
  { port: 5601, proto: 'TCP', service: 'Kibana', risk: 'high', category: 'monitoring', note: 'Elastic UI', guidance: 'SSO + reverse proxy. Never public without auth.', aliases: ['kibana'], related: [9200] },
  { port: 5672, proto: 'TCP', service: 'AMQP', risk: 'high', category: 'messaging', note: 'RabbitMQ / brokers', guidance: 'TLS (5671) preferred. Strong creds, vhost isolation.', aliases: ['amqp', 'rabbitmq'], related: [5671] },
  { port: 5671, proto: 'TCP', service: 'AMQPS', risk: 'medium', category: 'messaging', note: 'AMQP over TLS', guidance: 'Preferred broker port for prod.', aliases: ['amqps'] },
  { port: 5900, proto: 'TCP', service: 'VNC', risk: 'critical', category: 'remote', note: 'Often weak/no auth', guidance: 'Replace with SSH tunnel or enterprise remote access. Never public.', aliases: ['vnc', 'rfb'] },
  { port: 5985, proto: 'TCP', service: 'WinRM HTTP', risk: 'high', category: 'remote', note: 'Use 5986 HTTPS', guidance: 'Internal only. Prefer HTTPS WinRM. CredSSP carefully.', aliases: ['winrm'], related: [5986] },
  { port: 5986, proto: 'TCP', service: 'WinRM HTTPS', risk: 'medium', category: 'remote', note: 'Ansible/PowerShell remoting', guidance: 'Cert-based. Jump host / PAW recommended for admin.', aliases: ['winrm-https'] },
  { port: 6379, proto: 'TCP', service: 'Redis', risk: 'critical', category: 'database', note: 'No auth by default — never public', guidance: 'requirepass/ACL, bind private, TLS, rename dangerous cmds.', aliases: ['redis'] },
  { port: 6443, proto: 'TCP', service: 'Kubernetes API', risk: 'high', category: 'cloud', note: 'Cluster control plane', guidance: 'RBAC, audit logs, private endpoint or bastion only.', aliases: ['kube-apiserver'] },
  { port: 6514, proto: 'TCP', service: 'Syslog TLS', risk: 'low', category: 'monitoring', note: 'Encrypted log shipping', guidance: 'Preferred over UDP 514 for compliance environments.', aliases: ['syslog-tls'] },
  { port: 8000, proto: 'TCP', service: 'HTTP Dev', risk: 'medium', category: 'web', note: 'Common app/dev port', guidance: 'Treat as app traffic. Auth + TLS in front.', aliases: ['http-alt'] },
  { port: 8080, proto: 'TCP', service: 'HTTP Alt', risk: 'medium', category: 'web', note: 'Common proxy/app port', guidance: 'Often admin UIs — authenticate and restrict source.', aliases: ['http-proxy'], related: [8443] },
  { port: 8443, proto: 'TCP', service: 'HTTPS Alt', risk: 'low', category: 'web', note: 'Admin consoles', guidance: 'SSO, MFA, source IP allowlists for mgmt planes.', aliases: ['https-alt'] },
  { port: 8500, proto: 'TCP', service: 'Consul', risk: 'high', category: 'cloud', note: 'Service discovery UI/API', guidance: 'ACLs + TLS. Never public.', aliases: ['consul'] },
  { port: 9000, proto: 'TCP', service: 'Sonar / Portainer', risk: 'high', category: 'cloud', note: 'Common admin UI port', guidance: 'Reverse proxy + SSO. Restrict to ops networks.', aliases: ['portainer', 'sonar'] },
  { port: 9090, proto: 'TCP', service: 'Prometheus', risk: 'medium', category: 'monitoring', note: 'Metrics scrape UI', guidance: 'Auth proxy. Avoid public scrape endpoints.', aliases: ['prometheus'] },
  { port: 9200, proto: 'TCP', service: 'Elasticsearch', risk: 'critical', category: 'monitoring', note: 'No auth in default install', guidance: 'Security plugin/X-Pack required. Private only.', aliases: ['elasticsearch', 'es'], related: [9300, 5601] },
  { port: 9300, proto: 'TCP', service: 'ES Transport', risk: 'critical', category: 'monitoring', note: 'Elasticsearch node protocol', guidance: 'Cluster VLAN only. Never expose.', aliases: ['es-transport'] },
  { port: 9418, proto: 'TCP', service: 'Git Protocol', risk: 'medium', category: 'file', note: 'Unauthenticated git://', guidance: 'Prefer HTTPS/SSH git. Disable git:// on servers.', aliases: ['git'] },
  { port: 11211, proto: 'TCP/UDP', service: 'Memcached', risk: 'critical', category: 'database', note: 'Amplification + no auth', guidance: 'Localhost/private only. Never UDP on internet.', aliases: ['memcached'] },
  { port: 27017, proto: 'TCP', service: 'MongoDB', risk: 'critical', category: 'database', note: 'Bind IP + auth required', guidance: 'Auth, TLS, bindIp. Disable free monitoring exposure.', aliases: ['mongodb', 'mongo'], related: [27018] },
  { port: 27018, proto: 'TCP', service: 'MongoDB Shard', risk: 'critical', category: 'database', note: 'Shard server', guidance: 'Cluster-internal only.', aliases: ['mongo-shard'] },
  { port: 2575, proto: 'TCP', service: 'HL7 MLLP', risk: 'high', category: 'healthcare', note: 'Common HL7 interface port', guidance: 'VPN/private interconnect only. Encrypt (TLS wrappers). PHI — audit everything.', aliases: ['hl7', 'mllp'] },
  { port: 2576, proto: 'TCP', service: 'HL7 Alt', risk: 'high', category: 'healthcare', note: 'Alternate HL7 listener', guidance: 'Same controls as 2575. Document interface owners.', aliases: ['hl7-alt'] },
  { port: 104, proto: 'TCP', service: 'DICOM', risk: 'high', category: 'healthcare', note: 'Medical imaging (DIMSE)', guidance: 'PACS VLAN only. Prefer DICOM TLS (2762). Never internet.', aliases: ['dicom'], related: [2762] },
  { port: 2762, proto: 'TCP', service: 'DICOM TLS', risk: 'medium', category: 'healthcare', note: 'Secure DICOM', guidance: 'Preferred for imaging exchange. Mutual TLS where supported.', aliases: ['dicom-tls'] },
  { port: 11112, proto: 'TCP', service: 'DICOM Alt', risk: 'high', category: 'healthcare', note: 'Alternate DICOM port', guidance: 'Treat as PHI path. Segment + encrypt.', aliases: ['dicom-alt'] },
  { port: 8191, proto: 'TCP', service: 'Epic Interconnect (common)', risk: 'high', category: 'healthcare', note: 'Vendor-specific clinical integration', guidance: 'Vendor docs override. Private + mutual auth. Change control required.', aliases: ['epic'] },
  { port: 8192, proto: 'TCP', service: 'Epic Alt', risk: 'high', category: 'healthcare', note: 'Clinical integration alt', guidance: 'Confirm with vendor runbook. Segment from general user LAN.', aliases: ['epic-alt'] },
  { port: 4433, proto: 'TCP', service: 'HTTPS Mgmt Alt', risk: 'medium', category: 'web', note: 'Secondary admin TLS', guidance: 'Often appliance UIs — MFA + allowlist.', aliases: ['https-mgmt'] },
  { port: 8888, proto: 'TCP', service: 'HTTP Alt Dev', risk: 'medium', category: 'web', note: 'Notebooks / apps', guidance: 'Auth gate. Do not expose Jupyter-style UIs publicly.', aliases: ['jupyter-alt'] },
  { port: 9443, proto: 'TCP', service: 'HTTPS Appliance', risk: 'medium', category: 'web', note: 'Vendor appliance UI', guidance: 'Source-restrict. Patch firmware. Separate mgmt VRF.', aliases: ['appliance-https'] },
  { port: 10000, proto: 'TCP', service: 'Webmin / NDMP', risk: 'critical', category: 'remote', note: 'Often targeted admin UI', guidance: 'Disable if unused. If required, VPN + MFA only.', aliases: ['webmin', 'ndmp'] },
  { port: 1194, proto: 'UDP', service: 'OpenVPN', risk: 'low', category: 'security', note: 'Common VPN port', guidance: 'Cert auth, tls-crypt, modern ciphers. Consider non-default port.', aliases: ['openvpn'] },
  { port: 51820, proto: 'UDP', service: 'WireGuard', risk: 'low', category: 'security', note: 'Modern VPN', guidance: 'Peer keys rotated. Firewall to known peers when possible.', aliases: ['wireguard', 'wg'] },
  { port: 2222, proto: 'TCP', service: 'SSH Alt', risk: 'medium', category: 'remote', note: 'Non-standard SSH', guidance: 'Security through obscurity only — still harden like 22.', aliases: ['ssh-alt'] },
  { port: 8444, proto: 'TCP', service: 'Alt HTTPS Admin', risk: 'medium', category: 'web', note: 'Secondary console', guidance: 'Treat as management plane.', aliases: ['admin-https'] },
  { port: 9201, proto: 'TCP', service: 'OpenSearch', risk: 'critical', category: 'monitoring', note: 'Search cluster HTTP', guidance: 'Security plugin on. Private network only.', aliases: ['opensearch'] },
]

export const CATEGORIES: { id: PortCategory | 'all'; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'web', label: 'Web' },
  { id: 'remote', label: 'Remote' },
  { id: 'directory', label: 'Directory' },
  { id: 'database', label: 'Database' },
  { id: 'mail', label: 'Mail' },
  { id: 'file', label: 'File' },
  { id: 'monitoring', label: 'Monitoring' },
  { id: 'security', label: 'Security' },
  { id: 'messaging', label: 'Messaging' },
  { id: 'cloud', label: 'Cloud' },
  { id: 'healthcare', label: 'Healthcare' },
  { id: 'legacy', label: 'Legacy' },
]

export const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}
