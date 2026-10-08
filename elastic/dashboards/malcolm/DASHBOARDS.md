# The dashboards of the `malcolm` space

36 dashboards, one file each in this directory, imported into the `malcolm` Kibana space by the stack
deploy (README.md). "Selects" is the set of `event.dataset` values the dashboard's panel queries name on its
data view; "all" marks a dashboard with panels that apply no dataset filter. The navigation panel at the top
of every dashboard links the dashboards of each section below.

## General network logs

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| Overview | `overview.ndjson` | `logs-dxdfir.zeek-*` | zeek.dns, all | 7 |
| Connections | `connections.ndjson` | `logs-dxdfir.zeek-*` | zeek.conn | 15 |
| Files | `files.ndjson` | `logs-dxdfir.zeek-*` | zeek.files, all | 8 |
| PE | `pe.ndjson` | `logs-dxdfir.zeek-*` | zeek.pe | 7 |
| Zeek Weird | `zeek-weird.ndjson` | `logs-dxdfir.zeek-*` | zeek.weird | 6 |
| Suricata Alerts | `suricata-alerts.ndjson` | `logs-dxdfir.detections-*` | suricata.alert | 7 |

## Protocols

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| DCE/RPC | `dce-rpc.ndjson` | `logs-dxdfir.zeek-*` | zeek.dce_rpc | 11 |
| DHCP | `dhcp.ndjson` | `logs-dxdfir.zeek-*` | zeek.dhcp | 6 |
| DNS | `dns.ndjson` | `logs-dxdfir.zeek-*` | zeek.dns | 12 |
| FTP | `ftp.ndjson` | `logs-dxdfir.zeek-*` | zeek.ftp | 9 |
| HTTP | `http.ndjson` | `logs-dxdfir.zeek-*` | zeek.http, all | 16 |
| WebSocket | `websocket.ndjson` | `logs-dxdfir.zeek-*` | zeek.websocket | 8 |
| IRC | `irc.ndjson` | `logs-dxdfir.zeek-*` | zeek.irc | 7 |
| Kerberos | `kerberos.ndjson` | `logs-dxdfir.zeek-*` | zeek.kerberos | 13 |
| LDAP | `ldap.ndjson` | `logs-dxdfir.zeek-*` | zeek.ldap, zeek.ldap_search | 10 |
| MQTT | `mqtt.ndjson` | `logs-dxdfir.zeek-*` | zeek.mqtt_connect, zeek.mqtt_publish, zeek.mqtt_subscribe | 10 |
| MySQL | `mysql.ndjson` | `logs-dxdfir.zeek-*` | zeek.mysql | 5 |
| NTLM | `ntlm.ndjson` | `logs-dxdfir.zeek-*` | zeek.ntlm | 11 |
| NTP | `ntp.ndjson` | `logs-dxdfir.zeek-*` | zeek.ntp | 9 |
| PostgreSQL | `postgresql.ndjson` | `logs-dxdfir.zeek-*` | zeek.postgresql | 9 |
| QUIC | `quic.ndjson` | `logs-dxdfir.zeek-*` | zeek.quic | 7 |
| RADIUS | `radius.ndjson` | `logs-dxdfir.zeek-*` | zeek.radius | 9 |
| Redis | `redis.ndjson` | `logs-dxdfir.zeek-*` | zeek.redis | 9 |
| RDP | `rdp.ndjson` | `logs-dxdfir.zeek-*` | zeek.rdp | 10 |
| RFB | `rfb.ndjson` | `logs-dxdfir.zeek-*` | zeek.rfb | 12 |
| SIP | `sip.ndjson` | `logs-dxdfir.zeek-*` | zeek.sip | 12 |
| SMB | `smb.ndjson` | `logs-dxdfir.zeek-*` | zeek.smb_files, zeek.smb_mapping | 11 |
| SMTP | `smtp.ndjson` | `logs-dxdfir.zeek-*` | zeek.smtp | 11 |
| SNMP | `snmp.ndjson` | `logs-dxdfir.zeek-*` | zeek.snmp | 7 |
| SSH | `ssh.ndjson` | `logs-dxdfir.zeek-*` | zeek.ssh | 8 |
| SSL | `ssl.ndjson` | `logs-dxdfir.zeek-*` | zeek.ssl | 11 |
| X.509 | `x-509.ndjson` | `logs-dxdfir.zeek-*` | zeek.ocsp, zeek.x509 | 13 |
| Syslog | `syslog.ndjson` | `logs-dxdfir.zeek-*` | zeek.syslog | 9 |
| Tunnels | `tunnels.ndjson` | `logs-dxdfir.zeek-*` | zeek.tunnel | 7 |

## ICS protocols

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| Modbus | `modbus.ndjson` | `logs-dxdfir.zeek-*` | zeek.modbus | 6 |
| DNP3 | `dnp3.ndjson` | `logs-dxdfir.zeek-*` | zeek.dnp3 | 7 |

## Panels

Every dashboard also carries the navigation panel (markdown). Kinds: table, pie chart, metric, chart and tag cloud are Lens
visualisations stored in the dashboard; a Discover table is a saved search stored in the same file; Vega is a
Vega visualisation stored in the dashboard, which queries Elasticsearch through its own specification under the
dashboard's time range and filters. The query after a panel is the KQL it applies on the data view.

### Overview (`overview.ndjson`)

- Total Log Count Over Time (chart)
- Log Type (table)
- Total Number of Logs (metric)
- DNS - Queries (table): `event.dataset:zeek.dns`
- Log Source (table)
- Application Protocol (table)
- All Logs (Discover table of event.provider, event.dataset, id.orig_h, id.resp_h, id.resp_p, uid)

### Connections (`connections.ndjson`)

- Connections - Log Count Over Time (chart): `event.dataset:zeek.conn`
- Connections - Source IP Address (table): `event.dataset:zeek.conn`
- Connections - Destination IP Address (table): `event.dataset:zeek.conn`
- Connections - Responder Bytes (table): `event.dataset:zeek.conn`
- Connections - Missed Bytes (table): `event.dataset:zeek.conn`
- Connections - Connection State (table): `event.dataset:zeek.conn`
- Connections - Top 10 - Total Bytes By Connection (chart): `event.dataset:zeek.conn`
- Connections - Top 10 - Total Bytes By Destination IP (chart): `event.dataset:zeek.conn`
- Connections - Top 10 - Total Bytes By Destination Port (chart): `event.dataset:zeek.conn`
- Connections - Top 10 - Total Bytes By Source IP (chart): `event.dataset:zeek.conn`
- Connections - Log Count (metric): `event.dataset:zeek.conn`
- Connections - Total Bytes Per Source/Destination IP Pair (table): `event.dataset:zeek.conn`
- Connections - Destination Port (table): `event.dataset:zeek.conn`
- Connections - Protocol (pie chart): `event.dataset:zeek.conn`
- Connections - Logs (Discover table of proto, service, id.orig_h, id.orig_p, id.resp_h, id.resp_p, network.bytes, uid): `event.dataset:zeek.conn`

### Files (`files.ndjson`)

- Files - Log Count Over Time (chart): `event.dataset:zeek.files`
- Files - Files By Size (Bytes) (table): `event.dataset:zeek.files`
-  - Destination IP Address (table): `event.dataset:zeek.files`
- Files - Source IP Address (table): `event.dataset:zeek.files`
- Files - Log Count (metric): `event.dataset:zeek.files`
- Files - Source (chart): `event.dataset:zeek.files`
- Files - MIME Type (table)
- Files - Logs (Discover table of id.orig_h, id.resp_h, source, mime_type, uid): `event.dataset:zeek.files`

### PE (`pe.ndjson`)

- PE - Log Count Over Time (chart): `event.dataset:zeek.pe`
- PE - OS (pie chart): `event.dataset:zeek.pe`
- PE - Subsystem (pie chart): `event.dataset:zeek.pe`
- PE - Section Name (table): `event.dataset:zeek.pe`
- PE - Machine (table): `event.dataset:zeek.pe`
- PE - Log Count (metric): `event.dataset:zeek.pe`
- PE - Logs (Discover table of machine, os, subsystem, id): `event.dataset:zeek.pe`

### Zeek Weird (`zeek-weird.ndjson`)

- Weird - Log Count Over Time (chart): `event.dataset:zeek.weird`
- Weird - Source (table): `event.dataset:zeek.weird`
- Weird - Destination (table): `event.dataset:zeek.weird`
- Weird - Log Count (metric): `event.dataset:zeek.weird`
- Weird - Name (table): `event.dataset:zeek.weird`
- Weird - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, name, uid): `event.dataset:zeek.weird`

### Suricata Alerts (`suricata-alerts.ndjson`)

- Alerts - Log Count (metric): `event.dataset:suricata.alert`
- Alerts - Log Count Over Time (chart): `event.dataset:suricata.alert`
- Alert Category (chart): `event.dataset:suricata.alert`
- Alerts - Name (table): `event.dataset:suricata.alert`
- Alerts - Source (table): `event.dataset:suricata.alert`
- Alerts - Destination (table): `event.dataset:suricata.alert`
- Suricata Alerts - Logs (Discover table of alert.category, alert.signature, alert.signature_id, src_ip, dest_ip, flow_id): `event.dataset:suricata.alert`

### DCE/RPC (`dce-rpc.ndjson`)

- DCE/RPC - Log Count Over Time (chart): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Source IP Address (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Destination IP Address (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Endpoint (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Named Pipe (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Operation (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Round Trip Time (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Log Count (metric): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Destination Port (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Summary (table): `event.dataset:zeek.dce_rpc`
- DCE/RPC - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, operation, endpoint, uid): `event.dataset:zeek.dce_rpc`

### DHCP (`dhcp.ndjson`)

- DHCP - Log Count Over Time (chart): `event.dataset:zeek.dhcp`
- DHCP - Destination IP Address (table): `event.dataset:zeek.dhcp`
- DHCP - Source IP Address (table): `event.dataset:zeek.dhcp`
- DHCP - Log Count (metric): `event.dataset:zeek.dhcp`
- DHCP - IP to MAC Assignment (table): `event.dataset:zeek.dhcp`
- DHCP - Logs (Discover table of event.dataset, mac, assigned_addr, client_addr, server_addr, host_name, domain, msg_types, uids): `event.dataset:zeek.dhcp`

### DNS (`dns.ndjson`)

- DNS - Server (table): `event.dataset:zeek.dns`
- DNS - Client (table): `event.dataset:zeek.dns`
- DNS - Query Class (pie chart): `event.dataset:zeek.dns`
- DNS - Query/Answer (table): `event.dataset:zeek.dns`
- DNS - Log Count Over Time (chart): `event.dataset:zeek.dns`
- DNS - Destination Port (chart): `event.dataset:zeek.dns`
- DNS - Log Count (metric): `event.dataset:zeek.dns`
- DNS - Answers (table): `event.dataset:zeek.dns`
- DNS - Response Code (Name) (table): `event.dataset:zeek.dns`
- DNS - Query Type (table): `event.dataset:zeek.dns`
- DNS - Protocol (pie chart): `event.dataset:zeek.dns`
- DNS - Logs (Discover table of id.orig_h, id.resp_h, query, answers, uid): `event.dataset:zeek.dns`

### FTP (`ftp.ndjson`)

- FTP - Log Count Over Time (chart): `event.dataset:zeek.ftp`
- FTP - Argument (table): `event.dataset:zeek.ftp`
- FTP - Commands and Replies (table): `event.dataset:zeek.ftp`
- FTP - Reply (pie chart): `event.dataset:zeek.ftp`
- FTP - Source (table): `event.dataset:zeek.ftp`
- FTP - Destination (table): `event.dataset:zeek.ftp`
- FTP - Username (table): `event.dataset:zeek.ftp`
- FTP - Log Count (metric): `event.dataset:zeek.ftp`
- FTP - Logs (Discover table of id.orig_h, id.resp_h, command, reply_msg, uid): `event.dataset:zeek.ftp`

### HTTP (`http.ndjson`)

- HTTP - Status Over Time (chart): `event.dataset:zeek.http`
- HTTP - Sites (table): `event.dataset:zeek.http`
- HTTP - Sites Hosting EXEs (table): `resp_mime_types:"application/x-dosexec"`
- HTTP - URIs (table): `event.dataset:zeek.http`
- HTTP - Source IP Address (table): `event.dataset:zeek.http`
- HTTP - Destination IP Address (table): `event.dataset:zeek.http`
- HTTP - User Agent (table): `event.dataset:zeek.http`
- HTTP - Referrer (table): `event.dataset:zeek.http`
- HTTP - Destination Port (chart): `event.dataset:zeek.http`
- HTTP - Log Count (metric): `event.dataset:zeek.http`
- HTTP  - Status and Method (table): `event.dataset:zeek.http`
- HTTP - Unique Usernames and Passwords (metric): `event.dataset:zeek.http`
- HTTP - Version (pie chart): `(event.dataset:zeek.http) AND (NOT version:"0.0")`
- HTTP - File Type (tag cloud): `event.dataset:zeek.http`
- HTTP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, host, method, status_msg, uid): `event.dataset:zeek.http`
- HTTP - Method and Status (Vega)

### WebSocket (`websocket.ndjson`)

- WebSocket - Log Count (metric): `event.dataset:zeek.websocket`
- WebSocket - Logs Over Time (chart): `event.dataset:zeek.websocket`
- WebSocket - Source IP (table): `event.dataset:zeek.websocket`
- WebSocket - Destination IP (table): `event.dataset:zeek.websocket`
- WebSocket - Client Extensions (table): `event.dataset:zeek.websocket`
- WebSocket - Server Extensions (table): `event.dataset:zeek.websocket`
- WebSocket - URI (table): `event.dataset:zeek.websocket`
- WebSocket - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, host, uri, user_agent, subprotocol, client_protocols, client_extensions, server_extensions, uid): `event.dataset:zeek.websocket`

### IRC (`irc.ndjson`)

- IRC - Log Count Over Time (chart): `event.dataset:zeek.irc`
- IRC - Destination IP Address (table): `event.dataset:zeek.irc`
- IRC - Source IP Address (table): `event.dataset:zeek.irc`
- IRC - Destination Port (table): `event.dataset:zeek.irc`
- IRC - Log Count (metric): `event.dataset:zeek.irc`
- IRC - Command (table): `event.dataset:zeek.irc`
- IRC - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, nick, command, value, uid): `event.dataset:zeek.irc`

### Kerberos (`kerberos.ndjson`)

- Kerberos - Log Count Over Time (chart): `event.dataset:zeek.kerberos`
- Kerberos - Client (table): `event.dataset:zeek.kerberos`
- Kerberos - Success Status (pie chart): `event.dataset:zeek.kerberos`
- Kerberos - Server (table): `event.dataset:zeek.kerberos`
- Kerberos - Cipher (pie chart): `event.dataset:zeek.kerberos`
- Kerberos - Source IP Address (table): `event.dataset:zeek.kerberos`
- Kerberos - Destination IP Address (table): `event.dataset:zeek.kerberos`
- Kerberos - Service (table): `event.dataset:zeek.kerberos`
- Kerberos - Log Count (metric): `event.dataset:zeek.kerberos`
- Kerberos - Request Types (pie chart): `event.dataset:zeek.kerberos`
- Kerberos - Renewable Ticket Requested (pie chart): `event.dataset:zeek.kerberos`
- Kerberos - Destination Ports (chart): `event.dataset:zeek.kerberos`
- Kerberos - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, request_type, success, error_msg, uid): `event.dataset:zeek.kerberos`

### LDAP (`ldap.ndjson`)

- LDAP - Log Count Over Time (chart): `event.dataset:zeek.ldap`
- LDAP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, version, message_id, opcode, object, argument, result, uid): `event.dataset:zeek.ldap`
- LDAP - Source IP (table): `event.dataset:zeek.ldap`
- LDAP - Destination IP (table): `event.dataset:zeek.ldap`
- LDAP - Log Count (metric): `event.dataset:(zeek.ldap OR zeek.ldap_search)`
- LDAP - Bind (table): `(event.dataset:zeek.ldap) AND (opcode:bind*)`
- LDAP - Search Scope (chart): `event.dataset:zeek.ldap_search`
- LDAP - Result Code (table): `event.dataset:(zeek.ldap OR zeek.ldap_search)`
- LDAP - Operation (table): `event.dataset:(zeek.ldap OR zeek.ldap_search)`
- LDAP Search - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, message_id, base_object, filter, result_count, result, uid): `event.dataset:zeek.ldap_search`

### MQTT (`mqtt.ndjson`)

- MQTT - Log Count (metric): `event.dataset:(zeek.mqtt_connect OR zeek.mqtt_publish OR zeek.mqtt_subscribe)`
- MQTT - Log Count Over Time (chart): `event.dataset:(zeek.mqtt_connect OR zeek.mqtt_publish OR zeek.mqtt_subscribe)`
- MQTT - Source IP (table): `event.dataset:(zeek.mqtt_connect OR zeek.mqtt_publish OR zeek.mqtt_subscribe)`
- MQTT - Destination IP (table): `event.dataset:(zeek.mqtt_connect OR zeek.mqtt_publish OR zeek.mqtt_subscribe)`
- MQTT - Protocol (pie chart): `event.dataset:zeek.mqtt_connect`
- MQTT - Client ID (table): `event.dataset:zeek.mqtt_connect`
- MQTT - Subscription (table): `event.dataset:zeek.mqtt_subscribe`
- MQTT - Publish (table): `event.dataset:zeek.mqtt_publish`
- MQTT - Publish Payload (table): `event.dataset:zeek.mqtt_publish`
- MQTT - All Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, event.dataset, uid): `event.dataset:(zeek.mqtt_connect OR zeek.mqtt_publish OR zeek.mqtt_subscribe)`

### MySQL (`mysql.ndjson`)

- MySQL - Log Count Over Time (chart): `event.dataset:zeek.mysql`
- MySQL - Log Count (metric): `event.dataset:zeek.mysql`
- MySQL - Success (pie chart): `event.dataset:zeek.mysql`
- MySQL - Commands (table): `event.dataset:zeek.mysql`
- MySQL - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, cmd, success, uid): `event.dataset:zeek.mysql`

### NTLM (`ntlm.ndjson`)

- NTLM - Log Count Over Time (chart): `event.dataset:zeek.ntlm`
- NTLM - Hostname (table): `event.dataset:zeek.ntlm`
- NTLM - Domain Name (table): `event.dataset:zeek.ntlm`
- NTLM - Username (table): `event.dataset:zeek.ntlm`
- NTLM - Destination IP Address (table): `event.dataset:zeek.ntlm`
- NTLM - Source IP Address (table): `event.dataset:zeek.ntlm`
- NTLM - Destination Port (table): `event.dataset:zeek.ntlm`
- NTLM - Log Count (metric): `event.dataset:zeek.ntlm`
- NTLM - Hostname to Username (table): `event.dataset:zeek.ntlm`
- NTLM - Success (pie chart): `event.dataset:zeek.ntlm`
- NTLM - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, hostname, domainname, server_nb_computer_name, server_dns_computer_name, server_tree_name, uid): `event.dataset:zeek.ntlm`

### NTP (`ntp.ndjson`)

- NTP - Logs (Discover table of id.orig_h, id.resp_h, version, stratum, mode, org_time, xmt_time, uid): `event.dataset:zeek.ntp`
- NTP - Log Count (metric): `event.dataset:zeek.ntp`
- NTP - Log Count Over Time (chart): `event.dataset:zeek.ntp`
- NTP - Stratum (chart): `event.dataset:zeek.ntp`
- NTP - Version (pie chart): `event.dataset:zeek.ntp`
- NTP - Mode (pie chart): `event.dataset:zeek.ntp`
- NTP - Polling Interval (chart): `event.dataset:zeek.ntp`
- NTP - Source IP (table): `event.dataset:zeek.ntp`
- NTP - Destination IP (table): `event.dataset:zeek.ntp`

### PostgreSQL (`postgresql.ndjson`)

- PostgreSQL - Log Count (metric): `event.dataset:zeek.postgresql`
- PostgreSQL - Log Count Over Time (chart): `event.dataset:zeek.postgresql`
- PostgreSQL - Database (chart): `event.dataset:zeek.postgresql`
- PostgreSQL - Action and Results (table): `event.dataset:zeek.postgresql`
- PostgreSQL - Application (table): `event.dataset:zeek.postgresql`
- PostgreSQL - Source IP (table): `event.dataset:zeek.postgresql`
- PostgreSQL - Destination IP (table): `event.dataset:zeek.postgresql`
- PostgreSQL - User (table): `event.dataset:zeek.postgresql`
- PostgreSQL - Logs (Discover table of id.orig_h, id.resp_h, database, application_name, user, frontend, success, frontend_arg, backend_arg, rows, uid): `event.dataset:zeek.postgresql`

### QUIC (`quic.ndjson`)

- QUIC - Log Count (metric): `event.dataset:zeek.quic`
- QUIC - Logs (Discover table of id.orig_h, id.resp_h, server_name, version, uid): `event.dataset:zeek.quic`
- QUIC - Log Count Over Time (chart): `event.dataset:zeek.quic`
- QUIC - Source IP Address (table): `event.dataset:zeek.quic`
- QUIC - Destination IP Address (table): `event.dataset:zeek.quic`
- QUIC - Server Name (table): `event.dataset:zeek.quic`
- QUIC - Version (pie chart): `event.dataset:zeek.quic`

### RADIUS (`radius.ndjson`)

- RADIUS - Log Count Over Time (chart): `event.dataset:zeek.radius`
- RADIUS - Source IP Address (table): `event.dataset:zeek.radius`
- RADIUS - Destination IP Address (table): `event.dataset:zeek.radius`
- RADIUS - MAC (table): `event.dataset:zeek.radius`
- RADIUS - Connection Information (table): `event.dataset:zeek.radius`
- RADIUS - Log Count (metric): `event.dataset:zeek.radius`
- RADIUS - Username (table): `event.dataset:zeek.radius`
- RADIUS - Authentication Result (pie chart): `event.dataset:zeek.radius`
- RADIUS - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, username, mac, framed_addr, result, uid): `event.dataset:zeek.radius`

### Redis (`redis.ndjson`)

- Redis - Logs Over Time (chart): `event.dataset:zeek.redis`
- Redis - Log Count (metric): `event.dataset:zeek.redis`
- Redis - Success (pie chart): `event.dataset:zeek.redis`
- Redis - Source (table): `event.dataset:zeek.redis`
- Redis - Destination (table): `event.dataset:zeek.redis`
- Redis - Action and Result (table): `event.dataset:zeek.redis`
- Redis - Key (table): `event.dataset:zeek.redis`
- Redis - Key and Value (table): `event.dataset:zeek.redis`
- Redis - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, cmd.name, success, cmd.key, uid): `event.dataset:zeek.redis`

### RDP (`rdp.ndjson`)

- RDP - Log Count Over Time (chart): `event.dataset:zeek.rdp`
- RDP - Source IP Address (table): `event.dataset:zeek.rdp`
- RDP - Destination IP Address (table): `event.dataset:zeek.rdp`
- RDP - Cookie (table): `event.dataset:zeek.rdp`
- RDP - Result (pie chart): `event.dataset:zeek.rdp`
- RDP - Keyboard Layout (pie chart): `event.dataset:zeek.rdp`
- RDP - Client Version (chart): `event.dataset:zeek.rdp`
- RDP - Log Count (metric): `event.dataset:zeek.rdp`
- RDP - Encryption (pie chart): `event.dataset:zeek.rdp`
- RDP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, client_build, keyboard_layout, security_protocol, encryption_method, result, uid): `event.dataset:zeek.rdp`

### RFB (`rfb.ndjson`)

- RFB - Log Count Over Time (chart): `event.dataset:zeek.rfb`
- RFB - Authentication Status (pie chart): `event.dataset:zeek.rfb`
- RFB - Exclusive Session (pie chart): `event.dataset:zeek.rfb`
- RFB - Desktop Name (table): `event.dataset:zeek.rfb`
- RFB - Source IP Address (table): `event.dataset:zeek.rfb`
- RFB - Destination IP Address (table): `event.dataset:zeek.rfb`
- RFB - Destination Port (table): `event.dataset:zeek.rfb`
- RFB - Server Version (table): `event.dataset:zeek.rfb`
- RFB - Client Version (table): `event.dataset:zeek.rfb`
- RFB - Authentication Method (chart): `event.dataset:zeek.rfb`
- RFB - Log Count (metric): `event.dataset:zeek.rfb`
- RFB - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, desktop_name, authentication_method, auth, share_flag, uid): `event.dataset:zeek.rfb`

### SIP (`sip.ndjson`)

- SIP - Log Count Over Time (chart): `event.dataset:zeek.sip`
- SIP - Source IP Address (table): `event.dataset:zeek.sip`
- SIP - Destination IP Address (table): `event.dataset:zeek.sip`
- SIP - Request Path (table): `event.dataset:zeek.sip`
- SIP - URI (table): `event.dataset:zeek.sip`
- SIP - User Agent (table): `event.dataset:zeek.sip`
- SIP - Content Type (pie chart): `event.dataset:zeek.sip`
- SIP - Method (chart): `event.dataset:zeek.sip`
- SIP - Destination Port (table): `event.dataset:zeek.sip`
- SIP - Log Count (metric): `event.dataset:zeek.sip`
- SIP - Status (table): `event.dataset:zeek.sip`
- SIP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, method, content_type, status_msg, uid): `event.dataset:zeek.sip`

### SMB (`smb.ndjson`)

- SMB - Log Count Over Time (chart): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Source IP Address (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Destination IP Address (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Version (pie chart): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - FIle Path (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - File Name (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - File/Path Summary (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Log Count (metric): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Destination Port (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB Action (table): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`
- SMB - Logs (Discover table of event.dataset, id.orig_h, id.resp_h, id.resp_p, version, action, uid): `event.dataset:(zeek.smb_files OR zeek.smb_mapping)`

### SMTP (`smtp.ndjson`)

- SMTP - Log Count Over Time (chart): `event.dataset:zeek.smtp`
- SMTP - Subject (table): `event.dataset:zeek.smtp`
- SMTP - "From" Address (table): `event.dataset:zeek.smtp`
- SMTP - "To" Address (table): `event.dataset:zeek.smtp`
- SMTP - TLS (pie chart): `event.dataset:zeek.smtp`
- SMTP - Source IP Address (table): `event.dataset:zeek.smtp`
- SMTP - Destination IP Address (table): `event.dataset:zeek.smtp`
- SMTP - User Agent (table): `event.dataset:zeek.smtp`
- SMTP - Destination Port (table): `event.dataset:zeek.smtp`
- SMTP - Log Count (metric): `event.dataset:zeek.smtp`
- SMTP - Logs (Discover table of x_originating_ip, id.orig_h, id.resp_h, id.resp_p, mailfrom, user_agent, uid): `event.dataset:zeek.smtp`

### SNMP (`snmp.ndjson`)

- SNMP - Log Count Over Time (chart): `event.dataset:zeek.snmp`
- SNMP - Source IP Address (table): `event.dataset:zeek.snmp`
- SNMP - Destination IP Address (table): `event.dataset:zeek.snmp`
- SNMP - Session Duration (table): `event.dataset:zeek.snmp`
- SNMP - Log Count (metric): `event.dataset:zeek.snmp`
- SNMP - Community String (table): `event.dataset:zeek.snmp`
- SNMP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, version, community, uid): `event.dataset:zeek.snmp`

### SSH (`ssh.ndjson`)

- SSH - Log Count Over Time (chart): `event.dataset:zeek.ssh`
- SSH - Source IP Address (table): `event.dataset:zeek.ssh`
- SSH - Destination IP Address (table): `event.dataset:zeek.ssh`
- SSH - Client/Server (table): `event.dataset:zeek.ssh`
- SSH - Log Count (metric): `event.dataset:zeek.ssh`
- SSH -Server (table): `event.dataset:zeek.ssh`
- SSH - Version (pie chart): `event.dataset:zeek.ssh`
- SSH - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, auth_success, cipher_alg, mac_alg, uid): `event.dataset:zeek.ssh`

### SSL (`ssl.ndjson`)

- SSL - Log Count Over Time (chart): `event.dataset:zeek.ssl`
- SSL - Version (pie chart): `event.dataset:zeek.ssl`
- SSL - Source IP Address (table): `event.dataset:zeek.ssl`
- SSL - Destination Port (table): `event.dataset:zeek.ssl`
- SSL - Destination Address (table): `event.dataset:zeek.ssl`
- SSL - Log Count (metric): `event.dataset:zeek.ssl`
- SSL - Connection Established (pie chart): `event.dataset:zeek.ssl`
- SSL - Certificate Fingerprint (table): `event.dataset:zeek.ssl`
- SSL - Elliptic Curve (chart): `event.dataset:zeek.ssl`
- SSL - Next Protocol (table): `event.dataset:zeek.ssl`
- SSL - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, server_name, established, ssl_history, sni_matches_cert, uid): `event.dataset:zeek.ssl`

### X.509 (`x-509.ndjson`)

- X.509 - Log Count Over Time (chart): `event.dataset:zeek.x509`
- X.509 - Certificate Signing Algorithm (pie chart): `event.dataset:zeek.x509`
- X.509 - Certificate Subject (table): `event.dataset:zeek.x509`
- X.509 - Certificate Issuer (table): `event.dataset:zeek.x509`
- X.509 - Certificate Key Length (chart): `event.dataset:zeek.x509`
- X.509 - Certificate Key Algorithm (chart): `event.dataset:zeek.x509`
- X.509 - Log Count (metric): `event.dataset:zeek.x509`
- OCSP - Certificate Revocation (table): `(event.dataset:zeek.ocsp) AND (NOT certStatus:good)`
- X.509 - Is Host Certificate (pie chart): `event.dataset:zeek.x509`
- X.509 - Is Client Certificate (pie chart): `event.dataset:zeek.x509`
- X.509 - Certificate Fingerprint (table): `event.dataset:zeek.x509`
- X.509 - Logs (Discover table of host_cert, client_cert, certificate.sig_alg, certificate.version): `event.dataset:zeek.x509`
- OCSP - Logs (Discover table of thisUpdate, nextUpdate, certStatus, revokereason, revoketime, serialNumber, id): `event.dataset:zeek.ocsp`

### Syslog (`syslog.ndjson`)

- Syslog - Log Count Over Time (chart): `event.dataset:zeek.syslog`
- Syslog - Source IP Address (table): `event.dataset:zeek.syslog`
- Syslog - Destination IP Address (table): `event.dataset:zeek.syslog`
- Syslog - Destination Port (table): `event.dataset:zeek.syslog`
- Syslog - Log Count (metric): `event.dataset:zeek.syslog`
- Syslog - Severity (pie chart): `event.dataset:zeek.syslog`
- Syslog - Facility (chart): `event.dataset:zeek.syslog`
- Syslog - Protocol (pie chart): `event.dataset:zeek.syslog`
- Syslog (Zeek) - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, severity, facility, message, uid): `event.dataset:zeek.syslog`

### Tunnels (`tunnels.ndjson`)

- Tunnels - Log Count Over Time (chart): `event.dataset:zeek.tunnel`
- Tunnels - Type (pie chart): `event.dataset:zeek.tunnel`
- Tunnels - Destination Address (table): `event.dataset:zeek.tunnel`
- Tunnels - Source IP Address (table): `event.dataset:zeek.tunnel`
- Tunnels - Action (chart): `event.dataset:zeek.tunnel`
- Tunnels - Log Count (metric): `event.dataset:zeek.tunnel`
- Tunnels - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, action, tunnel_type, uid): `event.dataset:zeek.tunnel`

### Modbus (`modbus.ndjson`)

- Modbus - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, func, exception, unit, tid, uid): `event.dataset:zeek.modbus`
- Modbus - Source IP (table): `event.dataset:zeek.modbus`
- Modbus - Destination IP (table): `event.dataset:zeek.modbus`
- Modbus - Log Count (metric): `event.dataset:zeek.modbus`
- Modbus - Logs Over Time (chart): `event.dataset:zeek.modbus`
- Modbus - Functions and Exceptions (table): `(event.dataset:zeek.modbus) AND (func:* OR exception:*)`

### DNP3 (`dnp3.ndjson`)

- DNP3 - Source IP (table): `event.dataset:zeek.dnp3`
- DNP3 - Destination IP (table): `event.dataset:zeek.dnp3`
- DNP3 - Function Request (table): `event.dataset:zeek.dnp3`
- DNP3 - Function Reply (table): `event.dataset:zeek.dnp3`
- DNP3 - Log Count (metric): `event.dataset:zeek.dnp3`
- DNP3 - Logs Over Time (chart): `event.dataset:zeek.dnp3`
- DNP3 - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, fc_request, fc_reply, uid): `event.dataset:zeek.dnp3`
