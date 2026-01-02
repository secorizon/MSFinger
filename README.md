# MSFinger - Microsoft Network Service Fingerprinting Tool

**Version:** 1.0  
**Author:** Laurent Gaffie  
**Company:** Secorizon

## Overview

MSFinger is a high-performance network fingerprinting tool designed for internal network reconnaissance. It rapidly identifies Microsoft services, detects security configurations, and highlights potential vulnerabilities across SMB, LDAP, and LDAPS protocols.

**Key Features:**
- Fast concurrent scanning optimized for internal networks (1-second timeout default)
- SMB/SMB2/SMB3 version and signing detection
- LDAP/LDAPS signing and channel binding detection
- OS version identification with build number mapping
- SQLite database for persistent scan results
- Color-coded output highlighting security risks
- Support for single IPs, CIDR ranges, IP ranges, and file input

---

## Installation

MSFinger is written in pure python. No additional dependencies required beyond Python 3.6+.

```bash
cd /path/to/MSFinger
chmod +x MSFinger.py
```

---

## Usage

### Basic Syntax

```bash
python3 MSFinger.py -i <target> [options]
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --ip` | Target IP, CIDR range, or IP range | Required* |
| `-f, --file` | File containing targets (one per line) | Required* |
| `-t, --timeout` | Connection timeout in seconds | 1.0 |
| `-w, --workers` | Number of concurrent workers | 100 |
| `-d, --database` | SQLite database file for results | MSFinger.db |
| `--no-color` | Disable colored output | Disabled |

\* Either `-i` or `-f` must be specified

---

## Examples

### Single Host Scan
```bash
python3 MSFinger.py -i 192.168.1.10
```

### Subnet Scan (CIDR)
```bash
python3 MSFinger.py -i 192.168.1.0/24
```

### IP Range Scan
```bash
python3 MSFinger.py -i 192.168.1.1-50
```

### Multiple Ranges from File
```bash
python3 MSFinger.py -f targets.txt
```

Example `targets.txt`:
```
192.168.1.0/24
10.0.0.1-100
172.16.5.50
# Comments are supported
192.168.2.0/25
```

### Custom Timeout and Workers
```bash
# Faster scan with shorter timeout and more workers
python3 MSFinger.py -i 10.0.0.0/16 -t 0.3 -w 200

# More reliable scan with longer timeout
python3 MSFinger.py -i 192.168.1.0/24 -t 1.0 -w 50
```

### Custom Database
```bash
python3 MSFinger.py -i 192.168.1.0/24 -d pentest_2026.db
```

### Disable Colors (for logging)
```bash
python3 MSFinger.py -i 192.168.1.0/24 --no-color > scan_results.txt
```

---

## Output Format

### Console Output

Results are displayed in real-time with color-coded security indicators:

```
[192.168.1.10] SMB: 3.1.1, Signing: required, OS: Windows Server 2022 21H2, Domain: CORP.LOCAL, Boot: 2026-01-01 10:30:15 | SMB1: disabled | Services: RDP, LDAP (signing: required), LDAPS (signing: required, channel binding: required)
```

#### Color Coding

- 🟢 **GREEN**: Secure configuration (signing required)
- 🟡 **YELLOW**: Warning (enabled but not required, or port open with errors)
- 🔴 **RED**: Vulnerable (signing disabled or not required)
- 🔵 **BLUE**: Informational (SMB1 disabled, service status)

#### Output Fields

**SMB Information:**
- `SMB: X.X.X` - SMB dialect version (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1)
- `Signing: <status>` - required/enabled/disabled
- `OS: <version>` - Windows version with build number
- `Domain: <name>` - NetBIOS domain/workgroup name
- `Boot: <time>` - System boot time (or Disabled/Unknown)

**SMB1 Status:**
- `SMB1: disabled` - SMB1 not supported (secure)
- `SMB1: supported, Signing: <status>` - SMB1 enabled (potential risk)

**Services:**
- `RDP` - Remote Desktop Protocol (port 3389) open
- `MSSQL` - Microsoft SQL Server (port 1433) open
- `LDAP (signing: <status>)` - LDAP on port 389
- `LDAPS (signing: <status>, channel binding: <status>)` - LDAPS on port 636
- `LDAPS (port open, <error>)` - LDAPS port responding but SSL handshake failed

---

## Database Schema

MSFinger stores all scan results in an SQLite database for persistent storage and analysis.

### Table: `hosts`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `ip` | TEXT | IP address (unique) |
| `hostname` | TEXT | Hostname (reserved for future use) |
| `os_version` | TEXT | Operating system version |
| `os_build` | INTEGER | OS build number |
| `domain` | TEXT | Domain/workgroup name |
| `boot_time` | TEXT | System boot timestamp |
| `smb_dialect` | TEXT | SMB protocol version |
| `smb_signing` | TEXT | SMB signing status |
| `smb1_supported` | INTEGER | SMB1 enabled (0=no, 1=yes) |
| `smb1_signing` | TEXT | SMB1 signing status |
| `rdp_open` | INTEGER | RDP port open (0=no, 1=yes) |
| `mssql_open` | INTEGER | MSSQL port open (0=no, 1=yes) |
| `ldap_signing` | TEXT | LDAP signing status |
| `ldaps_signing` | TEXT | LDAPS signing status |
| `ldaps_channel_binding` | TEXT | LDAPS channel binding status |
| `ldaps_error` | TEXT | LDAPS connection error (if any) |
| `scan_time` | TIMESTAMP | First scan timestamp |
| `last_seen` | TIMESTAMP | Most recent scan timestamp |

### Database Behavior

- **Existing database:** Records are updated with latest scan data (upsert operation)
- **New database:** Created automatically with proper schema
- **Duplicate IPs:** Last scan result overwrites previous data for the same IP

### Querying the Database

```bash
# View all vulnerable hosts (no SMB signing)
sqlite3 MSFinger.db "SELECT ip, os_version, smb_signing FROM hosts WHERE smb_signing != 'required'"

# Find hosts with LDAP signing disabled
sqlite3 MSFinger.db "SELECT ip, domain, ldap_signing FROM hosts WHERE ldap_signing = 'not_required'"

# List all Windows Server 2022 hosts
sqlite3 MSFinger.db "SELECT ip, os_version, domain FROM hosts WHERE os_version LIKE '%Server 2022%'"

# Export to CSV
sqlite3 -header -csv MSFinger.db "SELECT * FROM hosts" > results.csv

# Count hosts by OS
sqlite3 MSFinger.db "SELECT os_version, COUNT(*) FROM hosts GROUP BY os_version"
```

---

## Detection Details

### SMB/SMB2/SMB3 Detection

**Protocols Tested:**
- SMB1 (legacy protocol, security risk if enabled)
- SMB2/3 (modern protocols with multiple dialects)

**Information Gathered:**
1. **Dialect Version:** 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
2. **Signing Status:** 
   - `required` - Server requires message signing (secure)
   - `enabled` - Server supports but doesn't require signing
   - `disabled` - No signing support (vulnerable)
3. **OS Version:** Extracted from NTLMSSP challenge
4. **Build Number:** Windows build number for precise version identification
5. **Domain:** NetBIOS domain or workgroup name
6. **Boot Time:** System startup timestamp (if available)

**OS Version Mapping:**

| Build Range | Operating System |
|-------------|------------------|
| 10240 | Windows 10 1507 |
| 14393 | Windows 10 1607 / Server 2016 |
| 17763 | Windows 10 1809 / Server 2019 |
| 19041-19045 | Windows 10 20H2 - 22H2 |
| 20348 | Windows Server 2022 21H2 |
| 22000+ | Windows 11 |
| 25398 | Windows Server 2025 |

### LDAP Detection (Port 389)

Tests anonymous bind to determine signing requirements:

- **Result Code 0:** Success - signing NOT required (vulnerable to relay attacks)
- **Result Code 8:** Strong auth required - signing IS required (secure)
- **Other codes:** Various authentication errors

### LDAPS Detection (Port 636)

Tests SSL/TLS connection with LDAP bind:

1. **SSL Handshake:** Attempts TLS connection with permissive cipher support
2. **Signing Detection:** Tests LDAP message signing over SSL
3. **Channel Binding:** Detects if TLS channel binding is enforced

**Possible Results:**
- `signing: required, channel binding: required` - Maximum security (secure)
- `signing: not_required, channel binding: not_required` - No protections (vulnerable)
- `port open, SSL handshake failed` - Port responding but SSL negotiation failed
- `port open, Connection error: 104` - Connection reset by peer

---

## Security Analysis

### Critical Findings (🔴 Red)

**SMB Signing Disabled:**
- Vulnerable to SMB relay attacks
- Attacker can intercept and relay authentication
- **Recommendation:** Enable SMB signing via Group Policy

**LDAP Signing Not Required:**
- Vulnerable to LDAP relay attacks
- Credentials can be relayed to other services
- **Recommendation:** Set `LdapEnforceChannelBinding=2` and `LDAPServerIntegrity=2` in registry

**LDAPS Without Channel Binding:**
- Vulnerable to LDAPS relay despite encryption
- **Recommendation:** Enable Extended Protection for Authentication

### Warnings (🟡 Yellow)

**SMB Signing Enabled (not required):**
- Better than disabled but not enforced
- Clients can choose not to sign
- **Recommendation:** Change from "enabled" to "required"

**SMB1 Supported:**
- Legacy protocol with known vulnerabilities
- Should be disabled unless required by legacy systems
- **Recommendation:** Disable SMBv1 via PowerShell or Group Policy

### Good Configurations (🟢 Green)

**SMB Signing Required:**
- All SMB traffic is cryptographically signed
- Prevents relay attacks

**LDAP/LDAPS Signing Required:**
- LDAP messages are signed
- Protects against tampering and relay

**Channel Binding Enforced:**
- TLS channel binding prevents SSL relay
- Highest level of LDAPS security

---

## Performance Tuning

### Timeout Recommendations

| Network Type | Recommended Timeout | Workers |
|-------------|---------------------|---------|
| Fast internal LAN (1Gbps+) | 0.5s | 200-300 |
| Normal internal network | 1.0s (default) | 100-150 |
| Slow/wireless network | 2.0-3.0s | 50-100 |
| VPN connection | 3.0-5.0s | 30-50 |

### Memory Considerations

Each worker consumes minimal memory (~1-2MB). Adjust workers based on system resources:

```bash
# High-performance scan (requires good CPU/RAM)
python3 MSFinger.py -i 10.0.0.0/8 -t 0.5 -w 500

# Conservative scan (low resource usage)
python3 MSFinger.py -i 192.168.0.0/16 -t 2.0 -w 50
```

---

## Troubleshooting

### No Results Appearing

1. **Check network connectivity:**
   ```bash
   ping <target_ip>
   telnet <target_ip> 445
   ```

2. **Increase timeout:**
   ```bash
   python3 MSFinger.py -i <target> -t 3.0
   ```

3. **Check firewall rules:**
   - Ensure ports 445, 389, 636, 3389, 1433 are accessible
   - Verify no host-based firewall blocking scans

### LDAPS Connection Errors

**"SSL handshake failed" or "Connection error: 104":**
- Server may require client certificate authentication
- Server may use non-standard SSL/TLS configuration
- Try using `openssl s_client -connect <ip>:636` to diagnose

### Database Locked

If scanning from multiple processes:
```bash
# Use different database files
python3 MSFinger.py -i 192.168.1.0/24 -d scan1.db &
python3 MSFinger.py -i 192.168.2.0/24 -d scan2.db &
```

### Permission Errors

Ensure the script is executable:
```bash
chmod +x MSFinger.py
```

---

## Integration Examples

### Nmap Integration

Identify live SMB hosts first, then fingerprint:
```bash
nmap -p445 --open -oG - 192.168.1.0/24 | awk '/445\/open/{print $2}' > smb_hosts.txt
python3 MSFinger.py -f smb_hosts.txt
```

### Scheduled Scanning

Monitor network changes with cron:
```bash
# Add to crontab (every day at 2 AM)
0 2 * * * /usr/bin/python3 /path/to/MSFinger.py -i 192.168.1.0/24 -d /var/scans/daily_scan.db
```

### PowerShell Export

Query and remediate from PowerShell:
```powershell
# Install SQLite PowerShell module
Install-Module -Name SimplySql

# Query vulnerable hosts
Open-SQLiteConnection -DataSource "MSFinger.db"
$vulnerable = Invoke-SqlQuery -Query "SELECT ip FROM hosts WHERE smb_signing != 'required'"
Close-SqlConnection

# Remediate
foreach ($host in $vulnerable) {
    Set-SmbServerConfiguration -ComputerName $host.ip -RequireSecuritySignature $true -Force
}
```

---

## Credits

**Author:** Laurent Gaffie (lgaffie@secorizon.com)  
**License:** GNU General Public License v3.0  


---

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
