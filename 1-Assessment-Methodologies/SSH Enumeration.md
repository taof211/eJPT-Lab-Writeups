<img width="829" height="302" alt="3-8  SSH Login nmap" src="https://github.com/user-attachments/assets/2c6693f2-cf9b-4c57-af20-ea00980cfe33" />---
tags:
  - lab
  - red_team
  - enumeration
  - msfconsole
  - T1046
  - ctf
  - nmap
module: Assessment Methodologies
topic: Enumeration
date: 2025-10-17
status: completed
---
# Objective

Your task is to run the following auxiliary modules against the target:

- auxiliary/scanner/ssh/ssh_version
- auxiliary/scanner/ssh/ssh_login

The following username and password dictionary will be useful: 
- /usr/share/metasploit-framework/data/wordlists/common_users.txt 
- /usr/share/metasploit-framework/data/wordlists/common_passwords.txt

# Walkthrough

- Ran `ifconfig` and `ping -c 1 demo.ine.local` commands to identify the network information of the attack machine and the victim machine. Confirmed:
	- The IP addresses of both the machines
	- The target machine is online and pingable
	- The machines are in the same subnet

  <img width="1025" height="420" alt="3-8  SSH Login ifconfig" src="https://github.com/user-attachments/assets/607497e9-36cf-4aa7-a94c-d54fc5ae1172" />
  <img width="943" height="212" alt="3-8  SSH Login ping" src="https://github.com/user-attachments/assets/21971af4-7a48-4414-be6a-77453d86788f" />

- Conduct initial port scan with nmap, `nmap -sS -p 22 192.122.141.3 -oX victim.xml`

  <img width="829" height="302" alt="3-8  SSH Login nmap" src="https://github.com/user-attachments/assets/4c92a4ab-fe95-4742-b2f8-e0993740de4c" />

- Launch and set up msfconsole initially

  <img width="779" height="565" alt="3-8  SSH Login msf setup" src="https://github.com/user-attachments/assets/f0fa6569-e59b-4080-85cd-0d7ddc580a15" />

- We need to use `auxiliary/scanner/ssh/ssh_login` to check the ssh service version

  <img width="1465" height="791" alt="3-8  SSH Login version 1" src="https://github.com/user-attachments/assets/be8e83bd-c58e-49ff-be23-00b9ca9c251a" />
  <img width="1396" height="761" alt="3-8  SSH Login version 2" src="https://github.com/user-attachments/assets/0fd83f3f-5dc6-4ff4-be2b-d148e7e547b4" />

- Beyond the modules provided in the lab instruction, we need to use `auxiliary/scanner/ssh/ssh_enumusers` module first to identify the users. in the server. From the screenshot we can see that our first choice of action of the module was Malformed Packet, and unfortunately, according to the results returned, it failed in the false positive step, which means the action method is not suitable for the case, so we switched the action and tried again. It failed again.

  <img width="851" height="631" alt="3-8  SSH Login User Enumeration" src="https://github.com/user-attachments/assets/21521b59-3302-408a-9561-33baf1238192" />

- The configuration of the SSH server to prevent user enumeration looks successful. So we are switching to brute force attack to see if there's any weak authentication we can take advantages of. Before that, we need to confirm the authentication way used by the server. Run nmap script to check it, `nmap -p 22 --script=ssh-auth-methods 192.122.141.3`, and we can see both password and publickey are supported. That's a good news for us.

  <img width="1155" height="387" alt="3-8  SSH Login ssh auth" src="https://github.com/user-attachments/assets/52c43306-7758-413c-8ced-1717b89656f9" />

- As we've known the password authentication are supported, we can use `auxiliary/scanner/ssh/ssh_login` to see if we can brute force any weak passwords in the case. Weak password has been found.

  <img width="1490" height="388" alt="3-8  SSH Login brute force" src="https://github.com/user-attachments/assets/2c38a0f0-d568-4554-b0ca-a9a3e2d235fb" />

- The `ssh_login` module created a session for us after it found the usable password, so we can connect to the victim host with it directly.

  <img width="1142" height="485" alt="3-8  SSH Login shell" src="https://github.com/user-attachments/assets/d643d580-a605-4185-ad7b-937c2ce0a72e" />

- Use `find / -name "flag"`, we found the flag

  <img width="666" height="653" alt="3-8  SSH Login flag" src="https://github.com/user-attachments/assets/aa6ba0a5-df58-4452-9c67-9ec0790e6bcf" />

  
# Key Finds

- We knew the server OS is ubuntu 19.04 and SSH service is OpenSSH 7.9p1
- User enumeration failed, but, as we find password authentication is supported on the server, we successfully obtain weak passwords with brute forcing
- flag: eb09cc6f1cd72756da145892892fbf5a

# Tools Used

- NMAP - [[NMAP MOC]]
- Metasploit Framework [[SSH Version Scanner]] Module
- Metasploit Framework [[SSH Username Enumeration]] Module
- NMAP NSE [[ssh-auth-methods]] Script
- Metasploit Framework [[SSH Login Check Scanner]] Module
