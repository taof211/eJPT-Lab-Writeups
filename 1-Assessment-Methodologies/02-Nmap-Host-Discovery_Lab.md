---
tags:
  - "#lab"
  - red_team
  - T1018
  - T1046
topic: Footprinting & Scanning
date: 2025-10-11
module: Assessment Methodologies
---
# Objective

Your task is to discover available live hosts and their open ports using Nmap and identify the running services and applications.

# Walkthrough

- Using `ifconfig` and `ping` commands to identify the network information of the attack machine and the victim machine. Confirmed:
	- The IP addresses of both the machine
	- The target machine is online and reachable
	- The machines are not in the same subnet
    <img width="667" height="343" alt="ifconfig" src="https://github.com/user-attachments/assets/fdf085bd-df64-4d47-9f8f-fd6cf5c8c109" />
    <img width="603" height="130" alt="ping" src="https://github.com/user-attachments/assets/d6027a27-3b31-42e6-85d5-38b84734dcbc" />


- Using a series of `nmap -sn` commands to identify potential live hosts in the target network
```
nmap -sn -v 10.0.29.0/24
nmap -sn -v -PE -PS21,22,25,80,110,135,3389,445 -PU 10.0.29.0/24
```
  Only find the target machine provided is up.
  <img width="617" height="58" alt="Host Discovery" src="https://github.com/user-attachments/assets/02b80956-3d20-47ce-947f-72a8e94ecb23" />

- Using command `nmap -Pn -sV -v 10.0.29.65` to identify the open ports and services running on the them.
  <img width="835" height="182" alt="Services" src="https://github.com/user-attachments/assets/ce813095-e889-4475-87ef-daa8a2b53e8d" />


# Key Finds
 - The target machine IP is 10.0.29.65, and it's in a different subnet as the attack machine
 - In the subnet 10.0.29.0/24, no up machine identified expect the target machine
 - The target machine has 7 TCP ports opening where various services running on, as the picture above shows.
