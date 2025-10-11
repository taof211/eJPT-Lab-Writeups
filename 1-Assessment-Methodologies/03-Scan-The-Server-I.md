---
tags:
  - "#lab"
  - "#ctf"
  - red_team
  - T1018
  - T1046
topic: Footprinting & Scanning
date: 2025-10-12
module: Assessment Methodologies
---
# Objective

This lab covers the process of performing port scanning and service detection with Nmap.

# Walkthrough

- Ran `ipconfig` and `ping -c 1 demo.ine.local` commands to identify the network information of the attack machine and the victim machine. Confirmed:
	- The IP addresses of both the machine
	- The target machine is online and reachable
	- The machines are not in the same subnet

   <img width="1098" height="534" alt="Scan The Server I ifconfig" src="https://github.com/user-attachments/assets/c520540a-472a-4ab4-84cf-902d67a6113e" />
   <img width="1110" height="262" alt="Scan The Server I Ping" src="https://github.com/user-attachments/assets/b15e5b8f-73f7-4b8c-ba1a-5a2f869b2fce" />


- Ran `nmap -sS -sV -p- -T4 192.121.152.3` and got the ports and services version information initially
  
  <img width="1345" height="461" alt="Scan The Server I Service Version 1" src="https://github.com/user-attachments/assets/ee30f34d-8df0-436c-8c42-8ee989898663" />


# Key Finds

 - The target machine IP is 192.121.152.3, and it's in the same subnet as the attack machine
 - The target machine has 3 TCP ports opening where various services running on, as the picture above shows.
