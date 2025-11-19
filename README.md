# eJPTv2 Lab Walkthroughs & Field Manual🚀

Welcome to my repository for the eLearnSecurity Junior Penetration Tester (eJPTv2) certification. This repository contains my detailed lab walkthroughs and custom cheatsheets compiled throughout my learning process.

> **⚠️ SPOILER WARNING**
>
> Please be aware that each lab walkthrough file contains the final solution, including the flag, at the end. If you are also studying for the eJPT, I highly recommend attempting the labs on your own before consulting these solutions.

## 📌 About This Project

This project serves as a portfolio of my hands-on lab work for the eJPTv2. The goal is to document my step-by-step processes for each lab and create a collection of quick-reference cheatsheets for essential tools and techniques.

## 📂 Repository Structure

The repository is organized into two main sections:

- **/1-Assessment-Methodologies/**
- **/2-Host-and-Network-Penetration-Testing/**
- **/3-Web-Application-Penetration-Testing/**
  - These directories contain the detailed, step-by-step walkthroughs for each lab within the eJPTv2 learning path.

-   **/Field-Manual/**
    -   This directory contains my primary strategic and tactical guide, **[eJPT-Field-Manual.md](Field-Manual/eJPT-Field-Manual.md)**, which gives up the trafitional cheatsheet format but provides quick-reference all-in-one commands and troubleshooting logic (OODA loops) for reconnaissance, exploitation, pivoting, and post-exploitation.

## 📖 How to Use the Field Manual

The Field Manual is designed not just as a list of commands, but as a decision-making framework for the exam. To navigate it efficiently, pay attention to the internal structure:

* **Quick Navigation & Indexing:** Use the **Quick Index** at the top of the document to instantly jump to major sections (e.g., Service Playbooks, Pivoting). Every major section also includes a **[Back to Index]** link for rapid return, minimizing scrolling time during the exam.
* **OODA Loop Framework:** The guide's structure (Observe, Orient, Decide, Act) is intended to help you troubleshoot when an attack fails, guiding you away from time-wasting "rabbit holes" and toward productive next steps.
* **Service Playbooks:** Use these sections (e.g., *Port 21: FTP*, *Port 80/443: HTTP/S*) as a checklist after initial Nmap scanning to ensure complete enumeration and systematic vulnerability checking for each open service.
* **Post-Exploitation Triage:** After gaining an initial shell, immediately navigate to the *Primary Triage* section. This is your mandatory starting point for discovery, network mapping, and assessing privilege escalation vectors.

## Disclaimer

All information in this repository is for educational purposes only. I am not responsible for any misuse of the information.
