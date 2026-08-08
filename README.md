<div align="center">

# 🕵️‍♂️ OSINT-Scanner 🕵️‍♀️
### *Advanced Open-Source Intelligence & Reconnaissance Engine*

<p align="center">
  <b>A modern, modular, and dual-interface reconnaissance tool designed for deep digital footprint analysis.</b>
</p>

<!-- Badges -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/Interface-CLI%20%2F%20GUI-orange?style=for-the-badge" alt="Interface">
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-gallery--interface">Gallery</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-modules--capabilities">Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a>
</p>

</div>

---

## 🌟 Overview

**OSINT-Scanner** is a comprehensive open-source intelligence utility crafted to streamline reconnaissance workflows. Whether you are conducting security audits, tracking digital footprints, or gathering threat intelligence, this engine delivers deep data collection through automated modules. Built with flexibility in mind, it provides a sleek **Graphical User Interface (GUI)** for interactive analysis and a lightning-fast **Command Line Interface (CLI)** for automated scripting.

---

## 📸 Gallery & Interface

Explore the clean, intuitive layout of the OSINT-Scanner desktop application. The GUI is divided into specialized intelligence tabs for organized analysis.

<p align="center">
  <img src="docs/images/gui_1.png" alt="Main Dashboard" width="48%" style="border-radius: 5px; margin: 1%;">
  <img src="docs/images/gui_2.png" alt="WHOIS & DNS Analysis" width="48%" style="border-radius: 5px; margin: 1%;">
</p>
<p align="center">
  <img src="docs/images/gui_3.png" alt="GeoIP Tracking" width="48%" style="border-radius: 5px; margin: 1%;">
  <img src="docs/images/gui_4.png" alt="Shodan Reconnaissance" width="48%" style="border-radius: 5px; margin: 1%;">
</p>
<p align="center">
  <img src="docs/images/gui_5.png" alt="Subdomain Enumeration" width="48%" style="border-radius: 5px; margin: 1%;">
  <img src="docs/images/gui_6.png" alt="Data Leaks & Export" width="48%" style="border-radius: 5px; margin: 1%;">
</p>

---

## 🚀 Key Features

*   ⚡ **High-Speed Execution:** Asynchronous data processing optimized with built-in rate-limiting and robust fallback mechanisms.
*   💻 **Dual Interface:** Seamlessly switch between the intuitive `Tkinter` desktop dashboard and the `Rich`-styled terminal CLI.
*   📂 **Batch Processing:** Load multiple targets from a `.txt` file directly into the GUI or CLI for mass reconnaissance.
*   📊 **Automated Reporting:** Instantly export findings into structured JSON files. View them directly from the GUI with the "Open JSON" and "Results Folder" quick-access buttons.
*   🛡️ **Resilient Error Handling:** Gracefully handles dropped connections, invalid targets, and API rate limits without breaking execution flow.

---

## 🧩 Modules & Capabilities

The scanner is broken down into specialized tabs and core modules, allowing for targeted data gathering:

| Module | Capability | Description |
| :--- | :--- | :--- |
| 🌐 **WHOIS** | Domain Info | Extracts registrar details, creation dates, and expiration schedules. |
| 🖧 **DNS** | Nameservers | Maps and resolves standard record types (A, AAAA, MX, NS, TXT, SOA). |
| 📍 **GeoIP** | Location | Resolves server coordinates, Autonomous System Numbers (ASN), and ISPs. |
| 🔍 **Shodan** | IoT Search | Identifies open ports, running services, and known vulnerabilities (Requires API Key). |
| 🌳 **Subdomains** | Asset Discovery | Maps the broader attack surface via passive logs and brute-forcing. |
| 🚨 **Leaks** | Threat Intel | Cross-references domains against known data breaches and GitHub exposure hits. |

---

## 📂 Project Architecture

```text
OSINT-Scanner/
├── config/             # External wordlists, API keys, & parameters
├── docs/               
│   └── images/         # GUI screenshots (gui_1.png to gui_6.png)
├── modules/            # Specialized intelligence-gathering Python scripts
├── results/            # Auto-generated JSON output logs
├── config.py           # Core configuration loader
├── gui.py              # Desktop GUI application entry point
├── output.py           # Console styling, tables, and exporters
├── scanner.py          # Main CLI orchestrator & execution engine
├── PROJECT_REPORT.md   # Comprehensive internal project analysis
├── requirements.txt    # Python dependencies
└── LICENSE             # MIT Open Source License
