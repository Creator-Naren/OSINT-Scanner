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
  <a href="#-key-features">Features</a> •
  <a href="#-project-structure">Architecture</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-license">License</a>
</p>

</div>

---

## 📸 Preview

<div align="center">
  <img src="https://via.placeholder.com/900x450/0f172a/38bdf8?text=OSINT-Scanner+Dashboard+Preview" alt="OSINT-Scanner Preview" width="100%" style="border-radius: 8px; border: 1px solid #334155;">
  <p><em>*Interactive Desktop GUI & Real-time Console Logging*</em></p>
</div>

---

## 🌟 Overview

**OSINT-Scanner** is a powerful open-source intelligence utility crafted to streamline reconnaissance workflows. Whether you are conducting security audits, tracking digital footprints, or gathering threat intelligence, this engine delivers comprehensive data collection through automated modules. Built with flexibility in mind, it gives users the freedom to operate via a sleek **Graphical User Interface (GUI)** or a lightning-fast **Command Line Interface (CLI)**.

---

## 🚀 Key Features

*   ⚡ **Asynchronous Execution:** High-speed data processing optimized with rate-limiting and robust fallback mechanisms.
*   💻 **Dual Interface:** Seamlessly switch between an intuitive `Tkinter` desktop dashboard and a `Rich`-styled terminal interface.
*   🧩 **Modular Architecture:** Easily plug in custom tracking scripts and intelligence-gathering modules without changing the core orchestrator.
*   📊 **Structured Reports:** Automatically logs and formats findings into clean console outputs and exportable JSON files.
*   🛡️ **Resilient Error Handling:** Gracefully handles dropped connections, invalid targets, and rate limits without breaking execution flow.

---

## 📂 Project Architecture

```text
OSINT-Scanner/
├── __pycache__/        # Compiled Python bytecode
├── config/             # External wordlists, API mappings, & parameters
├── docs/               # Documentation and reference reports
├── modules/            # Specialized intelligence-gathering components
├── results/            # Auto-generated JSON output logs
├── config.py           # Core configuration loader
├── gui.py              # Desktop GUI application entry point
├── output.py           # Console styling, tables, and exporters
├── scanner.py          # Main CLI orchestrator & execution engine
├── PROJECT_REPORT.md   # Comprehensive internal project analysis
└── LICENSE             # MIT Open Source License
