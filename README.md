# CortexAV: Static Analysis and ML for Malware Detection

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![C#](https://img.shields.io/badge/C%23-.NET-purple)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-XGBoost%20%7C%20LightGBM%20%7C%20CatBoost-orange)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

**CortexAV** is an autonomous security agent that utilizes static analysis and machine learning to detect malware. Designed as an offline-first solution, the system analyzes Portable Executable (PE) characteristics without execution, addressing the limitations of traditional signature-based antivirus software.

> *This repository contains the source code and documentation developed for my Bachelor's Thesis at the Politehnica University of Timișoara, Faculty of Automation and Computing.*

---

## Architecture & Methodology

### Feature Extraction
The static analysis pipeline parses PE files to generate a dimensional space of 2381 features per executable, divided into:
* **Raw Features:** Byte histograms, byte-entropy histograms, and string characteristics.
* **Parsed Features:** General PE file information, header details, imported/exported functions, and section configurations.

### Machine Learning Engine
Implements an ensemble of gradient boosting models (XGBoost, LightGBM, CatBoost) utilizing Soft Voting for final classification. The system provides different operational thresholds:
* **Standard Model:** Optimized for stable general detection while maintaining a strict False Positive rate (0.15%).
* **Paranoid Mode:** Lowers the decision threshold to ~40% to favor sensitivity (Recall) against modern threats.

---

## Operating Modes

* **Individual Analysis (Dashboard):** Granular user control over suspected files (Quarantine, Delete, Whitelist).
* **Batch Processing:** Asynchronous, high-volume file scanning.
* **Real-Time Monitoring:** Proactive directory watchdog for immediate scanning of filesystem modifications.
* **OS Integration:** Native integration with the Windows context menu for on-demand scanning.

---

## Experimental Results

The models were evaluated against model decay (concept drift) using independent samples from *MalwareBazaar* and *theZoo*, chronologically partitioned (pre-2018 vs. post-2019).

| Configuration | General Detection | Post-2019 Detection | False Positive Rate |
| :--- | :---: | :---: | :---: |
| **CortexAV (Standard)** | 86.39% | 77.78% | 0.15% |
| **CortexAV (Paranoid)** | 90.16% | 81.94% | 1.23% |
| *Defender (Offline)* | *69.80%* | *N/A* | *High* |

---

## Build and Run Instructions

The core Machine Learning engine is written in **Python**, while the Graphical User Interface (GUI) and system integrations are built in **C# (.NET)**. 

### 1. Prerequisites
* **Python 3.11.9 (recommended)** (ensure Python is added to your system's PATH)
* **Visual Studio** (or compatible C# IDE / .NET SDK)
* **Windows OS**

### 2. Environment Setup
Clone the repository and install the backend dependencies:
```bash
git clone [https://github.com/rares8069/CortexAV.git](https://github.com/rares8069/CortexAV.git)
cd CortexAV
pip install -r requirements.txt
```

### 3. Build and run
Build the project.
Navigate to the output directory.
Run CortexAV.exe.


### Acknowledgments & License

EMBER Dataset: The machine learning models were trained using the EMBER 2018v2 dataset.

theZoo & MalwareBazaar: Independent malware samples used for testing and evaluation were sourced from theZoo and MalwareBazaar.

This project is licensed under the MIT License.

