🚀 Overview

**InfoSec Suite** is an advanced web-based cybersecurity platform that integrates phishing detection, file integrity verification, and risk-based decision making into a unified system.

## 🧠 Key Features

### 🔍 Phishing URL Detection

* Machine Learning (Random Forest) + Rule-Based Analysis
* Detects suspicious patterns in URLs
* Provides confidence score and explainable results

### 🔗 Redirect Chain Visualization

* Simulates multi-step URL redirection
* Identifies hidden malicious destinations
* Enhances detection of phishing attack paths

### 🔐 File Integrity Verification

* Uses SHA-256 hashing
* Detects file tampering via hash comparison
* Supports expected hash validation

### ⚖️ Risk-Based Decision Engine

* Combines URL analysis + file integrity
* Outputs:

  * ✅ Allow
  * ⚠️ Warn
  * 🚨 Block

### 🧠 Explainable Security Output

* Shows reasons for detection
* Provides transparency in decision-making

---

## ⚙️ Tech Stack

* **Backend:** Python (Flask)
* **Machine Learning:** Scikit-learn
* **Frontend:** HTML, CSS
* **Security Concepts:** Hashing, Threat Analysis, Risk Evaluation

---

## 🧪 How It Works

1. User enters a URL
2. System analyzes URL (ML + rules + redirects)
3. Displays risk score and explanation
4. User checks file integrity (optional)
5. System verifies file using SHA-256
6. Final decision is generated

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/InfoSec-Suite.git
cd InfoSec-Suite
pip install -r requirements.txt
python app.py
```

## 👨‍💻 Author

Savarna
