# 📡 Wi-Fi Management & Security System

A **Streamlit-based dashboard** for real-time monitoring, security analysis, and network management for Wi-Fi networks. Designed for educational institutions like **Vainona High School**, this tool empowers IT staff to track, analyze, and secure their Wi-Fi network with ease.

---

## 🚀 Features

* 🔍 **Device Discovery** via ARP Scanning
* 🌐 **Network Scanning** using Nmap
* 📈 **Speed Testing** (Download, Upload, Ping)
* 💾 **Session Logging** using SQLite
* 📊 **System & Network Stats** (RAM, CPU, IP, hostname)
* 🔐 **Secure Access** via hashed credentials and encrypted config
* 🕒 **Timestamped Logs** in local timezone
* 📉 **Live Graphs** with Matplotlib
* 🔐 **Encryption** with Fernet (Cryptography library)

---

## 🛠️ Tech Stack

| Purpose             | Tool/Library                                    |
| ------------------- | ----------------------------------------------- |
| Web Dashboard       | `Streamlit`                                     |
| Data Handling       | `Pandas`                                        |
| System Monitoring   | `psutil`                                        |
| Network Scanning    | `nmap`, `scapy`                                 |
| Speed Test          | `speedtest`                                     |
| Database            | `sqlite3`                                       |
| Plotting            | `matplotlib`                                    |
| Timezone Conversion | `pytz`, `datetime`                              |
| Logging & Security  | `logging`, `hashlib`, `secrets`, `cryptography` |
| System Commands     | `subprocess`, `socket`, `os`                    |

---

## 📦 Installation

### 🔧 Prerequisites

* Python 3.8+
* [Nmap installed](https://nmap.org/download.html) and added to PATH
* Internet access for speed testing

### 📥 Clone & Install

```bash
unzip wifi-security-dashboard project folder
cd wifi-security-dashboard
pip install -r requirements.txt
```

### `requirements.txt` should include:

```
streamlit
pandas
psutil
pytz
speedtest-cli
cryptography
matplotlib
scapy
python-nmap
```

---

## ▶️ Run the App

```bash
streamlit run app.py
```

Once it launches, open in your browser at:
📍 `http://localhost:8501/`

---

## 🔐 Security Measures

* Passwords are hashed using SHA256
* Encryption keys are generated with `Fernet` for secure communication
* Logs are stored locally and timestamped using timezone-aware formats

---

## 🧪 Key Functions

* `scan_devices()` – Scans devices on the local network using ARP
* `run_nmap_scan()` – Runs port scans for open ports
* `check_speed()` – Measures current download/upload/ping speed
* `save_log()` – Stores data in SQLite with timestamps
* `encrypt()`/`decrypt()` – Secures sensitive data

---

## 🎯 Use Case: Vainona High School

* Monitor Wi-Fi usage in classrooms
* Detect unknown or unauthorized devices
* Maintain performance logs for IT audits
* Boost cyber-safety awareness for staff and students

---

## ✅ Future Enhancements

* User authentication with roles (admin, viewer)
* SMS/Email alerts for unauthorized access
* Graphical traffic monitoring per device
* Integration with router APIs for access control

---

## 👨‍💻 Developed By

**Elliot Kurangwa**
📍 Zimbabwe | 🧠 Empowering schools with smart tech