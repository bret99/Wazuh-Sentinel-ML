# 🛡️ Wazuh Sentinel ML

**Wazuh Sentinel ML** is an advanced User and Entity Behavior Analytics (UEBA) engine designed to augment Wazuh SIEM with Machine Learning capabilities. By leveraging the **Isolation Forest** algorithm, it identifies stealthy threats, off-hours compromises, and credential abuse that traditional signature-based rules might miss.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Wazuh: 4.x](https://img.shields.io/badge/Wazuh-4.x-blue.svg)](https://wazuh.com/)
[![ML: Isolation Forest](https://img.shields.io/badge/ML-Isolation_Forest-green.svg)](https://scikit-learn.org/)

---

## 🚀 Core Features

* **Behavioral Baseline**: Automatically learns "normal" user activity patterns.
* **Multi-Channel Alerting**: Sends detailed security reports via **Email** and compact alerts via **Telegram** and **VK Teams**.
* **Off-Hours Detection**: Special logic to highlight high-priority anomalies during non-working hours (marked with ⚠️).
* **Automated Maintenance**: Includes self-cleaning database logic to manage disk space in high-load environments.
* **Threat Intelligence**: Extracts and analyzes source IPs, usernames, and agent behavior across all Wazuh events.

---

## 🛠️ Installation & Setup

### 1. Clone & Dependencies
```bash
git clone https://github.com/bret99/Wazuh-Sentinel-ML.git
cd Wazuh-Sentinel-ML
pip install -r requirements.txt
```
### 2. Configuration

Fill in your credentials in access_tokens.py:

    Wazuh / OpenSearch API credentials.
    SMTP settings for Email alerts.
    Bot tokens for Telegram and VK Teams.
    Rules levels.
    UEBA night hours.

## 📖 Operating Workflow

The project follows a "Collect -> Train -> Detect" lifecycle.

### Phase 1: Data Collection (Baseline)

Before training the AI, collect events for at least 7 days. Run this hourly via Cron:
Bash

```
python3 get_wazuh_server_hour_events.py && python3 wazuh_soc_ml.py --mode global --file /tmp/wazuh_server_hour_events.json
```
### Phase 2: ML Model Training

Once you have sufficient data, calculate the training limit and build the model.

### Get the total number of collected events
```
sqlite3 /var/lib/soc_ai/events_ext_ueba.db "SELECT count(*) FROM events;"
```

### Train the model (replace [LIMIT] with the count from above)
```
python3 wazuh_soc_ml.py --mode global --file /tmp/wazuh_server_hour_events.json --train-ml --train-limit [LIMIT]
```

### Phase 3: Production & Monitoring

After training, continue running the hourly script. The system will now use the generated .pkl model to detect anomalies automatically.

### Phase 4: Maintenance

To prevent the database from growing too large, schedule the pruning script:
Bash

## Add to crontab
```
0 0 * * * /bin/bash /path/to/db_prune_ext_ueba.sh
```

📊 Alerting Priorities

In the UEBA Off-Hours section, the system prioritizes users marked with an exclamation mark (⚠️). These users have the highest anomaly scores and represent the greatest potential risk to the infrastructure.

---

## 💎 Support the Project

If this tool helps protect your infrastructure, consider supporting the developer! 

### Crypto Wallets
| Asset | Network | Address |
| :--- | :--- | :--- |
| **BTC** | Bitcoin | `bc1qjwl80sv06xj2yhumn6k6xemchryem923wwts5x` |
| **USDT / ETH** | Ethereum (ERC20) | `0xc01b996c7b08ccfad463f27e54f1e74e6ac6f9ff` |
| **USDT / SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |
| **TON** | TON Network | `UQBhPLwdFiJdh6sZ96sZfxrxD9Lu6NFtaUecWeoHSM-EPc0P` |
| **LTC** | Litecoin | `ltc1qkm58ks5kuc64rjwd74sfalc5xsn7h6sr4vt45w` |
| **SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |

---

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
