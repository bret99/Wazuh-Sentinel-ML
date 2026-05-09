#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sqlite3
import smtplib
import sys
import argparse
import hashlib
import pickle
import warnings
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from email.message import EmailMessage

import ijson
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Notifiers Integration
try:
    from vk_notifier import send_to_vk_teams
except ImportError:
    def send_to_vk_teams(msg): pass

try:
    from tg_notifier import send_to_telegram
except ImportError:
    def send_to_telegram(msg): pass

warnings.filterwarnings("ignore")

# Configuration
try:
    from access_tokens import (
        SMTP_SERVER, SMTP_PORT, EMAIL_FROM, EMAIL_PASSWORD, EMAIL_RECIPIENTS, NIGHT_START, NIGHT_END
    )
except ImportError:
    print("Error: access_tokens.py not found"); sys.exit(1)

DB_PATH = Path("/var/lib/soc_ai/events_ext_ueba.db")
ML_MODEL_PATH = Path("/var/lib/soc_ai/anomaly_model_ext_ueba.pkl")
SQL_TIMEOUT = 300

RE_USER = re.compile(r'(?:user|srcuser|dstuser|username)[:\s=]+([a-z0-9\._\\\@\-]+)', re.IGNORECASE)
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class AdvancedAnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.user_freq = {}
        self.agent_map = {}
        self.is_trained = False
        if ML_MODEL_PATH.exists():
            try:
                with open(ML_MODEL_PATH, 'rb') as f:
                    d = pickle.load(f)
                    self.model = d['model']
                    self.scaler = d['scaler']
                    self.user_freq = d.get('user_freq', {})
                    self.agent_map = d.get('agent_map', {})
                    self.is_trained = True
            except: pass

    def ip_to_features(self, ip_str):
        try:
            if not ip_str or ip_str == 'unknown': return [0, 0, 0, 0]
            parts = [int(x) for x in ip_str.split('.')]
            return parts if len(parts) == 4 else [0, 0, 0, 0]
        except: return [0, 0, 0, 0]

    def prepare_features(self, hour, level, user, ip, agent, rule_id):
        u_f = self.user_freq.get(user, 1)
        a_id = self.agent_map.get(agent, 0)
        r_id = int(rule_id) if str(rule_id).isdigit() else 0
        return [hour, level, u_f, a_id, r_id] + self.ip_to_features(ip)

    def predict_batch(self, feature_list):
        if not self.is_trained or not feature_list: return [False] * len(feature_list)
        try:
            X = self.scaler.transform(feature_list)
            return [p == -1 for p in self.model.predict(X)]
        except: return [False] * len(feature_list)

class SOCAnalyzer:
    def __init__(self):
        self.detector = AdvancedAnomalyDetector()

    def extract_user(self, event):
        d = event.get('data', {})
        win = d.get('win', {}).get('eventdata', {})
        fields = [
            d.get('srcuser'), d.get('src_user'), d.get('dstuser'), d.get('dst_user'),
            d.get('un'), d.get('gitlab_user'), d.get('gitlab_username'),
            event.get('user'), d.get('jira_creator'), d.get('confluence_creator'),
            event.get('syscheck', {}).get('uname_after'),
            win.get('targetUserName'), win.get('subjectUserName')
        ]
        for f in fields:
            if f and str(f).lower() not in ['unknown', '', '-', 'null', 'none']: return str(f)
        m = RE_USER.search(str(event.get('full_log', ''))); return m.group(1) if m else 'unknown'

    def extract_ip(self, event):
        d = event.get('data', {})
        fields = [
            event.get('srcip'), d.get('srcip'), event.get('src_ip'), d.get('src_ip'),
            d.get('dstip'), event.get('ip'), d.get('dst_ip'), d.get("source.ip"), d.get("destination.ip"),
            d.get('win', {}).get('eventdata', {}).get('ipAddress')
        ]
        for f in fields:
            val = str(f).strip()
            if val and val.lower() != 'unknown' and RE_IP.match(val): return val
        return 'unknown'

    def _save_to_db(self, events):
        if not events: return
        try:
            with sqlite3.connect(str(DB_PATH), timeout=SQL_TIMEOUT) as conn:
                conn.execute('''CREATE TABLE IF NOT EXISTS events 
                             (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, agent TEXT, user TEXT, 
                              src_ip TEXT, rule_level INTEGER, rule_description TEXT, rule_id TEXT, 
                              status TEXT, event_hash TEXT UNIQUE)''')
                recs = [(e['timestamp'], e['agent'], e['user'], e['src_ip'], e['rule_level'], 
                         e['rule_description'], e['rule_id'], e['status'],
                         hashlib.md5(f"{e['timestamp']}{e['rule_id']}{e['user']}".encode()).hexdigest()) for e in events]
                conn.executemany("INSERT OR IGNORE INTO events (timestamp, agent, user, src_ip, rule_level, rule_description, rule_id, status, event_hash) VALUES (?,?,?,?,?,?,?,?,?)", recs)
        except Exception as e:
            print(f"⚠️ DB Warning: {e}")

    def process_file(self, file_path):
        stats = {
            'total': 0, 'levels': Counter(), 'failed_logins': 0,
            'users_failed': Counter(), 'sources_failed': Counter(),
            'all_users': Counter(), 'all_sources': Counter(),
            'clusters': Counter(), 'anomalies': [], 'night_events': []
        }
        ml_buffer, ev_buffer, db_batch = [], [], []
        
        with open(file_path, 'r') as f:
            for item in ijson.items(f, 'item'):
                user = self.extract_user(item)
                ip = self.extract_ip(item)
                rule = item.get('rule', {})
                lvl = int(rule.get('level', 0))
                desc = rule.get('description', 'No description')
                agent = item.get('agent', {}).get('name', 'unknown')
                rid = str(rule.get('id', '0'))
                
                ev = {
                    'timestamp': item.get('@timestamp', datetime.utcnow().isoformat()),
                    'agent': agent, 'user': user, 'src_ip': ip, 'rule_level': lvl,
                    'rule_description': desc, 'rule_id': rid,
                    'status': 'failed' if any(x in desc.lower() for x in ['fail', 'denied', 'error', 'failed', 'unsuccessful']) else 'success'
                }

                stats['total'] += 1
                stats['levels'][lvl] += 1
                stats['all_users'][user] += 1
                stats['all_sources'][ip] += 1
                
                if ev['status'] == 'failed' and user != 'unknown':
                    stats['failed_logins'] += 1
                    stats['users_failed'][user] += 1
                    stats['sources_failed'][ip] += 1

                if lvl >= 8: stats['clusters'][desc] += 1

                try:
                    dt = datetime.fromisoformat(ev['timestamp'].replace('Z','+00:00'))
                    if dt.hour >= NIGHT_START or dt.hour <= NIGHT_END:
                        if lvl >= 5:
                            stats['night_events'].append(ev)
                except: pass

                if lvl >= 3:
                    try:
                        ml_buffer.append(self.detector.prepare_features(dt.hour, lvl, user, ip, agent, rid))
                        ev_buffer.append(ev)
                    except: pass
                
                db_batch.append(ev)
                if len(db_batch) >= 5000:
                    self._save_to_db(db_batch)
                    if self.detector.is_trained and ml_buffer:
                        preds = self.detector.predict_batch(ml_buffer)
                        stats['anomalies'].extend([ev_buffer[i] for i, p in enumerate(preds) if p])
                    db_batch, ml_buffer, ev_buffer = [], [], []

        if db_batch: self._save_to_db(db_batch)
        if ml_buffer and self.detector.is_trained:
            preds = self.detector.predict_batch(ml_buffer)
            stats['anomalies'].extend([ev_buffer[i] for i, p in enumerate(preds) if p])

        return stats

def build_reports(stats, mode):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lvl8plus = sum(v for k, v in stats['levels'].items() if k >= 8)
    anom_sorted = sorted(stats['anomalies'], key=lambda x: x['rule_level'], reverse=True)
    anom_hashes = {hashlib.md5(f"{a['timestamp']}{a['rule_id']}{a['user']}".encode()).hexdigest() for a in stats['anomalies']}

    # Messenger Report (VK & Telegram)
    msg = [f"🛡️ SOC AI: {mode.upper()} Report\n", 
          f"📊 Events: {stats['total']:,}", 
          f"🚨 High-level (8+): {lvl8plus:,}", 
          f"🔗 Clusters: {len(stats['clusters']):,}", 
          f"⚠️ ML Anomalies: {len(stats['anomalies']):,}\n"]
    
    msg.append("🔓 Top Failed Users:")
    for u, c in stats['users_failed'].most_common(5):
        if u != 'unknown': msg.append(f" • {u}: {c}")
    
    msg.append("\n🌐 Top Failed IPs:")
    for ip, c in stats['sources_failed'].most_common(5):
        if ip != 'unknown': msg.append(f" • {ip}: {c}")

    msg.append("\n🔑 Rare User - IP Access:")
    seen_classic = set()
    for a in anom_sorted:
        if a['user'] != 'unknown' and a['src_ip'] != 'unknown':
            pair = f"{a['user']} ➔ {a['src_ip']}"
            if pair not in seen_classic:
                seen_classic.add(pair); msg.append(f" • {pair}")
        if len(seen_classic) >= 5: break

    msg.append("\n🛠️ UEBA: Unusual Activity:")
    seen_act = set()
    for a in anom_sorted:
        if a['user'] != 'unknown':
            key = f"{a['user']}@{a['rule_id']}"
            if key not in seen_act:
                seen_act.add(key); msg.append(f" • {a['user']}: {a['rule_description'][:80]}...")
        if len(seen_act) >= 5: break

    msg.append("\n🌙 UEBA: Off-hours Activity:")
    seen_off = set()
    for e in stats['night_events']:
        if e['user'] not in seen_off and e['user'] != 'unknown':
            h = hashlib.md5(f"{e['timestamp']}{e['rule_id']}{e['user']}".encode()).hexdigest()
            mark = "⚠️ " if h in anom_hashes else ""
            dt = datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
            msg.append(f" • {mark}{e['user']} ({dt.hour}:00 UTC)")
            seen_off.add(e['user'])
        if len(seen_off) >= 5: break

    # Email Report
    mail = [f"🛡️ {mode.upper()} SECURITY REPORT", "="*60, f"📅 Date: {now} UTC", f"📊 Total events: {stats['total']:,}", "📈 Threat level distribution:"]
    for l in sorted(stats['levels'].keys()): mail.append(f"• Level {l}: {stats['levels'][l]:,} events")
    
    mail.append(f"\n🚨 High-level events (level >= 8): {lvl8plus}")
    mail.append(f"🔐 Failed login attempts: {stats['failed_logins']}")
    
    mail.append("\n🔓 Top 5 users with failed authentications:")
    added_u_f = 0
    for u, c in stats['users_failed'].most_common(10):
        if u == 'unknown': continue
        mail.append(f"• {u}: {c} failed attempts")
        added_u_f += 1
        if added_u_f >= 5: break

    mail.append("\n🌐 Top 5 sources of failed authentications:")
    added_ip_f = 0
    for ip, c in stats['sources_failed'].most_common(10):
        if ip == 'unknown': continue
        mail.append(f"• {ip}: {c} failed attempts")
        added_ip_f += 1
        if added_ip_f >= 5: break

    mail.append("\n🌐 Top-10 IP addresses by activity:")
    added_ip = 0
    for ip, count in stats['all_sources'].most_common(20):
        if ip == 'unknown': continue
        f_auth = stats['sources_failed'].get(ip, 0)
        mail.append(f"• {ip}: {count} events ({f_auth} failed auth)")
        added_ip += 1
        if added_ip >= 10: break

    mail.append("\n👤 Top-10 users by activity:")
    added_u = 0
    for u, count in stats['all_users'].most_common(20):
        if u == 'unknown': continue
        f_auth = stats['users_failed'].get(u, 0)
        mail.append(f"• {u}: {count} events ({f_auth} failed auth)")
        added_u += 1
        if added_u >= 10: break

    mail.append("\n🤖 ML BEHAVIORAL ANOMALIES & UEBA FINDINGS\n" + "-"*60)
    mail.append("🔑 Rare Access Patterns (User ➔ IP):")
    seen_m_classic = set()
    for a in anom_sorted:
        if a['user'] != 'unknown' and a['src_ip'] != 'unknown':
            pair = f"{a['user']} ➔ {a['src_ip']}"
            if pair not in seen_m_classic:
                seen_m_classic.add(pair); mail.append(f" • {pair}")
        if len(seen_m_classic) >= 5: break

    mail.append("\n🌙 Off-hours Activity Detected (Level 5+):")
    seen_m_off = set()
    for e in stats['night_events']:
        if e['user'] not in seen_m_off and e['user'] != 'unknown':
            h = hashlib.md5(f"{e['timestamp']}{e['rule_id']}{e['user']}".encode()).hexdigest()
            mark = "[ANOMALY] " if h in anom_hashes else ""
            dt = datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
            mail.append(f" • {mark}{e['user']} at {dt.hour}:00 (Rule: {e['rule_id']})")
            seen_m_off.add(e['user'])
        if len(seen_m_off) >= 5: break

    mail.append("\n🛠️ Detailed Anomaly List (Top 15):")
    for a in anom_sorted[:15]:
        if a['user'] != 'unknown':
            mail.append(f"• [{a['timestamp']}] User: {a['user']} | IP: {a['src_ip']} | {a['rule_description']} (Lvl {a['rule_level']})")

    mail.append("\n🚨 EVENT CORRELATION & CLUSTERS\n" + "-"*60)
    for i, (d, c) in enumerate(stats['clusters'].most_common(10)):
        mail.append(f"🔸 CLUSTER #{i} - {c} occurrences\n• {d}")

    return "\n".join(msg), "\n".join(mail)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True)
    parser.add_argument('--mode', default='global')
    parser.add_argument('--send-alerts', action='store_true')
    parser.add_argument('--train-ml', action='store_true')
    parser.add_argument('--train-limit', type=int, default=200000)
    args = parser.parse_args()

    analyzer = SOCAnalyzer()

    if args.train_ml and DB_PATH.exists():
        try:
            print(f"🚀 Training ML model with limit: {args.train_limit}...")
            with sqlite3.connect(str(DB_PATH), timeout=SQL_TIMEOUT) as conn:
                rows = conn.execute(f"SELECT timestamp, rule_level, user, src_ip, agent, rule_id FROM events ORDER BY id DESC LIMIT {args.train_limit}").fetchall()
            if len(rows) > 1000:
                u_counts = Counter([r[2] for r in rows])
                all_agents = sorted(list(set([r[4] for r in rows])))
                a_map = {name: i for i, name in enumerate(all_agents)}
                X = []
                for r in rows:
                    try:
                        dt = datetime.fromisoformat(r[0].replace('Z','+00:00'))
                        ip_f = analyzer.detector.ip_to_features(r[3])
                        X.append([dt.hour, r[1], u_counts[r[2]], a_map.get(r[4], 0), int(r[5]) if str(r[5]).isdigit() else 0] + ip_f)
                    except: continue
                X_np = np.array(X)
                scaler = StandardScaler().fit(X_np)
                X_s = scaler.transform(X_np)
                model = IsolationForest(contamination=0.005, n_estimators=300).fit(X_s)
                with open(ML_MODEL_PATH, 'wb') as f:
                    pickle.dump({'model': model, 'scaler': scaler, 'user_freq': dict(u_counts), 'agent_map': a_map}, f)
                print("✅ Model trained successfully.")
        except Exception as e: print(f"❌ Training Error: {e}")

    stats = analyzer.process_file(args.file)
    msg_rep, mail_rep = build_reports(stats, args.mode)
    print(mail_rep)
    
    if args.send_alerts:
        for rec in EMAIL_RECIPIENTS:
            try:
                msg = EmailMessage(); msg.set_content(mail_rep)
                msg['Subject'] = f"🛡️ SOC AI: {args.mode.upper()} Alert"
                msg['From'] = EMAIL_FROM; msg['To'] = rec
                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
                    s.starttls(); s.login(EMAIL_FROM, EMAIL_PASSWORD); s.send_message(msg)
            except: pass
        send_to_vk_teams(msg_rep)
        send_to_telegram(msg_rep)

if __name__ == "__main__":
    main()
