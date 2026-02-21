from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
from datetime import datetime
import random
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import sqlite3

app = Flask(__name__)
CORS(app)

class InsiderThreatDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        self.init_database()

    def init_database(self):
        """Initialize SQLite database for storing activity logs and alerts"""
        conn = sqlite3.connect('insider_threat.db', check_same_thread=False)
        cursor = conn.cursor()

        # Create activity logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                timestamp DATETIME,
                action_type TEXT,
                resource_accessed TEXT,
                file_size INTEGER,
                login_location TEXT,
                session_duration INTEGER,
                risk_score REAL
            )
        ''')

        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                timestamp DATETIME,
                risk_score REAL,
                status TEXT DEFAULT 'ACTIVE'
            )
        ''')

        conn.commit()
        conn.close()

    def extract_features(self, activity):
        """Extract behavioral features from user activity"""
        features = [
            activity.get('login_hour', 9),
            activity.get('file_access_count', 0),
            activity.get('data_transfer_mb', 0),
            activity.get('session_duration', 60),
            activity.get('unusual_location', 0),
            activity.get('after_hours', 0),
            activity.get('weekend_access', 0),
            activity.get('privilege_escalation', 0),
        ]
        return np.array(features).reshape(1, -1)

    def train_baseline(self, historical_data):
        if not historical_data:
            return False

        features_list = [self.extract_features(activity).flatten() for activity in historical_data]

        if len(features_list) < 10:
            return False

        X = np.array(features_list)
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector.fit(X_scaled)
        self.is_trained = True
        return True

    def calculate_risk_score(self, activity):
        if not self.is_trained:
            return 0.5  # neutral risk score

        features = self.extract_features(activity)
        features_scaled = self.scaler.transform(features)

        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        risk_score = max(0, min(1, (1 - anomaly_score) / 2))

        # Apply risk multipliers where applicable
        risk_multipliers = {
            'after_hours': 1.3,
            'unusual_location': 1.4,
            'privilege_escalation': 1.8,
            'large_data_transfer': 1.5 if activity.get('data_transfer_mb', 0) > 100 else 1.0
        }

        for factor, multiplier in risk_multipliers.items():
            if factor == 'large_data_transfer' and multiplier > 1.0:
                risk_score *= multiplier
            elif activity.get(factor, 0) == 1:
                risk_score *= multiplier

        return min(1.0, risk_score)

    def classify_threat_level(self, risk_score):
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_alert(self, user_id, activity, risk_score):
        if risk_score < 0.4:
            return None

        threat_level = self.classify_threat_level(risk_score)
        alert_descriptions = {
            "CRITICAL": f"Critical insider threat detected: {user_id} exhibiting highly anomalous behavior",
            "HIGH": f"High-risk activity detected: {user_id} deviating significantly from baseline",
            "MEDIUM": f"Suspicious activity detected: {user_id} showing moderate anomalies"
        }

        alert = {
            'user_id': user_id,
            'alert_type': 'BEHAVIORAL_ANOMALY',
            'severity': threat_level,
            'description': alert_descriptions.get(threat_level, f"Anomalous behavior for {user_id}"),
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'details': activity
        }

        # Save alert to DB
        conn = sqlite3.connect('insider_threat.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (user_id, alert_type, severity, description, timestamp, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (alert['user_id'], alert['alert_type'], alert['severity'],
              alert['description'], alert['timestamp'], alert['risk_score']))
        conn.commit()
        conn.close()

        return alert

detector = InsiderThreatDetector()

def generate_synthetic_training_data():
    training_data = []
    users = ['john.doe', 'jane.smith', 'bob.wilson', 'alice.brown', 'charlie.davis']
    for user in users:
        for day in range(30):
            for _ in range(random.randint(5, 15)):
                activity = {
                    'user_id': user,
                    'login_hour': random.randint(8, 18),
                    'file_access_count': random.randint(5, 25),
                    'data_transfer_mb': random.randint(1, 50),
                    'session_duration': random.randint(30, 240),
                    'unusual_location': 0,
                    'after_hours': 0,
                    'weekend_access': 0,
                    'privilege_escalation': 0
                }
                training_data.append(activity)
    return training_data

# Train with synthetic data at startup
training_data = generate_synthetic_training_data()
detector.train_baseline(training_data)


@app.route('/activity', methods=['POST'])
def log_activity():
    try:
        activity = request.json
        user_id = activity.get('user_id')

        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        risk_score = detector.calculate_risk_score(activity)
        activity['risk_score'] = risk_score

        conn = sqlite3.connect('insider_threat.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activity_logs (user_id, timestamp, action_type, resource_accessed,
                                     file_size, login_location, session_duration, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, datetime.now(), activity.get('action_type'),
              activity.get('resource_accessed'), activity.get('file_size', 0),
              activity.get('login_location'), activity.get('session_duration', 0), risk_score))
        conn.commit()
        conn.close()

        alert = detector.generate_alert(user_id, activity, risk_score)

        response = {
            'status': 'success',
            'risk_score': risk_score,
            'threat_level': detector.classify_threat_level(risk_score)
        }

        if alert:
            response['alert'] = alert

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        limit = request.args.get('limit', 50, type=int)

        conn = sqlite3.connect('insider_threat.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, user_id, alert_type, severity, description, timestamp, risk_score, status
            FROM alerts ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()

        alerts = []
        for row in rows:
            alerts.append({
                'id': row[0],
                'user_id': row[1],
                'alert_type': row[2],
                'severity': row[3],
                'description': row[4],
                'timestamp': row[5],
                'risk_score': row[6],
                'status': row[7]
            })

        return jsonify(alerts)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    try:
        conn = sqlite3.connect('insider_threat.db')
        cursor = conn.cursor()

        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        alert_counts = dict(cursor.fetchall())

        cursor.execute('''
            SELECT user_id, AVG(risk_score) as avg_risk, COUNT(*) as activity_count
            FROM activity_logs 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY user_id
            ORDER BY avg_risk DESC
            LIMIT 10
        ''')
        risky_users = []
        for row in cursor.fetchall():
            risky_users.append({
                'user_id': row[0],
                'avg_risk_score': round(row[1], 3),
                'activity_count': row[2]
            })

        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM activity_logs 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''')
        hourly_activity = [{'hour': int(row[0]), 'count': row[1]} for row in cursor.fetchall()]

        conn.close()

        dashboard_data = {
            'alert_summary': {
                'CRITICAL': alert_counts.get('CRITICAL', 0),
                'HIGH': alert_counts.get('HIGH', 0),
                'MEDIUM': alert_counts.get('MEDIUM', 0),
                'LOW': alert_counts.get('LOW', 0)
            },
            'risky_users': risky_users,
            'hourly_activity': hourly_activity,
            'total_alerts_24h': sum(alert_counts.values()) if alert_counts else 0,
            'system_status': 'ACTIVE'
        }

        return jsonify(dashboard_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/simulate', methods=['POST'])
def simulate_activity():
    try:
        scenario = request.json.get('scenario', 'normal')
        user_id = request.json.get('user_id', 'demo.user')

        scenarios = {
            'normal': {
                'login_hour': random.randint(8, 18),
                'file_access_count': random.randint(5, 25),
                'data_transfer_mb': random.randint(1, 50),
                'session_duration': random.randint(30, 240),
                'unusual_location': 0,
                'after_hours': 0,
                'weekend_access': 0,
                'privilege_escalation': 0
            },
            'data_exfiltration': {
                'login_hour': random.choice(list(range(22, 24)) + list(range(0, 7))),
                'file_access_count': random.randint(50, 200),
                'data_transfer_mb': random.randint(500, 2000),
                'session_duration': random.randint(180, 400),
                'unusual_location': 1,
                'after_hours': 1,
                'weekend_access': 1,
                'privilege_escalation': 1
            },
            'insider_sabotage': {
                'login_hour': random.choice(list(range(20, 24)) + list(range(0, 5))),
                'file_access_count': random.randint(30, 100),
                'data_transfer_mb': random.randint(10, 100),
                'session_duration': random.randint(60, 180),
                'unusual_location': 0,
                'after_hours': 1,
                'weekend_access': 1,
                'privilege_escalation': 1
            },
            'credential_misuse': {
                'login_hour': random.randint(0, 23),
                'file_access_count': random.randint(40, 150),
                'data_transfer_mb': random.randint(100, 500),
                'session_duration': random.randint(30, 120),
                'unusual_location': 1,
                'after_hours': random.choice([0, 1]),
                'weekend_access': 0,
                'privilege_escalation': 1
            }
        }

        if scenario not in scenarios:
            return jsonify({'error': 'Invalid scenario'}), 400

        activity = scenarios[scenario]
        activity['user_id'] = user_id
        activity['action_type'] = f'SIMULATED_{scenario.upper()}'
        activity['resource_accessed'] = f'/secure/documents/{random.randint(1000, 9999)}'

        risk_score = detector.calculate_risk_score(activity)
        alert = detector.generate_alert(user_id, activity, risk_score)

        conn = sqlite3.connect('insider_threat.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activity_logs (user_id, timestamp, action_type, resource_accessed,
                                     file_size, login_location, session_duration, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, datetime.now(), activity['action_type'],
              activity['resource_accessed'], activity.get('file_size', 0),
              'Simulated Location', activity.get('session_duration', 0), risk_score))
        conn.commit()
        conn.close()

        response = {
            'status': 'success',
            'scenario': scenario,
            'risk_score': risk_score,
            'threat_level': detector.classify_threat_level(risk_score),
            'activity': activity
        }

        if alert:
            response['alert'] = alert

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("🚀 AI Insider Threat Detection System Starting...")
    print("🔒 Security monitoring active")
    print("🤖 Machine Learning models loaded")
    print("📊 Dashboard available at frontend")
    app.run(debug=True, port=5000)
