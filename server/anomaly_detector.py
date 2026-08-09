# server/anomaly_detector.py
import os
import json
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import time

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

def get_model_path(host_id):
    return os.path.join(MODEL_DIR, f"{host_id}_model.pkl")

def extract_features(payload):
    """Extract numeric features from telemetry payload for anomaly detection."""
    try:
        features = {
            'cpu': float(payload.get('cpu', 0)),
            'ram_percent': float(payload.get('ram', {}).get('percent', 0)),
            'disk_percent': float(payload.get('disk', {}).get('percent', 0)),
            'num_processes': len(payload.get('processes', [])),
            'num_connections': len(payload.get('net', [])),
            'num_open_ports': len(payload.get('open_ports', [])),
            'num_active_conns': len(payload.get('active_conns', [])),
            'num_strange_ips': len(payload.get('strange_ips', [])),
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def features_to_array(features):
    """Convert feature dict to numpy array for model."""
    if not features:
        return None
    return np.array([
        features['cpu'],
        features['ram_percent'],
        features['disk_percent'],
        features['num_processes'],
        features['num_connections'],
        features['num_open_ports'],
        features['num_active_conns'],
        features['num_strange_ips']
    ]).reshape(1, -1)

def train_or_update_model(host_id, db_path):
    """Train or update anomaly detection model for a host."""
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Get recent non-flagged data for this host (last 200 records)
        cur.execute("""
            SELECT data FROM telemetry 
            WHERE host_id = ? AND flagged = 0
            ORDER BY ts DESC LIMIT 200
        """, (host_id,))
        
        rows = cur.fetchall()
        con.close()
        
        if len(rows) < 20:  # Need minimum data to train
            return None
        
        # Extract features from all records
        X = []
        for row in rows:
            try:
                data = json.loads(row[0])
                features = extract_features(data)
                if features:
                    X.append(list(features.values()))
            except Exception:
                pass
        
        if len(X) < 20:
            return None
        
        X = np.array(X)
        
        # Train Isolation Forest model
        model = IsolationForest(
            contamination=0.1,  # Assume 10% of data might be anomalies
            random_state=42,
            n_estimators=100
        )
        model.fit(X)
        
        # Save model
        model_path = get_model_path(host_id)
        joblib.dump(model, model_path)
        
        return model
    except Exception as e:
        print(f"Error training model for {host_id}: {e}")
        return None

def load_model(host_id):
    """Load pre-trained model for a host."""
    model_path = get_model_path(host_id)
    if os.path.exists(model_path):
        try:
            return joblib.load(model_path)
        except Exception as e:
            print(f"Error loading model for {host_id}: {e}")
    return None

def detect_anomaly(host_id, payload, db_path):
    """Detect if current telemetry is anomalous."""
    features = extract_features(payload)
    if not features:
        return False, []
    
    X = features_to_array(features)
    if X is None:
        return False, []
    
    # Try to load existing model
    model = load_model(host_id)
    
    # If no model exists or we have enough new data, retrain
    if model is None:
        model = train_or_update_model(host_id, db_path)
    
    if model is None:
        return False, []
    
    # Predict: -1 = anomaly, 1 = normal
    prediction = model.predict(X)[0]
    is_anomaly = prediction == -1
    
    # Get anomaly score (negative values = anomalies)
    score = model.score_samples(X)[0]
    
    reasons = []
    if is_anomaly:
        reasons.append(f"Anomaly detected (score: {score:.3f})")
        
        # Check individual feature extremes
        if features['cpu'] > 80:
            reasons.append(f"Unusual CPU spike: {features['cpu']}%")
        if features['ram_percent'] > 85:
            reasons.append(f"Unusual RAM usage: {features['ram_percent']}%")
        if features['num_processes'] > 150:
            reasons.append(f"Unusual process count: {features['num_processes']}")
        if features['num_strange_ips'] > 5:
            reasons.append(f"Multiple strange IP connections: {features['num_strange_ips']}")
    
    return is_anomaly, reasons

def retrain_all_models(db_path):
    """Retrain models for all hosts periodically."""
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT DISTINCT host_id FROM telemetry")
        hosts = [row[0] for row in cur.fetchall()]
        con.close()
        
        for host_id in hosts:
            train_or_update_model(host_id, db_path)
    except Exception as e:
        print(f"Error retraining models: {e}")
