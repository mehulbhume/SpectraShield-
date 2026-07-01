# ============================================================================================
# FEATURE NAME : Behavioral Heuristics
# FEATURE ID : 29
# INTERN ID : 2128
# ============================================================================================
import psutil

# Safe imports in case the libraries aren't installed yet
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Global state to store behavioral baseline data across scheduled runs
_BEHAVIORAL_HISTORY = []

def run(send_event):
    """
    This function runs automatically every X minutes.
    send_event() is given to you — just call it with your data.
    """
    # == STEP 1: Collect your data ============================================================
    try:
        # Collect current behavioral metrics
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_usage = psutil.virtual_memory().percent
        process_count = len(psutil.pids())
        
        # Cross-platform way to get network connections without root/admin crashes
        try:
            net_connections = len(psutil.net_connections())
        except psutil.AccessDenied:
            net_connections = 0
        
        current_metrics = [cpu_usage, ram_usage, process_count, net_connections]
        _BEHAVIORAL_HISTORY.append(current_metrics)
        
        # Keep history bounded to avoid memory leaks (e.g., store the last 100 observations)
        if len(_BEHAVIORAL_HISTORY) > 100:
            _BEHAVIORAL_HISTORY.pop(0)
            
        is_anomaly = False
        anomaly_score = 0.0
        
        # Train and Predict with Isolation Forest (if we have enough data)
        # We wait until we have 10 data points before making predictions
        if ML_AVAILABLE and len(_BEHAVIORAL_HISTORY) >= 10:
            # Train the model on our historical baseline
            clf = IsolationForest(contamination=0.05, random_state=42)
            X = np.array(_BEHAVIORAL_HISTORY)
            clf.fit(X)
            
            # Predict the current state (1 = Normal/Inlier, -1 = Anomaly/Outlier)
            current_X = np.array([current_metrics])
            prediction = clf.predict(current_X)[0]
            
            # Get the raw anomaly score (lower numbers indicate more abnormal behavior)
            anomaly_score = float(clf.score_samples(current_X)[0])
            
            if prediction == -1:
                is_anomaly = True

        data = {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "process_count": process_count,
            "net_connections": net_connections,
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "history_size": len(_BEHAVIORAL_HISTORY),
            "ml_active": ML_AVAILABLE
        }
        
        # Severity Condition: High if the Isolation Forest detects an anomaly
        severity = "high" if is_anomaly else "info"

        # == STEP 2: Send it to the backend ======================================================
        send_event(
            event_type="behavioral_heuristics",
            feature_id=29,
            data_dict=data,
            severity=severity
        )
        
    except Exception as e:
        # Golden Rule #2: Always wrap OS calls in try/except. Never crash the main agent.
        pass
