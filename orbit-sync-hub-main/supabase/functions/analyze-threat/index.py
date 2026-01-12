import json
import pickle
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path

# Define the model architecture (must match training)
class CyberAttackDetector(nn.Module):
    def __init__(self, input_size):
        super(CyberAttackDetector, self).__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.bn1 = nn.BatchNorm1d(128)
        self.dropout1 = nn.Dropout(0.3)
        self.fc2 = nn.Linear(128, 64)
        self.bn2 = nn.BatchNorm1d(64)
        self.dropout2 = nn.Dropout(0.3)
        self.fc3 = nn.Linear(64, 32)
        self.bn3 = nn.BatchNorm1d(32)
        self.dropout3 = nn.Dropout(0.3)
        self.fc4 = nn.Linear(32, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        x = self.relu(self.bn1(self.fc1(x)))
        x = self.dropout1(x)
        x = self.relu(self.bn2(self.fc2(x)))
        x = self.dropout2(x)
        x = self.relu(self.bn3(self.fc3(x)))
        x = self.dropout3(x)
        x = self.sigmoid(self.fc4(x))
        return x

# Load model and preprocessing artifacts
base_path = Path(__file__).parent

with open(base_path / 'columns.pkl', 'rb') as f:
    feature_columns = pickle.load(f)

with open(base_path / 'scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

model = CyberAttackDetector(input_size=len(feature_columns))
model.load_state_dict(torch.load(base_path / 'cyber_model.pth', map_location=torch.device('cpu')))
model.eval()

def extract_features_from_log(log_entry):
    """Convert log entry to numeric features"""
    # Event type encoding
    event_types = {
        'BruteForce': 5, 'Malware': 10, 'DataLeak': 8, 
        'PortScan': 4, 'UnauthorizedAccess': 7, 'Normal': 0
    }
    
    # Severity encoding
    severity_levels = {
        'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 0
    }
    
    features = {}
    
    # Extract numeric features from log entry
    if isinstance(log_entry, dict):
        # Get event type score
        event_type = log_entry.get('event_type', 'Normal')
        features['event_severity'] = event_types.get(event_type, 0)
        
        # Get severity level
        severity = log_entry.get('severity_status', 'Info')
        features['severity_level'] = severity_levels.get(severity, 0)
        
        # IP-based features (simple heuristics)
        src_ip = log_entry.get('source_ip', '0.0.0.0')
        dst_ip = log_entry.get('destination_ip', '0.0.0.0')
        
        # Check if IPs are internal or external
        features['src_external'] = 0 if src_ip.startswith(('192.168.', '10.', '172.')) else 1
        features['dst_internal'] = 1 if dst_ip.startswith(('192.168.', '10.', '172.')) else 0
        
        # Threat indicators from details
        details = str(log_entry.get('details', '')).lower()
        features['has_failed_login'] = 1 if 'failed' in details or 'login' in details else 0
        features['has_malware'] = 1 if 'malware' in details or 'trojan' in details or 'virus' in details else 0
        features['has_data_leak'] = 1 if 'data' in details or 'leak' in details or 'outbound' in details else 0
        features['has_scan'] = 1 if 'scan' in details or 'port' in details else 0
        features['has_unauthorized'] = 1 if 'unauthorized' in details or 'restricted' in details else 0
    
    return features

def parse_log_data(log_content):
    """Parse log file content and extract features"""
    try:
        lines = log_content.strip().split('\n')
        records = []
        
        # Skip header if present
        start_idx = 1 if lines and 'timestamp' in lines[0].lower() else 0
        
        for i, line in enumerate(lines[start_idx:], start=start_idx):
            if not line.strip():
                continue
                
            try:
                # Try JSON first
                record = json.loads(line)
                features = extract_features_from_log(record)
                records.append({'raw': record, 'features': features})
            except json.JSONDecodeError:
                # Parse CSV format
                parts = line.split(',')
                if len(parts) >= 5:
                    log_entry = {
                        'timestamp': parts[0].strip(),
                        'source_ip': parts[1].strip(),
                        'destination_ip': parts[2].strip(),
                        'event_type': parts[3].strip(),
                        'severity_status': parts[4].strip(),
                        'details': ','.join(parts[5:]).strip() if len(parts) > 5 else ''
                    }
                    features = extract_features_from_log(log_entry)
                    records.append({'raw': log_entry, 'features': features})
        
        return records
    except Exception as e:
        print(f"Error parsing log data: {e}")
        import traceback
        traceback.print_exc()
        return []

def predict_threat(record):
    """Run inference on a single record"""
    try:
        features_dict = record.get('features', {})
        raw_data = record.get('raw', {})
        
        # Calculate rule-based threat score
        rule_score = 0
        threat_indicators = []
        
        # Check extracted features
        if features_dict.get('event_severity', 0) >= 5:
            rule_score += 0.3
            threat_indicators.append(f"High-risk event: {raw_data.get('event_type', 'Unknown')}")
        
        if features_dict.get('severity_level', 0) >= 7:
            rule_score += 0.3
            threat_indicators.append(f"High severity: {raw_data.get('severity_status', 'Unknown')}")
        
        if features_dict.get('has_malware', 0) == 1:
            rule_score += 0.4
            threat_indicators.append("Malware detected in details")
        
        if features_dict.get('has_data_leak', 0) == 1:
            rule_score += 0.3
            threat_indicators.append("Data leak indicators")
        
        if features_dict.get('has_failed_login', 0) == 1:
            rule_score += 0.2
            threat_indicators.append("Failed login attempts")
        
        if features_dict.get('has_scan', 0) == 1:
            rule_score += 0.2
            threat_indicators.append("Port scanning activity")
        
        if features_dict.get('has_unauthorized', 0) == 1:
            rule_score += 0.3
            threat_indicators.append("Unauthorized access attempt")
        
        # Cap at 1.0
        threat_score = min(rule_score, 1.0)
        
        return {
            'is_threat': threat_score > 0.5,
            'threat_score': threat_score,
            'confidence': min(threat_score * 1.5, 1.0) if threat_score > 0.5 else (1.0 - threat_score),
            'indicators': threat_indicators
        }
    except Exception as e:
        print(f"Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return None

def handler(req):
    try:
        print("Threat analysis function called")
        
        # Parse request
        body = req.json()
        log_content = body.get('log_content', '')
        file_type = body.get('file_type', 'log')
        
        print(f"Received {len(log_content)} bytes of log content")
        
        if not log_content:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No log content provided'})
            }
        
        # Parse log records
        records = parse_log_data(log_content)
        
        print(f"Parsed {len(records)} records")
        
        if not records:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Could not parse log data. Expected CSV format with: timestamp,source_ip,destination_ip,event_type,severity_status,details'})
            }
        
        # Analyze each record
        results = []
        threat_details = []
        threat_count = 0
        total_threat_score = 0
        
        for idx, record in enumerate(records):
            prediction = predict_threat(record)
            if prediction:
                raw_data = record.get('raw', {})
                
                result_entry = {
                    'record_index': idx + 1,
                    'is_threat': prediction['is_threat'],
                    'threat_score': round(prediction['threat_score'], 4),
                    'confidence': round(prediction['confidence'] * 100, 2)
                }
                
                results.append(result_entry)
                
                if prediction['is_threat']:
                    threat_count += 1
                    # Add detailed threat information
                    threat_details.append({
                        'record_number': idx + 1,
                        'threat_score': round(prediction['threat_score'] * 100, 2),
                        'confidence': round(prediction['confidence'] * 100, 2),
                        'threat_type': raw_data.get('event_type', 'Unknown'),
                        'severity': raw_data.get('severity_status', 'Unknown'),
                        'source_ip': raw_data.get('source_ip', 'Unknown'),
                        'indicators': prediction.get('indicators', []),
                        'flagged_values': record.get('features', {}),
                        'sample_data': {
                            'timestamp': raw_data.get('timestamp', ''),
                            'event': raw_data.get('event_type', ''),
                            'severity': raw_data.get('severity_status', ''),
                            'details': raw_data.get('details', '')[:100]
                        }
                    })
                
                total_threat_score += prediction['threat_score']
        
        # Calculate overall statistics
        avg_threat_score = total_threat_score / len(results) if results else 0
        
        response = {
            'threat_status': 'threat' if threat_count > 0 else 'safe',
            'threat_score': round(avg_threat_score, 4),
            'total_records': len(results),
            'threat_count': threat_count,
            'safe_count': len(results) - threat_count,
            'average_confidence': round(sum(r['confidence'] for r in results) / len(results), 2) if results else 0,
            'threat_details': threat_details[:10],  # Return first 10 threats
            'summary': results[:20]  # Return first 20 for overview
        }
        
        return {
            'statusCode': 200,
            'body': json.dumps(response)
        }
        
    except Exception as e:
        print(f"Error in handler: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
