from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
import os
import sys
import json
from datetime import datetime

# Add the parent directory to the path to import CLI tool functions
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

app = Flask(__name__)

# Load the trained model and label encoder
MODEL_PATH = "../vulnerability_classifier_model_enhanced.joblib"

try:
    model_data = joblib.load(MODEL_PATH)
    model = model_data["model"]
    label_encoder = model_data["label_encoder"]
    feature_names = model_data["feature_names"]
    print("Model and label encoder loaded successfully for dashboard.")
except Exception as e:
    print(f"Warning: Error loading model components: {e}. Dashboard will work with limited functionality.")
    model = None
    label_encoder = None
    feature_names = None


def predict_severity_simple(description, cwe_ids):
    """Simple severity prediction based on keywords and CWE patterns"""
    description_lower = description.lower() if description else ""
    cwe_list = cwe_ids.split(",") if cwe_ids else []

    # Simple rule-based prediction
    critical_keywords = ["sql injection", "buffer overflow", "remote code execution", "privilege escalation"]
    high_keywords = ["xss", "cross-site scripting", "authentication bypass", "directory traversal"]
    medium_keywords = ["information disclosure", "weak cryptography", "insecure storage"]

    critical_cwes = ["CWE-89", "CWE-120", "CWE-787", "CWE-94"]
    high_cwes = ["CWE-79", "CWE-22", "CWE-306", "CWE-639"]

    # Check for critical indicators
    if any(keyword in description_lower for keyword in critical_keywords) or any(
            cwe in cwe_list for cwe in critical_cwes):
        return "Critical"
    elif any(keyword in description_lower for keyword in high_keywords) or any(cwe in cwe_list for cwe in high_cwes):
        return "High"
    elif any(keyword in description_lower for keyword in medium_keywords):
        return "Medium"
    else:
        return "Low"


def predict_severity_with_model(description, cwe_ids):
    """Predict severity using the trained ML model"""
    if model is None or label_encoder is None or feature_names is None:
        return predict_severity_simple(description, cwe_ids)

    try:
        # Create a DataFrame with the input data
        input_data = pd.DataFrame({
            'description': [description],
            'cwe_id': [cwe_ids]
        })

        # Apply the same feature engineering as during training
        # Note: This is a simplified version - you may need to adjust based on your actual feature engineering
        input_features = pd.DataFrame(0, index=[0], columns=feature_names)

        # Basic feature extraction (you may need to enhance this based on your training pipeline)
        if description:
            # Simple keyword-based features
            input_features.loc[0, 'description_length'] = len(description)
            input_features.loc[0, 'has_sql'] = 1 if 'sql' in description.lower() else 0
            input_features.loc[0, 'has_xss'] = 1 if 'xss' in description.lower() else 0
            input_features.loc[0, 'has_buffer'] = 1 if 'buffer' in description.lower() else 0

        if cwe_ids:
            cwe_list = [cwe.strip() for cwe in cwe_ids.split(',')]
            input_features.loc[0, 'cwe_count'] = len(cwe_list)
            # Add specific CWE features if they exist in the model
            for cwe in cwe_list:
                cwe_feature = f'cwe_{cwe.replace("-", "_")}'
                if cwe_feature in feature_names:
                    input_features.loc[0, cwe_feature] = 1

        # Make prediction
        prediction = model.predict(input_features)[0]
        severity = label_encoder.inverse_transform([prediction])[0]

        return severity

    except Exception as e:
        print(f"Error using ML model: {e}. Falling back to simple prediction.")
        return predict_severity_simple(description, cwe_ids)


def provide_recommendations(severity):
    """Provide recommendations based on severity"""
    recommendations = {
        "Critical": [
            "Immediate action required - patch within 24 hours",
            "Implement emergency security controls",
            "Consider taking affected systems offline if necessary",
            "Notify security team and stakeholders immediately",
            "Conduct thorough impact assessment"
        ],
        "High": [
            "Prioritize patching and apply updates within 24-48 hours",
            "Implement compensating controls if immediate patching is not possible",
            "Review access controls and network segmentation",
            "Monitor affected systems closely",
            "Document remediation steps"
        ],
        "Medium": [
            "Schedule patching within 1-2 weeks",
            "Review and update security configurations",
            "Consider implementing additional monitoring",
            "Assess potential impact on business operations",
            "Plan remediation during maintenance windows"
        ],
        "Low": [
            "Include in regular patching cycle (within 30 days)",
            "Review security best practices",
            "Consider as part of routine security updates",
            "Document for future reference",
            "Monitor for any changes in threat landscape"
        ]
    }

    return recommendations.get(severity, ["No specific recommendations available for this severity."])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/vulnerability/assess', methods=['POST'])
def assess_vulnerability():
    """Assess a single vulnerability"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        description = data.get('description', '').strip()
        cwe_ids = data.get('cwe_ids', '').strip()

        if not description and not cwe_ids:
            return jsonify({"error": "Please provide at least a description or CWE IDs"}), 400

        # Predict severity using ML model (with fallback to simple rules)
        predicted_severity = predict_severity_with_model(description, cwe_ids)

        # Get recommendations
        recommendations = provide_recommendations(predicted_severity)

        return jsonify({
            "severity": predicted_severity,
            "recommendations": recommendations,
            "description": description,
            "cwe_ids": cwe_ids
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/vulnerability/sample', methods=['GET'])
def get_sample_data():
    """Get sample vulnerability data for demonstration"""
    sample_vulnerabilities = [
        {
            "description": "SQL Injection vulnerability in user authentication module",
            "cwe_ids": "CWE-89,CWE-200",
            "severity": "Critical"
        },
        {
            "description": "Cross-site scripting (XSS) in user input validation",
            "cwe_ids": "CWE-79",
            "severity": "High"
        },
        {
            "description": "Buffer overflow in network packet processing",
            "cwe_ids": "CWE-120,CWE-787",
            "severity": "Critical"
        },
        {
            "description": "Insecure direct object reference in file access",
            "cwe_ids": "CWE-22,CWE-639",
            "severity": "High"
        },
        {
            "description": "Weak cryptographic algorithm in password storage",
            "cwe_ids": "CWE-327,CWE-916",
            "severity": "Medium"
        },
        {
            "description": "Missing authentication in administrative interface",
            "cwe_ids": "CWE-306",
            "severity": "High"
        },
        {
            "description": "Information disclosure through error messages",
            "cwe_ids": "CWE-209,CWE-200",
            "severity": "Medium"
        },
        {
            "description": "Race condition in file handling operations",
            "cwe_ids": "CWE-362",
            "severity": "Low"
        }
    ]

    return jsonify(sample_vulnerabilities)


@app.route('/api/vulnerability/cli-results', methods=['GET'])
def get_cli_results():
    """Get CLI assessment results from the JSON file"""
    try:
        cli_results_path = "cli_results.json"

        if os.path.exists(cli_results_path):
            with open(cli_results_path, 'r') as f:
                data = json.load(f)
            return jsonify(data)
        else:
            return jsonify({"results": []})

    except Exception as e:
        return jsonify({"error": f"Failed to load CLI results: {str(e)}"}), 500


@app.route('/api/vulnerability/cli-submit', methods=['POST'])
def submit_cli_result():
    """Submit a CLI assessment result"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Add timestamp
        data['timestamp'] = datetime.now().isoformat()

        # Load existing results
        cli_results_path = "cli_results.json"
        if os.path.exists(cli_results_path):
            with open(cli_results_path, 'r') as f:
                results_data = json.load(f)
        else:
            results_data = {"results": []}

        # Add new result
        results_data["results"].append(data)

        # Keep only the last 50 results to prevent file from growing too large
        if len(results_data["results"]) > 50:
            results_data["results"] = results_data["results"][-50:]

        # Save updated results
        with open(cli_results_path, 'w') as f:
            json.dump(results_data, f, indent=2)

        return jsonify({"message": "Result submitted successfully"})

    except Exception as e:
        return jsonify({"error": f"Failed to submit result: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
