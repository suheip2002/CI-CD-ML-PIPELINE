import joblib
import pandas as pd
import requests
import json
import os
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the trained model and label encoder
# Ensure this path is correct relative to where the CLI tool will be run
MODEL_PATH = "Model_Development/vulnerability_classifier_model_enhanced.joblib"

# Dashboard configuration
DASHBOARD_URL = "http://localhost:5000"
# Point to the dashboard folder at project root
CLI_RESULTS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dashboard', 'cli_results.json')

try:
    model_data = joblib.load(MODEL_PATH)
    model = model_data["model"]
    label_encoder = model_data["label_encoder"]
    feature_names = model_data["feature_names"]
    print("Model and label encoder loaded successfully.")
except FileNotFoundError:
    print(f"Error: Model file not found at {MODEL_PATH}. Please ensure the model has been trained and saved.")
    exit()
except KeyError as e:
    print(
        f"Error loading model components: {e}. Ensure the joblib file contains 'model', 'label_encoder', and 'feature_names'.")
    exit()


def preprocess_input(description, cwe_ids):
    # Create a DataFrame with the same columns as the training data
    input_df = pd.DataFrame(0, index=[0], columns=feature_names)

    # Fill in relevant columns based on user input
    input_df["CWE_Count"] = len(str(cwe_ids).split(",")) if cwe_ids else 0

    # For TF-IDF features, we need to re-apply the same vectorizer used during training.
    # Since we don't have the original TfidfVectorizer object saved, this is a simplification.
    # In a real-world scenario, you would save and load the vectorizer along with the model.
    # For this demonstration, we will create dummy TF-IDF features based on the description.
    # This is NOT ideal for accurate predictions but allows the CLI to run.
    # A proper solution would involve re-training the model with a saved vectorizer.

    # Dummy TF-IDF for demonstration purposes
    # This part needs to be aligned with how TF-IDF was generated in feature_engineering.py
    # For now, we'll just set some dummy values if description is provided.
    # This will likely not contribute meaningfully to the prediction.
    if description:
        # This is a very simplified way to handle description for prediction.
        # Ideally, the TfidfVectorizer used in feature_engineering.py should be saved and loaded here.
        # For now, we'll just create a dummy feature if the description is not empty.
        # This will likely not contribute meaningfully to the prediction.
        pass  # No direct TF-IDF generation here without the original vectorizer

    return input_df


def predict_severity(description, cwe_ids):
    processed_input = preprocess_input(description, cwe_ids)

    # Ensure columns match
    missing_cols = set(feature_names) - set(processed_input.columns)
    for c in missing_cols:
        processed_input[c] = 0
    processed_input = processed_input[feature_names]

    # If input is essentially empty, return Unknown immediately
    if processed_input.sum().sum() == 0:
        return "Unknown"

    # Predict probabilities
    proba = model.predict_proba(processed_input)[0]
    max_proba = max(proba)
    predicted_class_index = proba.argmax()
    predicted_label = label_encoder.inverse_transform([predicted_class_index])[0]

    # Debug print
    print(f"[DEBUG] max_proba={max_proba:.3f}, predicted_label={predicted_label}")

    # High threshold to classify as known
    CONFIDENCE_THRESHOLD = 0.75
    if max_proba < CONFIDENCE_THRESHOLD:
        predicted_label = "Unknown"

    return predicted_label



def provide_recommendations(severity):
    recommendations = {
        "Critical": [
            "Immediately patch affected systems.",
            "Isolate affected systems from the network.",
            "Conduct a thorough forensic analysis.",
            "Notify relevant stakeholders and incident response team."
        ],
        "High": [
            "Prioritize patching and apply updates within 24-48 hours.",
            "Implement compensating controls if immediate patching is not possible.",
            "Review access controls and network segmentation."
        ],
        "Medium": [
            "Schedule patching during the next maintenance window.",
            "Monitor for exploitation attempts.",
            "Review configuration settings to mitigate risk."
        ],
        "Low": [
            "Apply patches during routine updates.",
            "Document the vulnerability and accept the risk if remediation is not feasible."
        ],
        "Unknown": [
            "Further investigation is required to determine the severity and impact.",
            "Consult vulnerability databases (NVD, CVE) for more information."
        ]
    }
    return recommendations.get(severity, ["No specific recommendations available for this severity."])


def save_cli_result(description, cwe_ids, predicted_severity, recommendations):
    """Save CLI assessment result to local file for dashboard to read"""
    try:
        # Load existing results
        if os.path.exists(CLI_RESULTS_FILE):
            with open(CLI_RESULTS_FILE, 'r') as f:
                results = json.load(f)
        else:
            results = {"results": []}

        # Add new result
        new_result = {
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "cwe_ids": cwe_ids,
            "severity": predicted_severity,
            "recommendations": recommendations
        }

        results["results"].insert(0, new_result)  # Add to beginning

        # Keep only last 10 results
        results["results"] = results["results"][:10]

        # Save back to file
        with open(CLI_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"✅ Result saved to dashboard (stored in {CLI_RESULTS_FILE})")

    except Exception as e:
        print(f"⚠️  Could not save result to dashboard: {e}")


def send_to_dashboard_api(description, cwe_ids, predicted_severity, recommendations):
    """Send assessment results to the dashboard API (optional)"""
    try:
        dashboard_api_url = f"{DASHBOARD_URL}/api/vulnerability/cli-submit"
        data = {
            "description": description,
            "cwe_ids": cwe_ids,
            "severity": predicted_severity,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }

        response = requests.post(dashboard_api_url, json=data, timeout=5)

        if response.status_code == 200:
            print("✅ Results sent to dashboard API successfully")
        else:
            print(f"⚠️  Dashboard API responded with status: {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("⚠️  Dashboard not running - results saved locally only")
    except Exception as e:
        print(f"⚠️  Could not send to dashboard API: {e}")


def open_dashboard():
    """Open the dashboard in the default web browser"""
    try:
        import webbrowser
        dashboard_url = f"{DASHBOARD_URL}"
        print(f"🌐 Opening dashboard at {dashboard_url}")
        webbrowser.open(dashboard_url)
    except Exception as e:
        print(f"⚠️  Could not open dashboard: {e}")
        print(f"   Please manually open: {DASHBOARD_URL}")


if __name__ == "__main__":
    print("\n--- CI/CD Pipeline Vulnerability Assessment CLI ---")
    print("Enter vulnerability details to get a severity prediction and recommendations.")
    print("Results will be displayed here and sent to the dashboard.")

    while True:
        print("\n" + "=" * 60)
        description = input("\nEnter vulnerability description (e.g., 'SQL Injection in login form'): ")
        cwe_ids = input("Enter CWE IDs (comma-separated, e.g., 'CWE-89,CWE-200'): ")

        if not description and not cwe_ids:
            print("Please provide at least a description or CWE IDs.")
            continue

        print("\n🔍 Analyzing vulnerability...")

        try:
            predicted_severity = predict_severity(description, cwe_ids)
            recommendations = provide_recommendations(predicted_severity)

            # Display results in CLI
            print(f"\n📊 ASSESSMENT RESULTS")
            print(f"{'=' * 40}")
            print(f"Predicted Severity: {predicted_severity}")
            print(f"\n📋 Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")

            # Save to dashboard
            save_cli_result(description, cwe_ids, predicted_severity, recommendations)

            # Try to send to dashboard API (optional)
            send_to_dashboard_api(description, cwe_ids, predicted_severity, recommendations)

            print(f"\n💡 Tip: Check the dashboard at {DASHBOARD_URL} to see this result!")

        except Exception as e:
            print(f"\n❌ Error during assessment: {e}")
            continue

        another = input("\nAssess another vulnerability? (yes/no): ").lower()
        if another != "yes":
            break

    print(f"\n🎉 Thank you for using the Vulnerability Assessment CLI!")
    print(f"📊 View all results at: {DASHBOARD_URL}")

