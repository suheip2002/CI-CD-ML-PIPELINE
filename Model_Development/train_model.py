import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib

def train_and_evaluate_model(input_csv_path, model_output_path):
    print(f"Loading feature engineered data from {input_csv_path}...")
    df = pd.read_csv(input_csv_path)
    print(f"Loaded {len(df)} entries.")

    # Define features (X) and target (y)
    # Re-create the original 'Severity' column from the one-hot encoded columns
    severity_cols = [col for col in df.columns if col.startswith("Severity_")]
    if not severity_cols:
        raise ValueError("No 'Severity_' columns found for target variable. Ensure Severity was one-hot encoded.")

    # Recover original severity string from one-hot encoded columns
    df["Original_Severity"] = df[severity_cols].idxmax(axis=1).str.replace("Severity_", "")

    # Encode target variable
    label_encoder = LabelEncoder()
    df["Target_Severity_Encoded"] = label_encoder.fit_transform(df["Original_Severity"])

    # Features (X) — drop unnecessary columns
    cols_to_drop_for_training = [
        "CVE_ID", "Description", "Original_Severity", "Target_Severity_Encoded",
        "Advisory_Text", "repo_full_name_dependabot", "alert_number", "state",
        "created_at_dependabot", "updated_at_dependabot", "dismissed_at_dependabot",
        "dismissed_reason", "dependency_name", "dependency_scope",
        "vulnerability_advisory_ghsa_id", "vulnerability_advisory_summary",
        "vulnerability_advisory_description", "first_patched_version", "vulnerable_versions"
    ] + severity_cols + [col for col in df.columns if col.startswith("Dependabot_Severity_")]

    X = df.drop(columns=cols_to_drop_for_training, errors="ignore")
    y = df["Target_Severity_Encoded"]

    # Drop any remaining non-numeric columns
    non_numeric_cols = X.select_dtypes(include=["object"]).columns
    if len(non_numeric_cols) > 0:
        print(f"Warning: Non-numeric columns found in features: {list(non_numeric_cols)}. Dropping them.")
        X = X.drop(columns=non_numeric_cols)

    # Split data into train/test
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training set size: {len(X_train)}")
    print(f"Testing set size: {len(X_test)}")

    # Train model
    print("Training RandomForestClassifier model...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # Predict
    print("Making predictions on the test set...")
    y_pred = model.predict(X_test)

    # Evaluate
    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Save model
    print(f"Saving trained model and label encoder to {model_output_path}...")
    joblib.dump(
        {
            "model": model,
            "label_encoder": label_encoder,
            "feature_names": X.columns.tolist()
        },
        model_output_path
    )
    print("Model training and evaluation complete.")

if __name__ == "__main__":
    INPUT_CSV = "feature_engineered_vulnerabilities_enhanced.csv"
    MODEL_OUTPUT_PATH = "vulnerability_classifier_model_enhanced.joblib"
    train_and_evaluate_model(INPUT_CSV, MODEL_OUTPUT_PATH)
