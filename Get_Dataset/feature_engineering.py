
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

def perform_feature_engineering(input_csv_path, output_csv_path):
    print(f"Loading merged data from {input_csv_path}...")
    df = pd.read_csv(input_csv_path)
    print(f"Loaded {len(df)} entries.")

    # --- Preprocessing for TF-IDF ---
    # Ensure 'Description' column is string type and handle NaN values
    df["Description"] = df["Description"].astype(str).fillna("")

    # Combine new text fields from Dependabot alerts for TF-IDF
    df["Advisory_Text"] = (
        df["vulnerability_advisory_summary"].astype(str).fillna("") + " " +
        df["vulnerability_advisory_description"].astype(str).fillna("")
    )
    df["Advisory_Text"] = df["Advisory_Text"].fillna("")

    # --- Feature Engineering ---

    # 1. Text-based features from Description using TF-IDF
    print("Generating TF-IDF features from Description...")
    tfidf_vectorizer_desc = TfidfVectorizer(max_features=1000)  # Limit features to avoid sparsity
    tfidf_matrix_desc = tfidf_vectorizer_desc.fit_transform(df["Description"])
    tfidf_df_desc = pd.DataFrame(
        tfidf_matrix_desc.toarray(),
        columns=[f"desc_{col}" for col in tfidf_vectorizer_desc.get_feature_names_out()]
    )
    df = pd.concat([df, tfidf_df_desc], axis=1)

    # 2. Text-based features from Advisory_Text using TF-IDF
    print("Generating TF-IDF features from Advisory_Text...")
    tfidf_vectorizer_adv = TfidfVectorizer(max_features=500)  # Limit features
    tfidf_matrix_adv = tfidf_vectorizer_adv.fit_transform(df["Advisory_Text"])
    tfidf_df_adv = pd.DataFrame(
        tfidf_matrix_adv.toarray(),
        columns=[f"adv_{col}" for col in tfidf_vectorizer_adv.get_feature_names_out()]
    )
    df = pd.concat([df, tfidf_df_adv], axis=1)

    # 3. One-hot encode Severity (original) and vulnerability_severity (from Dependabot)
    print("One-hot encoding Severity and vulnerability_severity...")
    df = pd.get_dummies(df, columns=["Severity"], prefix="Severity")
    df = pd.get_dummies(df, columns=["vulnerability_severity"], prefix="Dependabot_Severity")

    # 4. Encode CWE_IDs (simple count)
    print("Encoding CWE_IDs...")
    df["CWE_Count"] = df["CWE_IDs"].apply(
        lambda x: len(str(x).split(",")) if pd.notna(x) and str(x) else 0
    )

    # 5. Encode Dependabot alert state
    print("Encoding Dependabot alert state...")
    df = pd.get_dummies(df, columns=["state"], prefix="Alert_State")

    # 6. Convert date/time columns to numerical features
    date_cols = ["created_at", "updated_at", "dismissed_at"]
    for col in date_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
            df[f"days_since_{col}"] = (pd.to_datetime("2025-01-01") - df[col]).dt.days

    # Drop original text columns and other non-numeric/redundant columns
    cols_to_drop = [
        "Description", "Advisory_Text", "CWE_IDs", "Affected_Versions",
        "repo_full_name", "alert_number", "dismissed_reason", "dependency_name",
        "dependency_scope", "vulnerability_advisory_ghsa_id", "vulnerability_advisory_summary",
        "vulnerability_advisory_description", "first_patched_version", "vulnerable_versions"
    ]
    df = df.drop(columns=cols_to_drop + date_cols, errors="ignore")

    print(f"Feature engineered dataframe has {len(df)} entries and {len(df.columns)} columns.")
    df.to_csv(output_csv_path, index=False)
    print(f"Feature engineered data saved to {output_csv_path}")

if __name__ == "__main__":
    INPUT_CSV = "merged_vulnerabilities.csv"
    OUTPUT_CSV = "feature_engineered_vulnerabilities_enhanced.csv"
    perform_feature_engineering(INPUT_CSV, OUTPUT_CSV)
