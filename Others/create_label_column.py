# create_label_column.py

import pandas as pd

def main():
    # Load your enhanced feature engineered dataset
    data_path = 'feature_engineered_vulnerabilities_enhanced.csv'
    df = pd.read_csv(data_path)

    # Check available severity columns
    severity_cols = [
        'Severity_Critical',
        'Severity_High',
        'Severity_Medium',
        'Severity_Low',
        'Severity_Unknown'
    ]

    # Validate columns exist
    for col in severity_cols:
        if col not in df.columns:
            print(f"WARNING: Column {col} not found in DataFrame!")
    # Decide how to combine them into a single label column
    # Option A: single multi-class label
    def get_label(row):
        # Order: Critical > High > Medium > Low > Unknown
        if row.get('Severity_Critical', 0) == 1:
            return 'Critical'
        elif row.get('Severity_High', 0) == 1:
            return 'High'
        elif row.get('Severity_Medium', 0) == 1:
            return 'Medium'
        elif row.get('Severity_Low', 0) == 1:
            return 'Low'
        else:
            return 'Unknown'

    df['severity_label'] = df.apply(get_label, axis=1)

    # Alternate Option B: binary label — treat Critical + High as "HighRisk", others "NotHighRisk"
    def get_binary_label(row):
        if row.get('Severity_Critical', 0) == 1 or row.get('Severity_High', 0) == 1:
            return 'HighRisk'
        else:
            return 'NotHighRisk'

    df['binary_label'] = df.apply(get_binary_label, axis=1)

    # Save new dataset – overwrite or to new file
    output_path = 'feature_engineered_vulnerabilities_with_label.csv'
    df.to_csv(output_path, index=False)
    print(f"Saved new dataset with label columns to {output_path}")

if __name__ == '__main__':
    main()
