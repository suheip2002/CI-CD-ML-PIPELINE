# check_class_distribution.py
import pandas as pd
import matplotlib.pyplot as plt
from config_paths import FEATURE_ENGINEERED_WITH_LABEL

def main():
    # Load only the label column
    df = pd.read_csv(FEATURE_ENGINEERED_WITH_LABEL, usecols=['binary_label'])

    class_counts = df['binary_label'].value_counts()
    class_percent = df['binary_label'].value_counts(normalize=True) * 100

    print("Class distribution of binary_label:")
    print(class_counts)
    print("\nPercentages:")
    print(class_percent)

    # Optional plot
    class_counts.plot(kind='bar', title='Binary Label Distribution')
    plt.show()

if __name__ == "__main__":
    main()
