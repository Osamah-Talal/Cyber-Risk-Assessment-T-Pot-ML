import pandas as pd
import numpy as np
import ast
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

def run_honeypot_clustering(csv_path):
    print(f"[1/5] Loading dataset from: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Error: Could not find '{csv_path}'. Please check your path.")
        return

    # Keep a copy of raw columns to make our final summary readable
    df_original = df.copy()

    print("[2/5] Engineering features and fixing string-list columns...")
    
    # Helper function to safely parse string representations of lists like "['guest']"
    def count_elements(val):
        if pd.isna(val):
            return 0
        try:
            # Safely converts the string back into a Python list and gets its length
            return len(ast.literal_eval(str(val)))
        except (ValueError, SyntaxError):
            return 0

    # Turn text lists into clean numerical counts if they exist in your CSV
    if 'usernames_tried' in df.columns:
        df_original['unique_usernames_count'] = df['usernames_tried'].apply(count_elements)
    else:
        df_original['unique_usernames_count'] = 0

    if 'passwords_tried' in df.columns:
        df_original['unique_passwords_count'] = df['passwords_tried'].apply(count_elements)
    else:
        df_original['unique_passwords_count'] = 0

    # Create our clean training feature set by dropping metadata and un-parsable strings
    columns_to_drop = [
        'session', 'src_ip', 'start_time', 
        'usernames_tried', 'passwords_tried'
    ]
    features_df = df_original.drop(columns=columns_to_drop, errors='ignore')

    print("[3/5] Performing One-Hot Encoding on network client configurations...")
    # Convert high-cardinality categorical text columns into 1s and 0s
    categorical_cols = ['protocol', 'version', 'hassh']
    # Enforce float dtype to guarantee compatibility across ML steps
    features_encoded = pd.get_dummies(features_df, columns=categorical_cols, dtype=float)

    print("[4/5] Normalizing numerical ranges with StandardScaler...")
    # Define all numerical metrics that need scaling so they carry equal weight
    numerical_cols = [
        'failed_login_count', 'duration', 'hour_of_day', 
        'unique_usernames_count', 'unique_passwords_count'
    ]
    # Filter only columns that actually ended up in the matrix
    numerical_cols = [col for col in numerical_cols if col in features_encoded.columns]
    
    scaler = StandardScaler()
    features_encoded[numerical_cols] = scaler.fit_transform(features_encoded[numerical_cols])

    print("[5/5] Executing K-Means Clustering...")
    # Setting clusters to 3 based on variations within the honeypot sample data
    kmeans = KMeans(n_clusters=3, random_state=42, n_init='auto')
    df_original['cluster_id'] = kmeans.fit_predict(features_encoded)

    print("\n" + "="*50)
    print("      EXTRACTED HONEYPOT BEHAVIOR FINGERPRINTS")
    print("="*50 + "\n")

    for cid in sorted(df_original['cluster_id'].unique()):
        cluster_data = df_original[df_original['cluster_id'] == cid]
        
        # Calculate behavioral metrics for this unique fingerprint group
        avg_logins = cluster_data['failed_login_count'].mean()
        avg_duration = cluster_data['duration'].mean()
        avg_unique_users = cluster_data['unique_usernames_count'].mean()
        avg_unique_passwords = cluster_data['unique_passwords_count'].mean()
        
        # Extract modes safely in case of ties or missing entries
        top_protocols = cluster_data['protocol'].mode().tolist()
        top_client_version = cluster_data['version'].mode().values[0] if not cluster_data['version'].empty else "Unknown"
        unique_ips_count = cluster_data['src_ip'].nunique()

        print(f"### [ FINGERPRINT IDENTITY PROFILE: CLUSTER {cid} ] ###")
        print(f" -> Threat Scale:     Captured {len(cluster_data)} malicious sessions from {unique_ips_count} unique IPs.")
        print(f" -> Network Platform: Primarily targeting: {top_protocols}")
        print(f" -> Primary Toolset:  {top_client_version}")
        print(f" -> Attack Pace:      Averages {avg_logins:.1f} brute-force attempts per session.")
        print(f" -> Credential Depth: Tried ~{avg_unique_users:.1f} unique usernames & {avg_unique_passwords:.1f} unique passwords.")
        print(f" -> Persistence Time: Stays connected for an average of {avg_duration:.2f} seconds.")
        print(f" -> Example Actors:   {cluster_data['src_ip'].head(2).tolist()}")
        print("-" * 50 + "\n")

    # Save the labeled dataset back to disk
    output_csv = "fingerprinted_cowrie_results.csv"
    df_original.to_csv(output_csv, index=False)
    print(f"Successfully appended cluster labels and saved output to: {output_csv}")

# --- Execution ---
if __name__ == "__main__":
    run_honeypot_clustering('cleaned_cowrie_sessions.csv')