import pandas as pd
import numpy as np
import json
import ast
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# =====================================================================
# STEP 1: PARSING ENGINE (Extracting from a valid standard JSON file)
# =====================================================================
def parse_raw_cowrie_logs(json_path):
    print(f"[1/7] Ingesting standard JSON file from: {json_path}")
    
    # Solves the UnicodeDecodeError on Windows and loads the whole JSON array/object at once
    with open(json_path, 'r', encoding='utf-8', errors='replace') as f:
        raw_data = json.load(f)

    # Convert the loaded list of dictionaries directly into a DataFrame
    df_raw = pd.DataFrame(raw_data)
    if df_raw.empty:
        raise ValueError("The cowrie.json file yielded an empty DataFrame.")

    print("[2/7] Extracting distinct network identity events...")
    # Base network session metadata
    connects = df_raw[df_raw['eventid'] == 'cowrie.session.connect'][[
        'session', 'src_ip', 'src_port', 'dst_port', 'protocol', 'timestamp'
    ]].rename(columns={'timestamp': 'start_time'})

    # SSH architecture details
    versions = df_raw[df_raw['eventid'] == 'cowrie.client.version'][['session', 'version']]
    kex_info = df_raw[df_raw['eventid'] == 'cowrie.client.kex'][['session', 'hassh']]

    print("[3/7] Aggregating authentication and post-exploitation actions...")
    # Brute force telemetry metrics
    logins = df_raw[df_raw['eventid'] == 'cowrie.login.failed']
    login_agg = logins.groupby('session').agg(
        failed_login_count=('eventid', 'count'),
        usernames_tried=('username', lambda x: list(set(x))),
        passwords_tried=('password', lambda x: list(set(x)))
    ).reset_index()

    # Success indicators (compromised credentials tracking)
    successful_logins = df_raw[df_raw['eventid'] == 'cowrie.login.success']
    success_agg = successful_logins.groupby('session').size().reset_index(name='successful_login_count')

    # Post-exploitation shell input execution
    commands = df_raw[df_raw['eventid'] == 'cowrie.command.input']
    command_agg = commands.groupby('session').size().reset_index(name='commands_executed_count')

    # Staged payload downloads or files dropped to disk
    uploads = df_raw[df_raw['eventid'] == 'cowrie.session.file_upload']
    upload_agg = uploads.groupby('session').size().reset_index(name='file_upload_count')

    # Session closure times
    closures = df_raw[df_raw['eventid'] == 'cowrie.session.closed'][['session', 'duration']]
    closures['duration'] = pd.to_numeric(closures['duration'], errors='coerce')

    print("[4/7] Compiling relational tables into unified sessions dataframe...")
    # Relational merge execution using unique 'session' ID hashes
    cleaned_df = connects.merge(versions, on='session', how='left')
    cleaned_df = cleaned_df.merge(kex_info, on='session', how='left')
    cleaned_df = cleaned_df.merge(login_agg, on='session', how='left')
    cleaned_df = cleaned_df.merge(success_agg, on='session', how='left')
    cleaned_df = cleaned_df.merge(command_agg, on='session', how='left')
    cleaned_df = cleaned_df.merge(upload_agg, on='session', how='left')
    cleaned_df = cleaned_df.merge(closures, on='session', how='left')

    # Null value treatment for early-stage drops
    cleaned_df['failed_login_count'] = cleaned_df['failed_login_count'].fillna(0).astype(int)
    cleaned_df['successful_login_count'] = cleaned_df['successful_login_count'].fillna(0).astype(int)
    cleaned_df['commands_executed_count'] = cleaned_df['commands_executed_count'].fillna(0).astype(int)
    cleaned_df['file_upload_count'] = cleaned_df['file_upload_count'].fillna(0).astype(int)
    cleaned_df['duration'] = cleaned_df['duration'].fillna(0.0)
    cleaned_df['hassh'] = cleaned_df['hassh'].fillna('unknown')
    cleaned_df['version'] = cleaned_df['version'].fillna('unknown')

    # Periodic cyclical time tracking
    cleaned_df['start_time'] = pd.to_datetime(cleaned_df['start_time'])
    cleaned_df['hour_of_day'] = cleaned_df['start_time'].dt.hour

    return cleaned_df


# =====================================================================
# STEP 2: RISK ENGINE (Domain-guided scoring mathematical limits)
# =====================================================================
def calculate_cluster_risk(avg_logins, avg_duration, avg_users, avg_passwords, avg_success, avg_cmds, avg_uploads):
    """
    Applies non-linear logarithmic transformation calculations to normalize attack parameters
    and generates an automated risk index bounded strictly between 0 and 100.
    """
    # Hard triggers override standard matrix weighting for severe interactive actions
    if avg_uploads > 0.1:
        return 98.0, "CRITICAL (Active Payload Delivery & Weaponization)"
    if avg_cmds > 0.2:
        return 88.0, "HIGH (Post-Exploitation Interaction & Shell Discovery)"
    if avg_success > 0.05:
        return 75.0, "HIGH (Unauthorized Session Intrusion Confirmed)"

    # Base behavior mathematical weights (sum to 1.0)
    w_logins = 0.30
    w_duration = 0.30
    w_users = 0.20
    w_passwords = 0.20
    
    # Scale variables using estimated realistic maximum attack caps to limit skewing
    score_logins = np.log1p(avg_logins) / np.log1p(1500)      
    score_duration = np.log1p(avg_duration) / np.log1p(3600)  
    score_users = np.log1p(avg_users) / np.log1p(100)          
    score_passwords = np.log1p(avg_passwords) / np.log1p(500) 
    
    def clamp(val):
        return min(max(val, 0.0), 1.0)

    weighted_score = (
        clamp(score_logins) * w_logins +
        clamp(score_duration) * w_duration +
        clamp(score_users) * w_users +
        clamp(score_passwords) * w_passwords
    )
    
    final_score = round(weighted_score * 100, 1)
    
    if final_score < 15:
        tier = "LOW (Blind Mass-Network Scanners)"
    elif final_score < 45:
        tier = "MEDIUM (Targeted Automated Brute-Force Botnets)"
    else:
        tier = "HIGH (Aggressive Password Spraying / Scanning)"
        
    return final_score, tier


# =====================================================================
# STEP 3: MACHINE LEARNING PIPELINE
# =====================================================================
def run_honeypot_pipeline(raw_json_path, output_csv_path):
    # Parse Cowrie entries
    df_original = parse_raw_cowrie_logs(raw_json_path)
    
    print("[5/7] Engineering structural features from list columns...")
    def count_elements(val):
        if isinstance(val, list):
            return len(val)
        if pd.isna(val) or val == '':
            return 0
        try:
            return len(ast.literal_eval(str(val)))
        except (ValueError, SyntaxError):
            return 0

    df_original['unique_usernames_count'] = df_original['usernames_tried'].apply(count_elements)
    df_original['unique_passwords_count'] = df_original['passwords_tried'].apply(count_elements)

    # Separate telemetry columns from categorical text strings
    columns_to_drop = [
        'session', 'src_ip', 'start_time', 'usernames_tried', 'passwords_tried'
    ]
    features_df = df_original.drop(columns=columns_to_drop, errors='ignore')

    # Structural feature transformations via One-Hot encoding 
    categorical_cols = ['protocol', 'version', 'hassh']
    features_encoded = pd.get_dummies(features_df, columns=categorical_cols, dtype=float)

    # Feature Scaling Engine
    numerical_cols = [
        'failed_login_count', 'successful_login_count', 'commands_executed_count',
        'file_upload_count', 'duration', 'hour_of_day', 
        'unique_usernames_count', 'unique_passwords_count'
    ]
    numerical_cols = [col for col in numerical_cols if col in features_encoded.columns]
    
    scaler = StandardScaler()
    features_encoded[numerical_cols] = scaler.fit_transform(features_encoded[numerical_cols])

    print("[6/7] Training unsupervised K-Means model to isolate fingerprints...")
    kmeans = KMeans(n_clusters=5, random_state=42, n_init=10)
    df_original['cluster_id'] = kmeans.fit_predict(features_encoded)

    print("[7/7] Generating final risk assignments and signatures...")
    cluster_risk_mapping = {}

    print("\n" + "="*75)
    print("      EXTRACTED HONEYPOT ATTACK FINGERPRINTS & RISK ASSESSMENTS")
    print("="*75 + "\n")

    for cid in sorted(df_original['cluster_id'].unique()):
        cluster_data = df_original[df_original['cluster_id'] == cid]
        
        # Calculate behavioral identity aggregates
        avg_logins = cluster_data['failed_login_count'].mean()
        avg_duration = cluster_data['duration'].mean()
        avg_users = cluster_data['unique_usernames_count'].mean()
        avg_passwords = cluster_data['unique_passwords_count'].mean()
        avg_success = cluster_data['successful_login_count'].mean()
        avg_cmds = cluster_data['commands_executed_count'].mean()
        avg_uploads = cluster_data['file_upload_count'].mean()
        
        # Execute customized heuristic engine
        risk_score, risk_tier = calculate_cluster_risk(
            avg_logins, avg_duration, avg_users, avg_passwords, avg_success, avg_cmds, avg_uploads
        )
        cluster_risk_mapping[cid] = {"risk_score": risk_score, "risk_tier": risk_tier}

        # Safe extraction for identification text labels
        top_protocols = cluster_data['protocol'].mode().tolist()
        top_version = cluster_data['version'].mode().values[0] if not cluster_data['version'].empty else "Unknown"
        unique_ips = cluster_data['src_ip'].nunique()

        print(f"### [ PROFILE SIGNATURE: CLUSTER ID {cid} ] ###")
        print(f" -> RISK EVALUATION:  Score: {risk_score}/100 | Assessment: {risk_tier}")
        print(f" -> Footprint Scale:  Captured {len(cluster_data)} sessions across {unique_ips} distinct source IPs.")
        print(f" -> Target Profiling: Target Protocols: {top_protocols} | Software Version: {top_version}")
        print(f" -> Behavioral Speed: Brute Forcing attempts per session: {avg_logins:.1f}")
        print(f" -> Exploitation State: Success rate: {avg_success:.2f} | Commands typed: {avg_cmds:.1f} | File Drops: {avg_uploads:.1f}")
        print(f" -> Example IPs:     {cluster_data['src_ip'].head(3).tolist()}")
        print("-" * 75 + "\n")

    # Map profile scores back onto individual session entries
    df_original['fingerprint_risk_score'] = df_original['cluster_id'].map(lambda x: cluster_risk_mapping[x]['risk_score'])
    df_original['fingerprint_risk_tier'] = df_original['cluster_id'].map(lambda x: cluster_risk_mapping[x]['risk_tier'])

    # File extraction save down
    df_original.to_csv(output_csv_path, index=False)
    print(f"Execution complete. Output containing fingerprints and risks saved to: {output_csv_path}")


if __name__ == "__main__":
    run_honeypot_pipeline('new.json', 'fingerprinted_cowrie_results.csv')