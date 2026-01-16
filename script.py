import sqlite3
import json
import boto3
import time
import os
from dotenv import load_dotenv

load_dotenv() # This loads the variables from .env

SESSION_CONFIG = {
    'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
    'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
    'region_name': os.getenv('AWS_REGION')
}
iam = boto3.client('iam', **SESSION_CONFIG)
s3 = boto3.client('s3', **SESSION_CONFIG)

def setup_db():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event_action TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, event_action, timestamp)
        )
    ''')
    conn.commit()
    conn.close()

def send_alert(user, action):
    """Sends a notification when a threat is detected."""
    alert_msg = f"🔔 ALERT: Incident report generated for {user} - Action: {action}"
    print(alert_msg)
    

def process_logs(logs, target_user_name):
    threat_actions = ["DeleteStorage", "DisableLogging", "ChangeIAMPolicy"]
    processed_alerts = []

    for entry in logs:
        severity = "HIGH" if entry["action"] in threat_actions else "INFO"
        processed_alerts.append((entry["user"], entry['action'], severity))

        if severity == "HIGH":
            print(f"🚨 CRITICAL THREAT: {entry['action']} detected by {entry['user']}!")
            send_alert(entry["user"], entry["action"])
            # We use target_user_name which is "target_user"
            deactivate_user_keys("target_user") 
            cloud_backup()
            
    return processed_alerts

def store_alerts(alerts):
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    # Changed column name to 'username' to match setup_db
    cursor.executemany('''
            INSERT OR IGNORE INTO alerts (username, event_action, severity)
             VALUES (?, ?, ?)
        ''', alerts)
    conn.commit()
    conn.close()

def deactivate_user_keys(username):
    # REMOVED: iam = boto3.client('iam') -> We use the global one now
    paginator = iam.get_paginator('list_access_keys')
    for response in paginator.paginate(UserName=username):
        for key in response['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status='Inactive'
            )
            print(f"🔒 Access Key {key_id} for user {username} has been DEACTIVATED.")

def cloud_backup():
    # Uses the global s3 client configured with your keys
    try:
        s3.upload_file('vault.db', 'my-vault-bucket-ria.shx', 'backups/vault.db')
        print("☁️ Vault database backed up to S3 successfully.")
    except Exception as e:
        print(f"❌ Backup failed: {e}")

if __name__ == "__main__":
    setup_db()
    while True:
        print("Searching for new logs...")
        try:
            with open('cloud_events.json', 'r') as file:
                raw_data = json.load(file)

            # Pass the actual string name of the user you want to deactivate
            process_logs(raw_data, "target_user")
            print("System Rebuilt: Vaulted Logs ✅")
        except Exception as e:
            print(f"⚠️ Error: {e}")
        time.sleep(60)  # Wait for 5 minutes before checking again
        