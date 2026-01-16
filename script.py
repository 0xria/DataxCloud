import sqlite3
import json
import boto3
import time

def setup_db(): #connect db
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event_action TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    
# extract&transfrom: get logs from json file
def process_logs(logs, username):
    threat_actions = ["DeleteStorage", "DisableLogging", "ChangeIAMPolicy"]
        
    for entry in logs:
        if entry["action"] in threat_actions:
            print(f"🚨 CRITICAL THREAT: {entry['action']} detected!") #destroy access
            deactivate_user_keys(username) # The Boto3 function we discussed
            
            cloud_backup() #secure evidence
            
            return "THREAT NEUTRALIZED"

#  input the alerts into the database
def store_alerts(alerts):
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.executemany('INSERT INTO alerts (username, event_action, severity) VALUES (?, ?, ?)''', alerts)    #inform sql to insert this data into 3 specific columns
    conn.commit()
    conn.close()

def get_logs_from_s3(bucket_name, file_key):
    s3 = boto3.client('s3')
    response = s3.get_object(Bucket=bucket_name, Key=file_key)
    content = response['Body'].read().decode('utf-8')
    return json.loads(content)

def deactivate_user_keys(username):
    iam = boto3.client('iam')
    
    paginator = iam.get_paginator('list_access_keys')#list the keys for this specific user
    for response in paginator.paginate(UserName=username):
        for key in response['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            
            # 2. Set the key to 'Inactive' (The Kill Switch)
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status='Inactive'
            )
            print(f"🔒 Access Key {key_id} for user {username} has been DEACTIVATED.")

def cloud_backup():
    s3 = boto3.client('s3') #initialize s3 client
    s3.upload_file('vault.db', 'my-vault-bucket', 'backups/vault.db')
    print("☁️ Vault database backed up to S3 successfully.")

#---Main---
if __name__ == "__main__":
    setup_db() #prep db
    
    while True:
        print("Searching for new logs...")
        
        with open('cloud_events.json', 'r') as file:
            raw_data = json.load(file)

            status = process_logs(raw_data, "admin_user_01")#we pass the data and target username to detect
            if status == "THREAT NEUTRALIZED":
                print("System Guarded: Contunuing monitoring... 🛡️")
            time.sleep(60)#wait a min before checking again


