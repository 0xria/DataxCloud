- DataxCloud Security SOAR
A Python-based automated response tool that detects unauthorized AWS actions and neutralizes threats.

- Features
- **Log Ingestion:** Scans JSON-formatted cloud events.
- **Threat Detection:** Identifies critical actions like `DeleteStorage`.
- **Automated Response:** Instantly deactivates AWS IAM Access Keys for the offending user.
- **Evidence Preservation:** Backs up the security database to an S3 "Vault" bucket.
- **Incident Logging:** Stores all alerts in an SQLite database.

- Setup
1. Create a `.env` file with your `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
2. Run `pip install boto3 python-dotenv`.
3. Run `python3 script.py` to start the monitor.

OR 
1. Create an virtual environment and install dependencies:
```
python3 -m venv venv
source venv/bin/activate
pip install boto3 
pip install python-dotenv
```
2. Create a `.env` file with your `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
3. Run `python3 script.py` to start the monitor.    