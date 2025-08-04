import boto3
import csv
import os
from openpyxl import Workbook

XLSX_FILE = "CloudSecurity/cloud_audit_status.xlsx"
ACCOUNT_LIST_FILE = "account_list.csv"
ROLE_NAME = "SecurityAutomation"
CREDENTIALS_FILE = "aws_credentials.txt"

REGIONS = {
    "jakarta": "ap-southeast-3",
    "singapore": "ap-southeast-1"
}

def load_credentials(file_path):
    creds = {}
    with open(file_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                creds[key.strip()] = value.strip()
    return creds.get("aws_access_key_id"), creds.get("aws_secret_access_key")

def get_account_list(file_path):
    with open(file_path, newline="") as f:
        reader = csv.DictReader(f)
        return [(row["account_id"], row.get("account_name", "")) for row in reader if row.get("account_id")]

def assume_role(account_id):
    access_key, secret_key = load_credentials(CREDENTIALS_FILE)
    sts = boto3.client(
        "sts",
        region_name="ap-southeast-3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName="CloudAuditSession")
    creds = response["Credentials"]
    return creds

def check_cloudtrail(client, region_code):
    try:
        trails = client.describe_trails()['trailList']
        for trail in trails:
            if trail.get("IsMultiRegionTrail") or trail.get("HomeRegion") == region_code:
                return "Enabled"
        return "Disabled"
    except Exception as e:
        return f"Error: {e}"

def check_config(client):
    try:
        status = client.describe_configuration_recorder_status()
        if not status['ConfigurationRecordersStatus']:
            return "Not Configured"
        return "Enabled" if any(r['recording'] for r in status['ConfigurationRecordersStatus']) else "Disabled"
    except Exception as e:
        return f"Error: {e}"

def check_guardduty(client):
    try:
        detectors = client.list_detectors()["DetectorIds"]
        if not detectors:
            return "Not Configured"
        return "Enabled"
    except Exception as e:
        return f"Error: {e}"

def main():
    accounts = get_account_list(ACCOUNT_LIST_FILE)
    rows = []
    header = [
        "account_id", "account_name",
        "cloudtrail_status_jakarta", "cloudtrail_status_singapore",
        "config_status_jakarta", "config_status_singapore",
        "guardduty_status_jakarta", "guardduty_status_singapore"
    ]

    for account_id, account_name in accounts:
        print(f"\n▶ Processing account: {account_id} ({account_name})")
        try:
            creds = assume_role(account_id)
        except Exception as e:
            print(f"❌ Could not assume role for account {account_id}: {e}")
            continue

        row = [account_id, account_name]
        results = {}

        for region_name, region_code in REGIONS.items():
            try:
                session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=region_code
                )

                ct_client = session.client("cloudtrail")
                config_client = session.client("config")
                gd_client = session.client("guardduty")

                results[f"cloudtrail_status_{region_name}"] = check_cloudtrail(ct_client, region_code)
                results[f"config_status_{region_name}"] = check_config(config_client)
                results[f"guardduty_status_{region_name}"] = check_guardduty(gd_client)

                print(f"✔ {region_name.title()} Region:")
                print(f"  - CloudTrail : {results[f'cloudtrail_status_{region_name}']}")
                print(f"  - Config     : {results[f'config_status_{region_name}']}")
                print(f"  - GuardDuty  : {results[f'guardduty_status_{region_name}']}")

            except Exception as e:
                print(f"❌ Error in {region_name.title()} for {account_id}: {e}")
                results[f"cloudtrail_status_{region_name}"] = "Error"
                results[f"config_status_{region_name}"] = "Error"
                results[f"guardduty_status_{region_name}"] = "Error"

        row.extend([
            results["cloudtrail_status_jakarta"],
            results["cloudtrail_status_singapore"],
            results["config_status_jakarta"],
            results["config_status_singapore"],
            results["guardduty_status_jakarta"],
            results["guardduty_status_singapore"]
        ])
        rows.append(row)

    if rows:
        os.makedirs(os.path.dirname(XLSX_FILE), exist_ok=True)
        wb = Workbook()
        ws = wb.active
        ws.title = "CloudAuditStatus"
        ws.append(header)
        for row in rows:
            ws.append(row)
        wb.save(XLSX_FILE)
        print(f"\n✅ XLSX report saved to: {XLSX_FILE}")
    else:
        print("[INFO] No data collected.")

if __name__ == "__main__":
    main()
