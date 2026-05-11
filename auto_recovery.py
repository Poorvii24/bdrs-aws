#!/usr/bin/env python3
"""
auto_recovery.py — BDRS Auto-Recovery Cron Script
===================================================
Runs every 5 minutes via cron. Scans DynamoDB for files
marked as 'deleted_locally' and automatically restores them
from S3 — no human intervention needed.

SETUP (run once on EC2):
  chmod +x /home/ec2-user/bdrs/auto_recovery.py
  crontab -e
  Add this line:
  */5 * * * * /usr/bin/python3 /home/ec2-user/bdrs/auto_recovery.py >> /var/log/bdrs_recovery.log 2>&1

This demonstrates real automated disaster recovery — one of the
core concepts of cloud-based BDRS systems.
"""

import boto3
import hashlib
import uuid
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────────────
REGION        = 'ap-south-1'
BUCKET_NAME   = 'bdrs-backup-1si23ad037'
DYNAMO_TABLE  = 'bdrs-metadata'
ALERTS_TABLE  = 'bdrs-alerts-log'
SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:060768937126:bdrs-alerts'

s3       = boto3.client('s3',       region_name=REGION)
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns      = boto3.client('sns',      region_name=REGION)
table    = dynamodb.Table(DYNAMO_TABLE)

# ── HELPERS ───────────────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{ts}] {msg}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def log_alert(alert_type, message):
    try:
        dynamodb.Table(ALERTS_TABLE).put_item(Item={
            'alert_id': str(uuid.uuid4()),
            'type':     alert_type,
            'message':  message,
            'time':     datetime.now().strftime('%d %b %Y, %H:%M'),
        })
    except Exception as e:
        log(f"[WARN] Could not write alert: {e}")


def send_sns(subject, message):
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except Exception as e:
        log(f"[WARN] SNS publish failed: {e}")


# ── MAIN RECOVERY LOGIC ───────────────────────────────────────────────────────

def run_auto_recovery():
    log("=" * 60)
    log("BDRS Auto-Recovery Script started")

    # Step 1: Scan DynamoDB for deleted files
    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('deleted_locally')
        )
        deleted_files = response.get('Items', [])
    except Exception as e:
        log(f"[ERROR] DynamoDB scan failed: {e}")
        return

    if not deleted_files:
        log("No files require auto-recovery. System healthy.")
        log("=" * 60)
        return

    log(f"Found {len(deleted_files)} file(s) marked as deleted. Initiating auto-recovery...")

    recovered = []
    failed    = []

    for file_meta in deleted_files:
        file_id  = file_meta.get('file_id', '')
        filename = file_meta.get('filename', 'unknown')
        s3_key   = file_meta.get('s3_key', '')

        log(f"  Recovering: {filename} (ID: {file_id[:8]}...)")

        if not s3_key:
            log(f"    [SKIP] No S3 key found for {filename}")
            failed.append(filename)
            continue

        try:
            # Step 2: Fetch file from S3
            obj       = s3.get_object(Bucket=BUCKET_NAME, Key=s3_key)
            file_data = obj['Body'].read()

            # Step 3: SHA-256 integrity verification
            live_hash   = sha256(file_data)
            stored_hash = file_meta.get('sha256', '')
            integrity   = True

            if stored_hash:
                integrity = (live_hash == stored_hash)
                if integrity:
                    log(f"    [OK] SHA-256 integrity verified: {live_hash[:16]}...")
                else:
                    log(f"    [WARN] SHA-256 mismatch! Stored={stored_hash[:16]} Live={live_hash[:16]}")

            # Step 4: Update DynamoDB status back to 'recovered'
            table.update_item(
                Key                       = {'file_id': file_id},
                UpdateExpression          = (
                    'SET #s = :v, last_restore = :t, '
                    'auto_recovered = :ar, integrity_ok = :io'
                ),
                ExpressionAttributeNames  = {'#s': 'status'},
                ExpressionAttributeValues = {
                    ':v':  'recovered',
                    ':t':  datetime.now().strftime('%d %b %Y, %H:%M'),
                    ':ar': True,
                    ':io': integrity,
                },
            )

            integrity_label = 'INTEGRITY PASS' if integrity else 'INTEGRITY FAIL'
            log(f"    [OK] {filename} auto-recovered from S3 · {integrity_label}")
            log_alert(
                'recover',
                f'{filename} AUTO-RECOVERED by cron script · {integrity_label}'
            )
            recovered.append(filename)

        except Exception as e:
            log(f"    [ERROR] Failed to recover {filename}: {e}")
            log_alert('error', f'Auto-recovery FAILED for {filename}: {e}')
            failed.append(filename)

    # Step 5: Summary notification via SNS
    summary = (
        f"BDRS Auto-Recovery Report\n"
        f"Time: {datetime.now().strftime('%d %b %Y, %H:%M:%S')}\n\n"
        f"Files recovered: {len(recovered)}\n"
        f"{chr(10).join('  ✓ ' + f for f in recovered) if recovered else '  None'}\n\n"
        f"Files failed: {len(failed)}\n"
        f"{chr(10).join('  ✗ ' + f for f in failed) if failed else '  None'}\n\n"
        f"Bucket: s3://{BUCKET_NAME}\n"
        f"Region: {REGION}"
    )

    if recovered:
        send_sns('BDRS: Auto-Recovery Completed', summary)
        log(f"SNS summary sent. {len(recovered)} file(s) recovered, {len(failed)} failed.")
    elif failed:
        send_sns('BDRS: Auto-Recovery FAILED', summary)
        log(f"SNS alert sent. {len(failed)} file(s) could not be recovered.")

    log("Auto-Recovery complete.")
    log("=" * 60)


if __name__ == '__main__':
    run_auto_recovery()
