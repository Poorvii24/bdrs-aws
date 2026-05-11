from flask import (Flask, render_template, request, redirect,
                   url_for, send_file, flash, jsonify, Response)
import boto3
import uuid
import hashlib
import base64
import mimetypes
from datetime import datetime
from io import BytesIO
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'bdrs-secret-key-2025'

REGION        = 'ap-south-1'
BUCKET_NAME   = 'bdrs-backup-1si23ad037'
DYNAMO_TABLE  = 'bdrs-metadata'
ALERTS_TABLE  = 'bdrs-alerts-log'
SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:060768937126:bdrs-alerts'

s3       = boto3.client('s3',       region_name=REGION)
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns      = boto3.client('sns',      region_name=REGION)
table    = dynamodb.Table(DYNAMO_TABLE)


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_alerts(limit=8):
    try:
        items = dynamodb.Table(ALERTS_TABLE).scan().get('Items', [])
        items.sort(key=lambda x: x.get('time', ''), reverse=True)
        return items[:limit]
    except Exception:
        return []


def get_all_alerts():
    """Return ALL alerts with DynamoDB pagination — used for audit log page."""
    try:
        all_items = []
        kwargs = {}
        while True:
            resp = dynamodb.Table(ALERTS_TABLE).scan(**kwargs)
            all_items.extend(resp.get('Items', []))
            last = resp.get('LastEvaluatedKey')
            if not last:
                break
            kwargs['ExclusiveStartKey'] = last
        all_items.sort(key=lambda x: x.get('time', ''), reverse=True)
        return all_items
    except Exception as e:
        print(f'[BDRS ERROR] get_all_alerts failed: {e}')
        return []


def log_alert(alert_type, message):
    try:
        dynamodb.Table(ALERTS_TABLE).put_item(Item={
            'alert_id': str(uuid.uuid4()),
            'type':     alert_type,
            'message':  message,
            'time':     datetime.now().strftime('%d %b %Y, %H:%M'),
        })
    except Exception:
        pass


def compute_stats(files):
    total_bytes = disaster = recovered = 0
    for f in files:
        try:
            total_bytes += int(f.get('file_size_bytes', 0))
        except Exception:
            try:
                total_bytes += int(
                    str(f.get('file_size', '0'))
                    .replace(' bytes', '').replace(',', '')
                )
            except Exception:
                pass
        if f.get('status') == 'deleted_locally':
            disaster += 1
        if f.get('status') == 'recovered':
            recovered += 1

    if total_bytes < 1024:
        size_str = f"{total_bytes} B"
    elif total_bytes < 1024 ** 2:
        size_str = f"{total_bytes / 1024:.1f} KB"
    else:
        size_str = f"{total_bytes / 1024**2:.2f} MB"

    pct = round(min(total_bytes / (5 * 1024**3) * 100, 100), 4)
    return size_str, pct, disaster, recovered, pct >= 70


def compute_chart_data(files, all_alerts):
    """Real chart data — bar chart from alerts, doughnut from file statuses."""
    from datetime import timedelta
    today = datetime.now().date()
    labels, backups_per_day, recoveries_per_day = [], [], []

    day_counts = defaultdict(lambda: defaultdict(int))
    for a in all_alerts:
        try:
            dt = datetime.strptime(a['time'], '%d %b %Y, %H:%M').date()
            day_counts[dt][a.get('type', '')] += 1
        except Exception:
            pass

    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        labels.append(d.strftime('%a').upper()[:3])
        backups_per_day.append(day_counts[d].get('backup', 0))
        recoveries_per_day.append(day_counts[d].get('recover', 0))

    status_counts = defaultdict(int)
    for f in files:
        status_counts[f.get('status', 'backed_up')] += 1

    active   = status_counts['backed_up']
    deleted  = status_counts['deleted_locally']
    rec_c    = status_counts['recovered']
    archived = status_counts['archived']
    free_slot = max(10 - len(files), 1)

    integrity_pass = sum(
        1 for f in files
        if str(f.get('integrity_ok', '')).lower() in ('true', '1')
    )

    return (labels, backups_per_day, recoveries_per_day,
            active, deleted, rec_c, archived, free_slot, integrity_pass)


# ─── MAIN INDEX ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    files  = sorted(table.scan().get('Items', []),
                    key=lambda x: x.get('upload_time', ''), reverse=True)
    alerts = get_alerts()
    total_size, storage_percent, disaster_count, recovered_count, quota_warning = compute_stats(files)

    all_alerts_for_chart = get_all_alerts()
    (chart_labels, chart_backups, chart_recoveries,
     chart_active, chart_deleted, chart_recovered,
     chart_archived, chart_free,
     chart_integrity_pass) = compute_chart_data(files, all_alerts_for_chart)

    # collect all unique tags from DynamoDB for the tag filter UI
    all_tags = sorted({
        tag for f in files
        for tag in (f.get('tags') or [])
    })

    return render_template('index.html',
        files               = files,
        alerts              = alerts,
        total_size          = total_size,
        storage_percent     = storage_percent,
        disaster_count      = disaster_count,
        recovered_count     = recovered_count,
        quota_warning       = quota_warning,
        chart_labels        = chart_labels,
        chart_backups       = chart_backups,
        chart_recoveries    = chart_recoveries,
        chart_active        = chart_active,
        chart_deleted       = chart_deleted,
        chart_recovered     = chart_recovered,
        chart_archived      = chart_archived,
        chart_free          = chart_free,
        chart_integrity_pass= chart_integrity_pass,
        all_tags            = all_tags,
    )


# ── BATCH UPLOAD ──────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_files = request.files.getlist('file')
    if not uploaded_files or uploaded_files[0].filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index'))

    tags_raw = request.form.get('tags', '').strip()
    tags = [t.strip() for t in tags_raw.split(',') if t.strip()] if tags_raw else []

    success_names = []
    for file in uploaded_files:
        if not file or file.filename == '':
            continue

        file_id     = str(uuid.uuid4())
        filename    = file.filename
        file_data   = file.read()
        file_size   = len(file_data)
        file_hash   = sha256_hash(file_data)
        upload_time = datetime.now().strftime('%d %b %Y, %H:%M')
        s3_key      = f"uploads/{file_id}_{filename}"
        mime_type   = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

        s3.put_object(
            Bucket               = BUCKET_NAME,
            Key                  = s3_key,
            Body                 = file_data,
            ServerSideEncryption = 'AES256',
            ContentType          = mime_type,
        )

        item = {
            'file_id':         file_id,
            'filename':        filename,
            'file_size':       f"{file_size} bytes",
            'file_size_bytes': file_size,
            'upload_time':     upload_time,
            's3_key':          s3_key,
            'status':          'backed_up',
            'sha256':          file_hash,
            'mime_type':       mime_type,
        }
        if tags:
            item['tags'] = tags

        table.put_item(Item=item)
        log_alert('backup', f'{filename} backed up to S3 · {file_size} bytes')

        try:
            sns.publish(
                TopicArn = SNS_TOPIC_ARN,
                Subject  = 'BDRS: New File Backed Up',
                Message  = (
                    f'File "{filename}" backed up successfully.\n'
                    f'Time: {upload_time}\nSize: {file_size} bytes\n'
                    f'SHA-256: {file_hash}\nTags: {", ".join(tags) or "none"}\n'
                    f'Location: s3://{BUCKET_NAME}/{s3_key}'
                ),
            )
        except Exception as e:
            print(f"SNS error: {e}")

        success_names.append(filename)

    if len(success_names) == 1:
        flash(f'"{success_names[0]}" backed up successfully!', 'success')
    elif len(success_names) > 1:
        flash(f'{len(success_names)} files backed up successfully!', 'success')
    else:
        flash('No valid files were uploaded.', 'error')

    return redirect(url_for('index'))


# ── RESTORE ───────────────────────────────────────────────────────────────────

@app.route('/download/<file_id>')
def download(file_id):
    item = table.get_item(Key={'file_id': file_id}).get('Item')
    if not item:
        flash('File not found in backup.', 'error')
        return redirect(url_for('index'))

    file_data     = s3.get_object(Bucket=BUCKET_NAME, Key=item['s3_key'])['Body'].read()
    restored_hash = sha256_hash(file_data)
    stored_hash   = item.get('sha256', '')
    integrity_ok  = (restored_hash == stored_hash) if stored_hash else True

    table.update_item(
        Key                       = {'file_id': file_id},
        UpdateExpression          = 'SET #s = :v, last_restore = :t, integrity_ok = :i',
        ExpressionAttributeNames  = {'#s': 'status'},
        ExpressionAttributeValues = {
            ':v': 'recovered',
            ':t': datetime.now().strftime('%d %b %Y, %H:%M'),
            ':i': integrity_ok,
        },
    )

    label = 'INTEGRITY PASS' if integrity_ok else 'INTEGRITY FAIL'
    log_alert('recover', f'{item["filename"]} restored · {label}')

    if not integrity_ok:
        flash(f'WARNING: Integrity check FAILED for "{item["filename"]}"!', 'error')

    return send_file(BytesIO(file_data), download_name=item['filename'], as_attachment=True)


# ── DISASTER SIMULATION ───────────────────────────────────────────────────────

@app.route('/delete/<file_id>')
def delete(file_id):
    item = table.get_item(Key={'file_id': file_id}).get('Item')
    if item:
        table.update_item(
            Key                       = {'file_id': file_id},
            UpdateExpression          = 'SET #s = :v',
            ExpressionAttributeNames  = {'#s': 'status'},
            ExpressionAttributeValues = {':v': 'deleted_locally'},
        )
        log_alert('disaster', f'{item["filename"]} — disaster simulated (deleted locally)')
        flash(f'Disaster simulated: "{item["filename"]}" marked as deleted.', 'error')
    return redirect(url_for('index'))


# ── FILE TAGGING ──────────────────────────────────────────────────────────────

@app.route('/tag/<file_id>', methods=['POST'])
def tag_file(file_id):
    """Add/replace tags on a file. Accepts JSON: {"tags": ["tag1","tag2"]}"""
    try:
        data = request.get_json()
        tags = [t.strip() for t in data.get('tags', []) if t.strip()]
        table.update_item(
            Key                       = {'file_id': file_id},
            UpdateExpression          = 'SET tags = :t',
            ExpressionAttributeValues = {':t': tags},
        )
        log_alert('tag', f'File {file_id[:8]}… tagged: {", ".join(tags)}')
        return jsonify({'ok': True, 'tags': tags})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ── FILE PREVIEW ──────────────────────────────────────────────────────────────

@app.route('/preview/<file_id>')
def preview(file_id):
    """
    Returns JSON with a base64-encoded preview payload for images and PDFs.
    The frontend renders these inline — no file download needed.
    """
    try:
        item = table.get_item(Key={'file_id': file_id}).get('Item')
        if not item:
            return jsonify({'error': 'File not found'}), 404

        mime = item.get('mime_type', '')
        # Only serve preview for images and PDFs
        previewable = (
            mime.startswith('image/')
            or mime == 'application/pdf'
        )
        if not previewable:
            return jsonify({'previewable': False, 'mime': mime})

        file_data = s3.get_object(Bucket=BUCKET_NAME, Key=item['s3_key'])['Body'].read()
        b64       = base64.b64encode(file_data).decode('utf-8')

        return jsonify({
            'previewable': True,
            'mime':        mime,
            'filename':    item['filename'],
            'data':        b64,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── INTEGRITY CHECK ───────────────────────────────────────────────────────────

@app.route('/integrity/<file_id>')
def integrity_check(file_id):
    try:
        item = table.get_item(Key={'file_id': file_id}).get('Item')
        if not item:
            return jsonify({'ok': False, 'error': 'File not found'}), 404

        file_data = s3.get_object(Bucket=BUCKET_NAME, Key=item['s3_key'])['Body'].read()
        live_hash = sha256_hash(file_data)
        stored    = item.get('sha256', '')

        if not stored:
            return jsonify({'ok': None, 'message': 'No stored hash', 'live_hash': live_hash})

        match = live_hash == stored
        table.update_item(
            Key                       = {'file_id': file_id},
            UpdateExpression          = 'SET integrity_ok = :i',
            ExpressionAttributeValues = {':i': match},
        )
        return jsonify({
            'ok':          match,
            'stored_hash': stored,
            'live_hash':   live_hash,
            'filename':    item['filename'],
            'message':     'Hash match — file intact' if match else 'Hash mismatch — possible corruption!',
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ── VERSION HISTORY ───────────────────────────────────────────────────────────

@app.route('/versions/<file_id>')
def versions(file_id):
    try:
        item = table.get_item(Key={'file_id': file_id}).get('Item')
        if not item:
            return jsonify({'error': 'File not found'}), 404

        paginator = s3.get_paginator('list_object_versions')
        ver_list  = []
        for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=item['s3_key']):
            for v in page.get('Versions', []):
                ver_list.append({
                    'version_id':    v['VersionId'],
                    'last_modified': v['LastModified'].strftime('%d %b %Y, %H:%M'),
                    'size':          v['Size'],
                    'is_latest':     v['IsLatest'],
                })
        ver_list.sort(key=lambda x: x['last_modified'], reverse=True)
        return jsonify({'filename': item['filename'], 'versions': ver_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/restore_version/<file_id>/<version_id>')
def restore_version(file_id, version_id):
    try:
        item = table.get_item(Key={'file_id': file_id}).get('Item')
        if not item:
            flash('File not found.', 'error')
            return redirect(url_for('index'))
        file_data = s3.get_object(
            Bucket=BUCKET_NAME, Key=item['s3_key'], VersionId=version_id
        )['Body'].read()
        log_alert('recover', f'{item["filename"]} version {version_id[:8]}… restored')
        return send_file(BytesIO(file_data), download_name=item['filename'], as_attachment=True)
    except Exception as e:
        flash(f'Version restore failed: {e}', 'error')
        return redirect(url_for('index'))


# ── POINT-IN-TIME RESTORE ─────────────────────────────────────────────────────

@app.route('/pitr', methods=['POST'])
def pitr():
    try:
        data       = request.get_json()
        target_str = data.get('timestamp', '')
        target_dt  = datetime.strptime(target_str, '%d %b %Y, %H:%M')

        all_files = table.scan().get('Items', [])
        matched   = []
        for f in all_files:
            try:
                ft = datetime.strptime(f.get('upload_time', ''), '%d %b %Y, %H:%M')
                if ft <= target_dt:
                    matched.append({
                        'file_id':     f['file_id'],
                        'filename':    f['filename'],
                        'upload_time': f['upload_time'],
                        'file_size':   f.get('file_size', ''),
                        'status':      f.get('status', ''),
                    })
            except Exception:
                pass

        matched.sort(key=lambda x: x['upload_time'], reverse=True)
        log_alert('pitr', f'PITR query at {target_str} · {len(matched)} files matched')
        return jsonify({'count': len(matched), 'files': matched})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── AUDIT LOG PAGE ────────────────────────────────────────────────────────────

@app.route('/audit')
def audit_log():
    """Dedicated full-page audit log with all events from DynamoDB."""
    all_alerts = get_all_alerts()
    # compute summary counts
    counts = defaultdict(int)
    for a in all_alerts:
        counts[a.get('type', 'other')] += 1
    return render_template('audit.html',
        alerts        = all_alerts,
        total         = len(all_alerts),
        backup_count  = counts['backup'],
        recover_count = counts['recover'],
        disaster_count= counts['disaster'],
        pitr_count    = counts['pitr'],
        tag_count     = counts['tag'],
        ALERTS_TABLE  = ALERTS_TABLE,
    )


# ── DEBUG: RAW AUDIT DATA ─────────────────────────────────────────────────────

@app.route('/debug/alerts')
def debug_alerts():
    """Debug endpoint — shows raw DynamoDB alerts as JSON. Remove before production."""
    try:
        items = dynamodb.Table(ALERTS_TABLE).scan().get('Items', [])
        counts = defaultdict(int)
        for a in items:
            counts[a.get('type', 'other')] += 1
        return jsonify({
            'table':   ALERTS_TABLE,
            'total':   len(items),
            'counts':  dict(counts),
            'sample':  items[:3],
        })
    except Exception as e:
        return jsonify({'error': str(e), 'table': ALERTS_TABLE}), 500


# ── CHART DATA JSON ENDPOINT ──────────────────────────────────────────────────

@app.route('/chart-data')
def chart_data():
    """Returns real chart data as JSON — consumed by the frontend charts."""
    try:
        files      = table.scan().get('Items', [])
        all_alerts = get_all_alerts()
        (labels, backups, recoveries,
         active, deleted, recovered, archived, free_slot,
         integrity_pass) = compute_chart_data(files, all_alerts)
        counts = defaultdict(int)
        for a in all_alerts:
            counts[a.get('type', 'other')] += 1
        return jsonify({
            'labels':      labels,
            'backups':     backups,
            'recoveries':  recoveries,
            'active':      active,
            'deleted':     deleted,
            'recovered':   recovered,
            'archived':    archived,
            'free':        free_slot,
            'total_events': len(all_alerts),
            'backup_count': counts['backup'],
            'recover_count': counts['recover'],
            'disaster_count': counts['disaster'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── AUDIT COUNTS (live refresh) ───────────────────────────────────────────────

@app.route('/audit/counts')
def audit_counts():
    """Live audit summary counts for 30-second auto-refresh on audit page."""
    try:
        all_alerts = get_all_alerts()
        counts = defaultdict(int)
        for a in all_alerts:
            counts[a.get('type', 'other')] += 1
        return jsonify({
            'total':    len(all_alerts),
            'backup':   counts['backup'],
            'recover':  counts['recover'],
            'disaster': counts['disaster'],
            'other':    counts['pitr'] + counts['tag'] + counts['sns'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── SNS SUBSCRIPTION MANAGEMENT ──────────────────────────────────────────────

@app.route('/notifications')
def notifications():
    """List current SNS subscriptions for bdrs-alerts topic."""
    try:
        resp  = sns.list_subscriptions_by_topic(TopicArn=SNS_TOPIC_ARN)
        subs  = resp.get('Subscriptions', [])
        return jsonify({'subscriptions': subs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/notifications/subscribe', methods=['POST'])
def subscribe():
    """Subscribe an email to SNS alerts."""
    data  = request.get_json()
    email = data.get('email', '').strip()
    if not email or '@' not in email:
        return jsonify({'ok': False, 'error': 'Invalid email'}), 400
    try:
        sns.subscribe(TopicArn=SNS_TOPIC_ARN, Protocol='email', Endpoint=email)
        log_alert('sns', f'New SNS subscription requested for {email}')
        return jsonify({'ok': True, 'message': f'Confirmation email sent to {email}. Check inbox to confirm.'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/notifications/unsubscribe', methods=['POST'])
def unsubscribe():
    """Unsubscribe using the subscription ARN."""
    data = request.get_json()
    arn  = data.get('subscription_arn', '')
    if not arn:
        return jsonify({'ok': False, 'error': 'No subscription ARN provided'}), 400
    try:
        sns.unsubscribe(SubscriptionArn=arn)
        log_alert('sns', f'SNS subscription {arn[:30]}… removed')
        return jsonify({'ok': True, 'message': 'Unsubscribed successfully.'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
