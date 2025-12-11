import json, gzip, base64, boto3, os
import re
from collections import Counter

ses = boto3.client('ses')

THRESHOLD = int(os.environ['THRESHOLD'])
ADMIN_EMAIL = os.environ['ADMIN_EMAIL']
BLOCK_URL = os.environ['BLOCK_URL']

def extract_ip(msg):
    m = re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', msg)
    return m.group(0) if m else None

def lambda_handler(event, context):
    print("=== SCAN LAMBDA START ===")
    print("Incoming event:", event)

    # Decode CW logs
    cw_data = event['awslogs']['data']
    payload = gzip.decompress(base64.b64decode(cw_data))
    data = json.loads(payload)

    print("Decoded log event count:", len(data.get("logEvents", [])))

    ips = []
    for log_event in data['logEvents']:
        msg = log_event['message']
        ip = extract_ip(msg)
        if ip:
            ips.append(ip)

    print("Extracted IP list:", ips)

    counter = Counter(ips)
    print("IP frequency:", counter)

    for ip, count in counter.items():
        if count > THRESHOLD:
            print(f"⚠️ ALERT: IP {ip} vượt ngưỡng ({count}) > {THRESHOLD}")
            send_email(ip, count)

    print("=== SCAN LAMBDA END ===")


def send_email(ip, count):
    print(f"📧 Sending email for IP {ip} with {count} requests...")

    link = f"{BLOCK_URL}?ip={ip}"

    body = f"""
⚠️ CẢNH BÁO IP nghi ngờ DoS

IP: {ip}
Số lượng request trong burst: {count}

➡ BLOCK NOW: {link}

Nếu bạn không block → sẽ tiếp tục gửi cảnh báo.
"""

    ses.send_email(
        Source=ADMIN_EMAIL,
        Destination={'ToAddresses': [ADMIN_EMAIL]},
        Message={
            'Subject': {'Data': f'CẢNH BÁO DoS từ IP {ip}'},
            'Body': {'Text': {'Data': body}}
        }
    )

    print("✅ Email sent successfully!")
