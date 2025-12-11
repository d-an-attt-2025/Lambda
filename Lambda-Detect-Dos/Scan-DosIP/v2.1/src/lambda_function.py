import json, gzip, base64, boto3, os, time
import re
from collections import Counter

# ==========================
# AWS CLIENTS (CHUẨN REGION)
# ==========================
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.client("dynamodb", region_name=REGION)

# ======================
# ENVIRONMENT VARIABLES
# ======================
THRESHOLD = int(os.environ["THRESHOLD"])          # Ngưỡng gửi email
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]           # Email nhận cảnh báo
BLOCK_URL = os.environ["BLOCK_URL"]               # Lambda URL để block IP
DDB_TABLE = os.environ["DDB_TABLE"]               # Tên DynamoDB table
TTL_SECONDS = int(os.environ.get("TTL_SECONDS", "10800"))  # TTL: default 3 giờ

# ======================
# HELPER: Extract IPv4
# ======================
def extract_ip(msg: str):
    """Tách IPv4 từ log line."""
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", msg)
    return m.group(0) if m else None

# ======================
# CHECK DDB: Đã gửi email?
# ======================
def has_recent_alert(ip):
    try:
        resp = dynamodb.get_item(
            TableName=DDB_TABLE,
            Key={"ip": {"S": ip}}
        )
        return "Item" in resp
    except Exception as e:
        print("❌ DDB GetItem ERROR:", e)
        return False

# ============================
# LƯU IP vào DDB (TTL tự xoá)
# ============================
def mark_alert_sent(ip):
    expire_at = int(time.time()) + TTL_SECONDS
    try:
        dynamodb.put_item(
            TableName=DDB_TABLE,
            Item={
                "ip": {"S": ip},
                "expire_at": {"N": str(expire_at)}
            }
        )
        print(f"🕒 TTL set for {ip}: expire_at={expire_at}")
    except Exception as e:
        print("❌ DDB PutItem ERROR:", e)

# ============================
# SEND EMAIL (CHUẨN SES)
# ============================
def send_email(ip, count):
    link = f"{BLOCK_URL}?ip={ip}"

    body = f"""
⚠️ CẢNH BÁO IP nghi ngờ DoS

IP: {ip}
Số lượng request vượt ngưỡng: {count}
Ngưỡng hiện tại: {THRESHOLD}

➡ Nhấn để BLOCK IP ngay:  
{link}

(Hệ thống sẽ không gửi lại email này cho đến khi TTL hết hạn và IP tấn công lại.)
"""

    print(f"📧 Sending email for IP {ip} ({count} requests)...")

    try:
        ses.send_email(
            Source=ADMIN_EMAIL,
            Destination={"ToAddresses": [ADMIN_EMAIL]},
            Message={
                "Subject": {"Data": f"CẢNH BÁO DoS từ IP {ip}"},
                "Body": {"Text": {"Data": body}}
            }
        )
        print("✅ Email sent successfully!")

    except Exception as e:
        print("❌ SES ERROR:", e)

# ============================
# MAIN HANDLER
# ============================
def lambda_handler(event, context):
    print("=== SCAN LAMBDA START ===")

    # ---------------------------
    # Decode CloudWatch Logs
    # ---------------------------
    try:
        cw_data = event["awslogs"]["data"]
        payload = gzip.decompress(base64.b64decode(cw_data))
        data = json.loads(payload)
    except Exception as e:
        print("❌ ERROR decoding CloudWatch logs:", e)
        return

    log_events = data.get("logEvents", [])
    print(f"Decoded log event count: {len(log_events)}")

    # ---------------------------
    # Extract IPs
    # ---------------------------
    ips = []
    for log_event in log_events:
        msg = log_event["message"]
        ip = extract_ip(msg)
        if ip:
            ips.append(ip)

    print("Extracted IPs:", ips)

    counter = Counter(ips)
    print("IP frequency:", counter)

    # ---------------------------
    # CHECK NGƯỠNG & SEND EMAIL
    # ---------------------------
    for ip, count in counter.items():

        if count > THRESHOLD:
            print(f"⚠️ ALERT: {ip} vượt ngưỡng ({count}) > {THRESHOLD}")

            # Kiểm tra đã gửi email chưa
            if has_recent_alert(ip):
                print(f"⏭ SKIP: Email đã được gửi trước đó cho {ip} (TTL chưa hết)")
                continue

            # Gửi email cảnh báo
            send_email(ip, count)

            # Ghi vào DynamoDB để ko gửi lại
            mark_alert_sent(ip)

    print("=== SCAN LAMBDA END ===")
