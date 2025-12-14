import json, gzip, base64, boto3, os, time, re
from datetime import datetime, timezone

# ==========================
# AWS client
# ==========================
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
ddb = boto3.client("dynamodb", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)

# ==========================
# ENV
# ==========================
DDB_TABLE = os.environ["DDB_TABLE"]
THRESHOLD = int(os.environ["THRESHOLD"])
TTL_COUNTER = int(os.environ.get("TTL_COUNTER", "300"))      # TTL cho counter (5 phút)
TTL_EMAIL = int(os.environ.get("TTL_EMAIL", "21600"))        # TTL email 6 giờ
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
BLOCK_URL = os.environ["BLOCK_URL"]

# ==========================
# Extract IPv4 (fallback)
# ==========================
def extract_ip(msg: str):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", msg)
    return match.group(0) if match else None

# ==========================
# Parse WAF log để lấy IP, UA, country
# ==========================
def parse_waf_log(msg: str):
    """
    Thử parse message như JSON WAF log:
    - httpRequest.clientIp
    - httpRequest.country
    - httpRequest.headers[].(name == User-Agent).value
    """
    try:
        data = json.loads(msg)
    except Exception:
        return None, None, None

    http_req = data.get("httpRequest", {})
    ip = http_req.get("clientIp")
    geo_region = http_req.get("country")  # ví dụ: JP, US, VN

    user_agent = None
    for h in http_req.get("headers", []):
        name = h.get("name", "").lower()
        if name == "user-agent":
            user_agent = h.get("value")
            break

    return ip, user_agent, geo_region

# ==========================
# Format timestamp
# ==========================
def format_ts_utc(ts_ms: int) -> str:
    """CloudWatch gửi timestamp dạng epoch ms."""
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")

# ==========================
# SEND EMAIL (KHÔNG CÓ LOG MẪU, KHÔNG CỬA SỔ/LOGGROUP/LOGSTREAM)
# ==========================
def send_alert(ip, count, user_agent, geo_region, event_ts_ms):
    link = f"{BLOCK_URL}?ip={ip}"

    detected_at = format_ts_utc(event_ts_ms)

    # fallback nếu không có UA/region từ log
    if not user_agent:
        user_agent = "N/A"
    if not geo_region:
        geo_region = "N/A"

    body = f"""
🚨 CẢNH BÁO DoS ATTACK

Thời gian phát hiện: {detected_at}
AWS Region: {REGION}

IP tấn công: {ip}
Geo Region (country): {geo_region}
User-Agent: {user_agent}

Số lượng request trong cửa sổ: {count}
Ngưỡng cảnh báo: {THRESHOLD}

➡ Block IP ngay:
{link}

Thông tin hệ thống:
- TTL counter: {TTL_COUNTER} giây
- TTL email (thời gian không gửi lại cảnh báo cho IP này): {TTL_EMAIL} giây
"""

    ses.send_email(
        Source=ADMIN_EMAIL,
        Destination={"ToAddresses": [ADMIN_EMAIL]},
        Message={
            "Subject": {"Data": f"CẢNH BÁO DoS từ IP {ip}"},
            "Body": {"Text": {"Data": body}},
        },
    )
    print(f"📧 Email sent for {ip}")

# ==========================
# MAIN HANDLER
# ==========================
def lambda_handler(event, context):
    print("=== SCAN LAMBDA ===")

    # ==========================
    # Manual test (Lambda Console / Invoke trực tiếp)
    # ==========================
    if "awslogs" not in event:
        print("Manual test event (no awslogs).")
        msg = event.get("message", "")

        # Ưu tiên parse JSON WAF log
        ip, user_agent, geo_region = parse_waf_log(msg)

        # fallback regex IP
        if not ip:
            ip = extract_ip(msg)

        if not ip:
            print("No IP found in manual test event.")
            return {"status": "no_ip_found"}

        # Tạo timestamp giả lập
        event_ts_ms = int(time.time() * 1000)

        # ---- dùng lại đúng logic tăng counter + gửi email như luồng chính ----
        window = int(time.time() / TTL_COUNTER) * TTL_COUNTER
        pk = f"COUNT#{ip}"
        sk = f"WINDOW#{window}"
        expire = window + TTL_COUNTER

        try:
            resp = ddb.update_item(
                TableName=DDB_TABLE,
                Key={"pk": {"S": pk}, "sk": {"S": sk}},
                UpdateExpression="ADD #c :inc SET expire_at = :exp",
                ExpressionAttributeNames={"#c": "count"},
                ExpressionAttributeValues={
                    ":inc": {"N": "1"},
                    ":exp": {"N": str(expire)}
                },
                ReturnValues="UPDATED_NEW"
            )
            count = int(resp["Attributes"]["count"]["N"])
        except Exception as ex:
            print("❌ Counter update error:", ex)
            return {"status": "ddb_error"}

        print(f"[MANUAL] IP {ip} count={count}")

        if count == THRESHOLD + 1:
            print(f"🔥 First time exceeding threshold for {ip}")
            try:
                ddb.put_item(
                    TableName=DDB_TABLE,
                    Item={
                        "pk": {"S": f"EMAIL#{ip}"},
                        "sk": {"S": "SEND"},
                        "expire_at": {"N": str(int(time.time()) + TTL_EMAIL)}
                    },
                    ConditionExpression="attribute_not_exists(pk)"
                )
                send_alert(ip, count, user_agent, geo_region, event_ts_ms)

            except ddb.exceptions.ConditionalCheckFailedException:
                print(f"⏭ Email already sent for {ip}, skip")
            except Exception as ex:
                print("❌ Email lock error:", ex)

        print("=== END (MANUAL) ===")
        return {"status": "ok_manual", "ip": ip, "count": count}

    # ==========================
    # CloudWatch Logs subscription path (event có awslogs.data)
    # ==========================
    data = gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
    logs = json.loads(data)
    events = logs.get("logEvents", [])

    for e in events:
        msg = e["message"]

        ip, user_agent, geo_region = parse_waf_log(msg)
        if not ip:
            ip = extract_ip(msg)
        if not ip:
            continue

        event_ts_ms = e.get("timestamp", int(time.time() * 1000))

        window = int(time.time() / TTL_COUNTER) * TTL_COUNTER
        pk = f"COUNT#{ip}"
        sk = f"WINDOW#{window}"
        expire = window + TTL_COUNTER

        try:
            resp = ddb.update_item(
                TableName=DDB_TABLE,
                Key={"pk": {"S": pk}, "sk": {"S": sk}},
                UpdateExpression="ADD #c :inc SET expire_at = :exp",
                ExpressionAttributeNames={"#c": "count"},
                ExpressionAttributeValues={
                    ":inc": {"N": "1"},
                    ":exp": {"N": str(expire)}
                },
                ReturnValues="UPDATED_NEW"
            )
            count = int(resp["Attributes"]["count"]["N"])
        except Exception as ex:
            print("❌ Counter update error:", ex)
            continue

        print(f"IP {ip} count={count}")

        if count == THRESHOLD + 1:
            print(f"🔥 First time exceeding threshold for {ip}")

            try:
                ddb.put_item(
                    TableName=DDB_TABLE,
                    Item={
                        "pk": {"S": f"EMAIL#{ip}"},
                        "sk": {"S": "SEND"},
                        "expire_at": {"N": str(int(time.time()) + TTL_EMAIL)}
                    },
                    ConditionExpression="attribute_not_exists(pk)"
                )
                send_alert(ip, count, user_agent, geo_region, event_ts_ms)

            except ddb.exceptions.ConditionalCheckFailedException:
                print(f"⏭ Email already sent for {ip}, skip")
            except Exception as ex:
                print("❌ Email lock error:", ex)

    print("=== END ===")
    return {"status": "ok"}
