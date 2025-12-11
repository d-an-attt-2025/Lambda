import json, gzip, base64, boto3, os, time, re

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
# Extract IPv4
# ==========================
def extract_ip(msg: str):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", msg)
    return match.group(0) if match else None


# ==========================
# SEND EMAIL
# ==========================
def send_alert(ip, count):
    link = f"{BLOCK_URL}?ip={ip}"

    body = f"""
🚨 CẢNH BÁO DoS ATTACK

IP: {ip}
Số lượng request vượt ngưỡng: {count}
Ngưỡng: {THRESHOLD}

➡ Block IP ngay:
{link}

(Hệ thống sẽ không gửi lại email trong TTL {TTL_EMAIL} giây.)
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

    # Decode CloudWatch Logs
    data = gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
    logs = json.loads(data)
    events = logs.get("logEvents", [])

    for e in events:
        msg = e["message"]
        ip = extract_ip(msg)
        if not ip:
            continue

        # Window 5 phút
        window = int(time.time() / 300) * 300
        pk = f"COUNT#{ip}"
        sk = f"WINDOW#{window}"
        expire = window + TTL_COUNTER

        # ==========================
        # Increase counter (atomic)
        # ==========================
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

        # ============================================
        # Chỉ gửi email khi count == THRESHOLD + 1
        # ============================================
        if count == THRESHOLD + 1:
            print(f"🔥 First time exceeding threshold for {ip}")

            # ==========================
            # Atomic email-sent lock
            # ==========================
            try:
                ddb.put_item(
                    TableName=DDB_TABLE,
                    Item={
                        "pk": {"S": f"EMAIL#{ip}"},
                        "sk": {"S": "SEND"},
                        "expire_at": {"N": str(int(time.time()) + TTL_EMAIL)}
                    },
                    ConditionExpression="attribute_not_exists(pk)"  # LOCK
                )
                # Nếu tới đây → email chưa gửi → gửi ngay
                send_alert(ip, count)

            except ddb.exceptions.ConditionalCheckFailedException:
                print(f"⏭ Email already sent for {ip}, skip")

            except Exception as ex:
                print("❌ Email lock error:", ex)

    print("=== END ===")
    return {"status": "ok"}
