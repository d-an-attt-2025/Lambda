import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config

# ==========================
# ENV
# ==========================
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
INCIDENT_TABLE_NAME = os.environ["INCIDENT_TABLE"]
BEDROCK_MODEL_ID = os.environ["BEDROCK_MODEL_ID"].strip()  # ví dụ: anthropic.claude-3-haiku-20240307-v1:0

SES_FROM = os.environ["SES_FROM"]
SES_TO = os.environ["SES_TO"]
BLOCK_IP_BASE_URL = os.environ.get("BLOCK_IP_BASE_URL", "https://example.com/block-ip")

# Log group thật chứa log ứng dụng
LOG_GROUP_NAME = os.environ["LOG_GROUP_NAME"]
LOG_TIME_WINDOW_MINUTES = int(os.environ.get("LOG_TIME_WINDOW_MINUTES", "5"))

# ==========================
# AWS clients
# ==========================
dynamodb = boto3.resource("dynamodb", region_name=REGION)
incident_table = dynamodb.Table(INCIDENT_TABLE_NAME)

bedrock = boto3.client(
    "bedrock-runtime",
    region_name=REGION,
    config=Config(read_timeout=60, retries={"max_attempts": 3}),
)

ses = boto3.client("ses", region_name=REGION)

logs_client = boto3.client(
    "logs",
    region_name=REGION,
    config=Config(read_timeout=10, retries={"max_attempts": 3}),
)


def lambda_handler(event, context):
    print("=== RAW EVENT ===")
    print(json.dumps(event))

    print(f"ENV MODEL={BEDROCK_MODEL_ID} REGION={REGION}")
    print(f"LOG_GROUP_NAME={LOG_GROUP_NAME} WINDOW_MIN={LOG_TIME_WINDOW_MINUTES}")

    alarm_name = event.get("alarmData", {}).get("alarmName", "UNKNOWN_ALARM")
    event_time_str = event.get("time", "")

    # 1) Lấy log thật từ CloudWatch Logs xung quanh thời điểm alarm
    logs_text = fetch_logs_around_time(event_time_str)

    if not logs_text:
        print("Không tìm thấy log trong cửa sổ thời gian, dùng message placeholder.")
        logs_text = "NO_LOGS_FOUND in the configured time window."

    # 2) Gọi Bedrock để phân tích
    analysis = analyze_with_bedrock(alarm_name, event_time_str, logs_text)

    print("=== ANALYSIS ===")
    print(json.dumps(analysis, ensure_ascii=False))

    suspected_ips = analysis.get("suspected_ips") or ["1.2.3.4"]

    # 3) Lưu incident vào DynamoDB
    incident_id = save_incident_to_dynamodb(
        alarm_name, event_time_str, suspected_ips
    )

    # 4) Gửi email cho người dùng
    try:
        send_incident_email(
            incident_id=incident_id,
            alarm_name=alarm_name,
            event_time=event_time_str,
            suspected_ips=suspected_ips,
            analysis=analysis,
        )
    except Exception as e:
        print(f"Error when sending SES email: {e}")

    return {
        "status": "OK",
        "incidentId": incident_id,
        "alarmName": alarm_name,
        "ips": suspected_ips,
        "analysis": analysis,
    }


# ==========================
# FETCH REAL LOGS FROM CLOUDWATCH
# ==========================
def fetch_logs_around_time(event_time_str: str) -> str:
    """
    Lấy log từ CloudWatch Logs quanh thời điểm alarm:
    - Trong LOG_TIME_WINDOW_MINUTES trước và sau event_time.
    - Ghép tất cả message thành 1 string để gửi cho Bedrock.
    """

    # Parse thời gian alarm
    # Ví dụ: "2025-12-09T00:00:00+00:00"
    try:
        if event_time_str.endswith("Z"):
            event_time_str_fixed = event_time_str.replace("Z", "+00:00")
        else:
            event_time_str_fixed = event_time_str

        dt = datetime.fromisoformat(event_time_str_fixed)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception as e:
        print(f"Không parse được event_time '{event_time_str}', dùng now(): {e}")
        dt = datetime.now(timezone.utc)

    center_ms = int(dt.timestamp() * 1000)
    window_ms = LOG_TIME_WINDOW_MINUTES * 60 * 1000

    start_time = center_ms - window_ms
    end_time = center_ms + window_ms

    print(f"Fetching logs from {start_time} to {end_time} (ms)")

    messages = []
    next_token = None

    while True:
        kwargs = {
            "logGroupName": LOG_GROUP_NAME,
            "startTime": start_time,
            "endTime": end_time,
            "limit": 1000,
        }
        if next_token:
            kwargs["nextToken"] = next_token

        resp = logs_client.filter_log_events(**kwargs)

        for ev in resp.get("events", []):
            msg = ev.get("message", "").rstrip()
            if msg:
                messages.append(msg)

        next_token = resp.get("nextToken")
        if not next_token:
            break

    print(f"Fetched {len(messages)} log lines from CloudWatch")
    return "\n".join(messages)


# ==========================
# CALL BEDROCK (CLAUDE 3)
# ==========================
def analyze_with_bedrock(alarm_name: str, event_time: str, logs_text: str) -> dict:
    prompt = f"""
Bạn là hệ thống phân tích log tự động.

Hãy phân tích log và trả về JSON DUY NHẤT dạng:

{{
  "summary": "tóm tắt ngắn gọn",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommendations": ["..."],
  "suspected_ips": ["1.2.3.4"]
}}

Yêu cầu:
- Nếu thấy nhiều lần đăng nhập thất bại (HTTP 401/403) trong thời gian ngắn từ cùng một IP tới /login hoặc endpoint authentication,
  hãy coi đó là brute force tấn công mật khẩu.
- Trong trường hợp brute force rõ ràng, hãy đặt severity ít nhất là HIGH.
- Trong suspected_ips, hãy đưa các IP nghi vấn brute force hoặc tấn công vào.

Alarm: {alarm_name}
Time: {event_time}

Log:
----------------
{logs_text}
----------------
"""

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt}
                ],
            }
        ],
    }

    print(f"[Bedrock] Calling model: {BEDROCK_MODEL_ID}")

    try:
        resp = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body),
        )

        resp_json = json.loads(resp["body"].read())

        print("=== RAW CLAUDE RESPONSE ===")
        print(json.dumps(resp_json, ensure_ascii=False))

        # Claude 3 format: content là list block
        content_blocks = resp_json.get("content", [])

        raw_output = ""
        for block in content_blocks:
            if block.get("type") == "text":
                raw_output += block.get("text", "")

        raw_output = raw_output.strip()

        print("=== PARSED OUTPUT ===")
        print(raw_output)

        return json.loads(raw_output)

    except Exception as e:
        print("Bedrock error:", e)
        return {
            "summary": "Fallback do Bedrock lỗi",
            "severity": "HIGH",
            "recommendations": ["Kiểm tra Bedrock", str(e)],
            "suspected_ips": ["1.2.3.4", "5.6.7.8"],
        }


# ==========================
# SAVE INCIDENT TO DDB
# ==========================
def save_incident_to_dynamodb(alarm_name: str, event_time: str, ips: list) -> str:
    incident_id = str(uuid.uuid4())
    now_epoch = int(time.time())
    ttl_epoch = now_epoch + 7 * 24 * 3600

    for ip in ips:
        item = {
            "incidentId": incident_id,
            "ip": ip,
            "alarmName": alarm_name,
            "alarmTime": event_time,
            "status": "PENDING",
            "createdAt": now_epoch,
            "ttl": ttl_epoch,
        }
        print("PutItem:", item)
        incident_table.put_item(Item=item)

    return incident_id


# ==========================
# SEND EMAIL VIA SES
# ==========================
def send_incident_email(
    incident_id: str,
    alarm_name: str,
    event_time: str,
    suspected_ips: list,
    analysis: dict,
) -> None:
    summary = analysis.get("summary", "")
    severity = analysis.get("severity", "UNKNOWN")
    recommendations = analysis.get("recommendations", [])

    subject = f"[MLSA] Incident {incident_id[:8]} - {severity}"

    # Tạo link block IP
    block_links = []
    for ip in suspected_ips:
        link = f"{BLOCK_IP_BASE_URL}?incidentId={incident_id}&ip={ip}"
        block_links.append(f"- {ip}: {link}")

    body_lines = [
        f"Alarm name : {alarm_name}",
        f"Time       : {event_time}",
        f"IncidentId : {incident_id}",
        "",
        f"Severity   : {severity}",
        "",
        "Summary:",
        summary,
        "",
        "Suspected IPs:",
        *([*block_links] if block_links else ["- (none)"]),
        "",
        "Recommendations:",
    ]

    if recommendations:
        for idx, rec in enumerate(recommendations, start=1):
            body_lines.append(f"{idx}. {rec}")
    else:
        body_lines.append("- (none)")

    body_text = "\n".join(body_lines)

    print("=== SES EMAIL BODY ===")
    print(body_text)

    ses.send_email(
        Source=SES_FROM,
        Destination={"ToAddresses": [SES_TO]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": body_text, "Charset": "UTF-8"},
            },
        },
    )

    print(f"Email sent to {SES_TO} for incident {incident_id}")
