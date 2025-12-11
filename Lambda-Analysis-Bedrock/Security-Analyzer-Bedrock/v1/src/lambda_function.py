import json
import os
import time
import uuid

import boto3
from botocore.config import Config

# ==========================
# ENV
# ==========================
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
INCIDENT_TABLE_NAME = os.environ["INCIDENT_TABLE"]
BEDROCK_MODEL_ID = os.environ["BEDROCK_MODEL_ID"].strip()    # ví dụ: anthropic.claude-3-haiku-20240307-v1:0

# ==========================
# AWS clients
# ==========================
dynamodb = boto3.resource("dynamodb", region_name=REGION)
incident_table = dynamodb.Table(INCIDENT_TABLE_NAME)

bedrock = boto3.client(
    "bedrock-runtime",
    region_name=REGION,
    config=Config(read_timeout=60, retries={"max_attempts": 3})
)


def lambda_handler(event, context):
    print("=== RAW EVENT ===")
    print(json.dumps(event))

    print(f"ENV MODEL={BEDROCK_MODEL_ID} REGION={REGION}")

    alarm_name = event.get("alarmData", {}).get("alarmName", "UNKNOWN_ALARM")
    event_time_str = event.get("time", "")

    # Dummy log sample
    dummy_logs = (
        "2025-12-09T00:00:01Z 1.2.3.4 GET /login 200\n"
        "2025-12-09T00:00:02Z 1.2.3.4 GET /login 200\n"
        "2025-12-09T00:00:03Z 5.6.7.8 POST /api/order 500\n"
    )

    analysis = analyze_with_bedrock(alarm_name, event_time_str, dummy_logs)

    print("=== ANALYSIS ===")
    print(json.dumps(analysis, ensure_ascii=False))

    suspected_ips = analysis.get("suspected_ips") or ["1.2.3.4"]

    incident_id = save_incident_to_dynamodb(
        alarm_name, event_time_str, suspected_ips
    )

    return {
        "status": "OK",
        "incidentId": incident_id,
        "alarmName": alarm_name,
        "ips": suspected_ips,
        "analysis": analysis,
    }


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

Alarm: {alarm_name}
Time: {event_time}

Log:
----------------
{logs_text}
----------------
"""

    # FIXED: đúng định dạng Claude 3
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt}
                ]
            }
        ]
    }

    print(f"[Bedrock] Calling model: {BEDROCK_MODEL_ID}")

    try:
        resp = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body)
        )

        resp_json = json.loads(resp["body"].read())

        print("=== RAW CLAUDE RESPONSE ===")
        print(json.dumps(resp_json, ensure_ascii=False))

        # Claude 3 format
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
def save_incident_to_dynamodb(alarm_name: str, event_time: str, ips: list):
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
