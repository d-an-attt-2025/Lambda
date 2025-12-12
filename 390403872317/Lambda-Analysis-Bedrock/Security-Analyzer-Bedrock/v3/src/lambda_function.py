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
BEDROCK_MODEL_ID = os.environ["BEDROCK_MODEL_ID"].strip()

SES_FROM = os.environ["SES_FROM"]
SES_TO = os.environ["SES_TO"]

BLOCK_IP_BASE_URL = os.environ.get("BLOCK_IP_BASE_URL", "https://example.com/block-ip")

LOG_GROUP_NAME = os.environ["LOG_GROUP_NAME"]
LOG_TIME_WINDOW_MINUTES = int(os.environ.get("LOG_TIME_WINDOW_MINUTES", "5"))

# Safety limits
MAX_LOG_CHARS = int(os.environ.get("MAX_LOG_CHARS", "50000"))
MAX_EVENTS_FOR_BEDROCK = int(os.environ.get("MAX_EVENTS_FOR_BEDROCK", "500"))

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

# ==========================
# Helpers
# ==========================
def _safe_json_dumps(obj) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)


def normalize_waf_log(raw_msg: str) -> str:
    """
    Nếu message là JSON WAF log -> rút gọn còn các field hữu ích để Bedrock hiểu nhanh.
    Nếu không parse được -> trả raw_msg để không mất dữ liệu.
    """
    try:
        data = json.loads(raw_msg)
        http_req = data.get("httpRequest", {}) or {}

        # User-Agent (nếu có)
        ua = None
        for h in (http_req.get("headers") or []):
            if (h.get("name") or "").lower() == "user-agent":
                ua = h.get("value")
                break

        out = {
            "timestamp": data.get("timestamp"),
            "formatVersion": data.get("formatVersion"),
            "webaclId": data.get("webaclId"),
            "action": data.get("action"),
            "terminatingRuleId": data.get("terminatingRuleId"),
            "terminatingRuleType": data.get("terminatingRuleType"),
            "httpSourceName": data.get("httpSourceName"),
            "httpSourceId": data.get("httpSourceId"),
            "rateBasedRuleList": data.get("rateBasedRuleList"),
            "nonTerminatingMatchingRules": data.get("nonTerminatingMatchingRules"),
            "httpRequest": {
                "clientIp": http_req.get("clientIp"),
                "country": http_req.get("country"),
                "httpMethod": http_req.get("httpMethod"),
                "uri": http_req.get("uri"),
                "args": http_req.get("args"),
                "httpVersion": http_req.get("httpVersion"),
                "requestId": http_req.get("requestId"),
                "scheme": http_req.get("scheme"),
                "host": http_req.get("host"),
                "userAgent": ua,
            },
        }

        # remove empty/null recursively
        def compact(x):
            if isinstance(x, dict):
                return {k: compact(v) for k, v in x.items() if v not in (None, "", [], {})}
            if isinstance(x, list):
                y = [compact(v) for v in x]
                return [v for v in y if v not in (None, "", [], {})]
            return x

        out = compact(out)
        return json.dumps(out, ensure_ascii=False)

    except Exception:
        return raw_msg


def parse_event_time(event_time_str: str) -> datetime:
    """
    Parse event['time'] của EventBridge/Alarm.
    Accept:
      - 2025-12-09T00:00:00Z
      - 2025-12-09T00:00:00+00:00
    """
    try:
        if event_time_str.endswith("Z"):
            event_time_str = event_time_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(event_time_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


# ==========================
# FETCH LOGS
# ==========================
def fetch_logs_around_time(event_time_str: str) -> str:
    dt = parse_event_time(event_time_str)

    center_ms = int(dt.timestamp() * 1000)
    window_ms = LOG_TIME_WINDOW_MINUTES * 60 * 1000

    start_time = center_ms - window_ms
    end_time = center_ms + window_ms

    print(f"[Logs] group={LOG_GROUP_NAME} start={start_time} end={end_time} window_min={LOG_TIME_WINDOW_MINUTES}")
    print(f"[Logs] MAX_EVENTS_FOR_BEDROCK={MAX_EVENTS_FOR_BEDROCK} MAX_LOG_CHARS={MAX_LOG_CHARS}")

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
            msg = (ev.get("message") or "").rstrip()
            if msg:
                messages.append(normalize_waf_log(msg))

            if len(messages) >= MAX_EVENTS_FOR_BEDROCK:
                print(f"[Logs] Reached MAX_EVENTS_FOR_BEDROCK={MAX_EVENTS_FOR_BEDROCK}, stop collecting.")
                next_token = None
                break

        next_token = resp.get("nextToken")
        if not next_token:
            break

    payload = "\n".join(messages)
    print(f"[Logs] lines={len(messages)} payload_chars={len(payload)}")

    if len(payload) > MAX_LOG_CHARS:
        print(f"[Logs] payload too long ({len(payload)}), trim to {MAX_LOG_CHARS} (keep newest tail)")
        payload = payload[-MAX_LOG_CHARS:]

    return payload


# ==========================
# BEDROCK
# ==========================
def analyze_with_bedrock(alarm_name: str, event_time: str, logs_text: str) -> dict:
    prompt = f"""
Bạn là hệ thống phân tích log bảo mật tự động.

Hãy phân tích đoạn log dưới đây và TRẢ VỀ DUY NHẤT một JSON (không thêm markdown, không thêm giải thích).
Schema JSON bắt buộc:

{{
  "summary": "tóm tắt ngắn gọn tình hình trong log",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "attack_type": "BRUTE_FORCE|L7_DDOS|SQLI|SCAN|NONE|OTHER",
  "suspected_ips": ["1.2.3.4"],
  "top_offenders": [
    {{
      "ip": "1.2.3.4",
      "event_count": 123,
      "sample_paths": ["/login", "/api/auth"],
      "notes": "mô tả ngắn"
    }}
  ],
  "detection_reason": "giải thích ngắn tại sao đánh giá như vậy",
  "recommendations": ["khuyến nghị 1", "khuyến nghị 2"]
}}

Yêu cầu:
- Nếu thấy nhiều lần đăng nhập thất bại (HTTP 401/403) trong thời gian ngắn từ cùng một IP tới /login
  hoặc endpoint authentication, hãy coi đó là brute force tấn công mật khẩu và đặt attack_type = "BRUTE_FORCE".
- Trong trường hợp brute force rõ ràng, hãy đặt severity ít nhất là HIGH.
- Nếu không thấy dấu hiệu tấn công rõ ràng, đặt attack_type = "NONE", severity = "LOW"
  và để suspected_ips là mảng rỗng [].
- Chỉ đưa IP vào suspected_ips khi có lý do tương đối rõ.
- TUYỆT ĐỐI chỉ in ra JSON đúng schema trên, không thêm text nào khác.

Alarm: {alarm_name}
Time: {event_time}

Log:
----------------
{logs_text}
----------------
""".strip()

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 400,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}],
            }
        ],
    }

    print(f"[Bedrock] Calling model={BEDROCK_MODEL_ID}")

    try:
        resp = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body),
        )
        resp_json = json.loads(resp["body"].read())

        print("[Bedrock] Raw response envelope:", _safe_json_dumps({k: resp_json.get(k) for k in ["id", "type", "model", "stop_reason"]}))

        content_blocks = resp_json.get("content", []) or []
        raw_output = ""
        for block in content_blocks:
            if block.get("type") == "text":
                raw_output += block.get("text", "")

        raw_output = raw_output.strip()
        print("[Bedrock] Model output:", raw_output[:2000] + ("..." if len(raw_output) > 2000 else ""))

        analysis = json.loads(raw_output)

        # Normalize required fields
        if not isinstance(analysis.get("suspected_ips"), list):
            analysis["suspected_ips"] = []
        if not isinstance(analysis.get("recommendations"), list):
            analysis["recommendations"] = []
        if not isinstance(analysis.get("top_offenders"), list):
            analysis["top_offenders"] = []

        return analysis

    except Exception as e:
        print("[Bedrock] ERROR:", str(e))
        return {
            "summary": "Fallback: Lỗi khi gọi Bedrock hoặc parse output.",
            "severity": "HIGH",
            "attack_type": "UNKNOWN",
            "suspected_ips": [],
            "top_offenders": [],
            "detection_reason": str(e),
            "recommendations": [
                "Kiểm tra IAM permissions cho bedrock:InvokeModel.",
                "Kiểm tra Bedrock modelId và region.",
                "Xem CloudWatch Logs của Lambda analyzer để biết lỗi chi tiết.",
            ],
        }


# ==========================
# DDB
# ==========================
def save_incident_to_dynamodb(alarm_name: str, event_time: str, ips: list) -> str:
    incident_id = str(uuid.uuid4())
    now_epoch = int(time.time())
    ttl_epoch = now_epoch + 7 * 24 * 3600  # keep 7 days

    ip_list = ips if ips else ["NO_IP"]

    for ip in ip_list:
        item = {
            "incidentId": incident_id,
            "ip": ip,
            "alarmName": alarm_name,
            "alarmTime": event_time,
            "status": "PENDING",
            "createdAt": now_epoch,
            "ttl": ttl_epoch,
        }
        print("[DDB] PutItem:", _safe_json_dumps(item))
        incident_table.put_item(Item=item)

    return incident_id


# ==========================
# SES
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
    attack_type = analysis.get("attack_type", "UNKNOWN")
    recommendations = analysis.get("recommendations", []) or []
    detection_reason = analysis.get("detection_reason", "")
    top_offenders = analysis.get("top_offenders") or []

    subject = f"[MLSA] Incident {incident_id[:8]} - {severity}"

    # Block links
    block_links = []
    for ip in suspected_ips or []:
        link = f"{BLOCK_IP_BASE_URL}?incidentId={incident_id}&ip={ip}"
        block_links.append(f"- {ip}: {link}")

    offender_lines = []
    for offender in top_offenders:
        ip = offender.get("ip", "?")
        count = offender.get("event_count", "?")
        paths = offender.get("sample_paths") or []
        notes = offender.get("notes", "")
        paths_str = ", ".join(paths) if paths else "(none)"
        line = f"- IP {ip}: {count} events, paths: {paths_str}"
        if notes:
            line += f" ({notes})"
        offender_lines.append(line)

    body_lines = [
        f"Alarm name : {alarm_name}",
        f"Time       : {event_time}",
        f"IncidentId : {incident_id}",
        "",
        f"Severity   : {severity}",
        f"Attack type: {attack_type}",
        "",
        "Summary:",
        summary or "(none)",
        "",
    ]

    if detection_reason:
        body_lines += ["Detection reason:", detection_reason, ""]

    body_lines.append("Suspected IPs:")
    body_lines += block_links if block_links else ["- (none)"]

    body_lines += ["", "Top offenders:"]
    body_lines += offender_lines if offender_lines else ["- (none)"]

    body_lines += ["", "Recommendations:"]
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            body_lines.append(f"{i}. {rec}")
    else:
        body_lines.append("- (none)")

    body_text = "\n".join(body_lines)

    print("=== SES EMAIL BODY (preview) ===")
    print(body_text[:4000] + ("..." if len(body_text) > 4000 else ""))

    ses.send_email(
        Source=SES_FROM,
        Destination={"ToAddresses": [SES_TO]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
        },
    )

    print(f"[SES] Email sent to {SES_TO} for incident {incident_id}")


# ==========================
# MAIN
# ==========================
def lambda_handler(event, context):
    print("=== RAW EVENT ===")
    print(_safe_json_dumps(event))

    alarm_name = event.get("alarmData", {}).get("alarmName", "UNKNOWN_ALARM")
    event_time_str = event.get("time", "")

    print(f"[Env] REGION={REGION} MODEL={BEDROCK_MODEL_ID}")
    print(f"[Env] LOG_GROUP_NAME={LOG_GROUP_NAME} WINDOW_MIN={LOG_TIME_WINDOW_MINUTES}")

    # 1) Fetch logs
    logs_text = fetch_logs_around_time(event_time_str)
    if not logs_text:
        print("[Logs] No logs found in window. Use placeholder.")
        logs_text = "NO_LOGS_FOUND in the configured time window."

    # 2) Bedrock analysis
    print("[Flow] Start Bedrock analysis")
    analysis = analyze_with_bedrock(alarm_name, event_time_str, logs_text)
    print("[Flow] Bedrock analysis done")
    print("=== ANALYSIS ===")
    print(_safe_json_dumps(analysis))

    suspected_ips = analysis.get("suspected_ips") or []

    # 3) Save incident
    incident_id = save_incident_to_dynamodb(alarm_name, event_time_str, suspected_ips)

    # 4) Send SES email
    try:
        print("[Flow] Start sending SES email")
        send_incident_email(
            incident_id=incident_id,
            alarm_name=alarm_name,
            event_time=event_time_str,
            suspected_ips=suspected_ips,
            analysis=analysis,
        )
        print("[Flow] SES email sent")
    except Exception as e:
        print("[SES] ERROR when sending email:", str(e))

    return {
        "status": "OK",
        "incidentId": incident_id,
        "alarmName": alarm_name,
        "ips": suspected_ips,
        "analysis": analysis,
    }
