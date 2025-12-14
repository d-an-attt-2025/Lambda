import json
import os
import re

import boto3
from botocore.config import Config

# =============== ENV ===============
# Tự động có sẵn trong Lambda, không cần set tay
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

# ARN của WAFv2 IPSet (REGIONAL hoặc CLOUDFRONT) – BẮT BUỘC
# Ví dụ:
# arn:aws:wafv2:ap-southeast-1:123456789012:regional/ipset/mlsa-ip-blacklist/abcd1234-...
BLACKLIST_ARN = os.environ["BLACKLIST_ARN"]

# REGIONAL hoặc CLOUDFRONT (phải khớp với IPSet)
WAF_SCOPE = os.environ.get("WAF_SCOPE", "REGIONAL")

# =============== AWS CLIENTS ===============
waf = boto3.client(
    "wafv2",
    region_name=REGION,
    config=Config(read_timeout=10, retries={"max_attempts": 3}),
)

IPV4_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def lambda_handler(event, context):
    """
    Sử dụng qua:
    - Lambda Function URL, hoặc
    - API Gateway HTTP API (proxy integration)

    Query string:
      ?ip=1.2.3.4&action=block
      ?ip=1.2.3.4&action=unblock
      (&incidentId=xyz  # chỉ để hiển thị)
    """
    print("=== RAW EVENT ===")
    print(json.dumps(event))

    params = event.get("queryStringParameters") or {}

    ip = params.get("ip")
    action = (params.get("action") or "block").lower()
    incident_id = params.get("incidentId") or params.get("incidentID") or "N/A"

    if not ip:
        return _response_html(400, "Missing 'ip' in query string.")

    if not IPV4_REGEX.match(ip):
        return _response_html(400, f"Invalid IPv4 address: {ip}")

    if action not in ("block", "unblock"):
        return _response_html(
            400, f"Invalid action={action}, must be 'block' or 'unblock'."
        )

    try:
        if action == "block":
            _update_waf_ipset(ip, add=True)
            msg = f"IP {ip} đã được BLOCK. incidentId={incident_id}"
        else:
            _update_waf_ipset(ip, add=False)
            msg = f"IP {ip} đã được UNBLOCK. incidentId={incident_id}"

        return _response_html(200, msg)

    except Exception as e:
        print("Error while processing request:", e)
        return _response_html(500, f"Internal error: {e}")


# =============== WAF HELPER ===============

def _parse_ipset_from_arn(arn: str):
    """
    ARN dạng:
    arn:aws:wafv2:region:account:regional/ipset/<name>/<id>
    -> trả về: name, id
    """
    parts = arn.split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid IPSet ARN: {arn}")
    name = parts[-2]
    ipset_id = parts[-1]
    return name, ipset_id


def _update_waf_ipset(ip: str, add: bool):
    cidr = f"{ip}/32"
    name, ipset_id = _parse_ipset_from_arn(BLACKLIST_ARN)

    print(f"Using IPSet: Name={name}, Id={ipset_id}, Scope={WAF_SCOPE}")

    # 1) Lấy IPSet hiện tại + LockToken
    get_resp = waf.get_ip_set(
        Scope=WAF_SCOPE,
        Name=name,
        Id=ipset_id,
    )

    addresses = set(get_resp["IPSet"]["Addresses"])
    lock_token = get_resp["LockToken"]

    print("Current addresses:", addresses)

    changed = False
    if add:
        if cidr not in addresses:
            addresses.add(cidr)
            changed = True
    else:
        if cidr in addresses:
            addresses.remove(cidr)
            changed = True

    if not changed:
        print("No change to IPSet needed.")
        return

    # 2) Update IPSet
    waf.update_ip_set(
        Scope=WAF_SCOPE,
        Name=name,
        Id=ipset_id,
        Addresses=sorted(addresses),
        LockToken=lock_token,
    )

    print(f"Updated IPSet with {cidr}, add={add}")


# =============== HTTP RESPONSE ===============

def _response_html(status_code: int, message: str):
    body = f"""
<!DOCTYPE html>
<html>
  <head>
    <title>MLSA IP action</title>
  </head>
  <body>
    <h2>MLSA – IP action result</h2>
    <p>Status code: {status_code}</p>
    <p>Message: {message}</p>
  </body>
</html>
""".strip()

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
        },
        "body": body,
    }
