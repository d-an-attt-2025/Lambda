import boto3, os

waf = boto3.client("wafv2")

BLACK = os.environ["BLACKLIST_ARN"]

def lambda_handler(event, context):

    # Debug log
    print("EVENT:", event)

    # Lấy query params an toàn
    params = event.get("queryStringParameters") or {}

    ip = params.get("ip")
    if not ip:
        return {
            "statusCode": 400,
            "body": "Missing ?ip= parameter. Nothing to block."
        }

    cidr = f"{ip}/32"

    # Parse name + id từ ARN IPSet
    # ARN dạng: arn:aws:wafv2:region:account:regional/ipset/Name/ID
    parts = BLACK.split("/")
    name = parts[-2]
    ipset_id = parts[-1]

    # Lấy IPSet hiện tại
    detail = waf.get_ip_set(
        Scope="REGIONAL",
        Name=name,
        Id=ipset_id
    )

    addresses = detail["IPSet"]["Addresses"]

    if cidr not in addresses:
        addresses.append(cidr)

        waf.update_ip_set(
            Scope="REGIONAL",
            Name=name,
            Id=ipset_id,
            Addresses=addresses,
            LockToken=detail["LockToken"]
        )

    return {
        "statusCode": 200,
        "body": f"IP {ip} has been BLOCKED."
    }
