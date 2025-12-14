import boto3, os

waf = boto3.client("wafv2")

BLACK = os.environ["BLACKLIST_ARN"]

def lambda_handler(event, context):

    # Debug log
    print("=== BLOCK IP LAMBDA START ===")
    print("EVENT RAW:", event)

    params = event.get("queryStringParameters") or {}
    print("Query Params:", params)

    ip = params.get("ip")
    if not ip:
        print("❌ Missing IP parameter")
        return {"statusCode": 400, "body": "Missing ?ip= parameter."}

    cidr = f"{ip}/32"
    print(f"Parsed CIDR: {cidr}")

    parts = BLACK.split("/")
    name = parts[-2]
    ipset_id = parts[-1]

    print(f"Using IPSet: Name={name}, ID={ipset_id}")

    detail = waf.get_ip_set(
        Scope="REGIONAL",
        Name=name,
        Id=ipset_id
    )
    addresses = detail["IPSet"]["Addresses"]
    print("Current Addresses:", addresses)

    if cidr not in addresses:
        print(f"⚠️ Adding new IP to blacklist: {cidr}")
        addresses.append(cidr)

        waf.update_ip_set(
            Scope="REGIONAL",
            Name=name,
            Id=ipset_id,
            Addresses=addresses,
            LockToken=detail["LockToken"]
        )
        print("✅ IP added successfully")
    else:
        print("ℹ️ IP already exists, skip update.")

    print("=== BLOCK IP LAMBDA END ===")

    return {"statusCode": 200, "body": f"IP {ip} has been BLOCKED."}
