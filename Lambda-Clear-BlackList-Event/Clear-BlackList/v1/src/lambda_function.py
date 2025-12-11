import boto3
import os

waf = boto3.client('wafv2')  # WAFv2

IP_SET_NAME = os.environ.get("IP_SET_NAME")
IP_SET_ID = os.environ.get("IP_SET_ID")
SCOPE = os.environ.get("SCOPE", "REGIONAL")  # hoặc "CLOUDFRONT"

def lambda_handler(event, context):
    # Lấy thông tin IPSet
    get_resp = waf.get_ip_set(
        Name=IP_SET_NAME,
        Scope=SCOPE,
        Id=IP_SET_ID
    )

    ip_set = get_resp['IPSet']
    lock_token = get_resp['LockToken']
    addresses = ip_set['Addresses']

    if not addresses:
        print(f"IPSet {IP_SET_NAME} đã rỗng.")
        return {
            'statusCode': 200,
            'body': 'No IPs to delete'
        }

    # Cập nhật IPSet về list IP rỗng
    waf.update_ip_set(
        Name=IP_SET_NAME,
        Scope=SCOPE,
        Id=IP_SET_ID,
        Addresses=[],
        LockToken=lock_token
    )

    print(f"Đã xóa toàn bộ IP khỏi IPSet {IP_SET_NAME}")
    return {
        'statusCode': 200,
        'body': 'All IPs removed from IPSet'
    }
