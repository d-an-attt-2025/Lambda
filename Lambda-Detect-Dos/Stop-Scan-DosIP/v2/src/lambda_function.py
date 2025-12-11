import boto3, os
logs = boto3.client('logs')

LOG_GROUP = os.environ['LOG_GROUP']
FILTER_NAME = "EnableDoSScan"

def lambda_handler(event, context):
    print("=== STOP SCAN LAMBDA ===")
    print("LOG_GROUP:", LOG_GROUP)

    logs.delete_subscription_filter(
        logGroupName=LOG_GROUP,
        filterName=FILTER_NAME
    )

    print("✔ Subscription filter removed -> SCAN DISABLED")
    return {"status": "STOPPED"}
