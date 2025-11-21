import boto3, os
logs = boto3.client('logs')

LOG_GROUP = os.environ['LOG_GROUP']
FILTER_NAME = "EnableDoSScan"
LAMBDA_SCAN_ARN = os.environ['LAMBDA_SCAN_ARN']

def lambda_handler(event, context):
    logs.put_subscription_filter(
        logGroupName=LOG_GROUP,
        filterName=FILTER_NAME,
        filterPattern="",
        destinationArn=LAMBDA_SCAN_ARN
    )
    return {"status": "STARTED"}
