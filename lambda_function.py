import json
import boto3
from botocore.vendored import requests


# SLACK_CHANNEL = os.environ.get("slack_channel")
SLACK_WEBHOOK_URL = os.environ.get("slack_webhook_url")
SLACK_CHANNEL = "#cloudops-ecr-scan-results"


def format_slack_message(image_name, image_tag, build_url, vuln_findings):
    text = f"Vuln scan for {image_name}:{image_tag} found {vuln_findings} (build: {build_url})"
    channel = SLACK_CHANNEL
    username = "ECR vuln scan report"
    icon_emoji = ":black_circle:"

    slack_message = dict(
        text=text,
        channel=channel,
        username=username,
        icon_emoji=icon_emoji
    )

    return slack_message


def post_slack_message(message):
    """Makes a http POST request to slack webhook url, posting a notification message.
    Args:
        message (dict): a payload with slack message data
    Returns:
        boolean: message has been sent successfully or not
    """

    response = requests.post(SLACK_WEBHOOK_URL,
                             data=json.dumps(message),
                             headers={'Content-Type': 'application/json'}
                             )

    if response.status_code != 200:
        raise ValueError('Request to slack returned an error: %s, the response is: %s' %
                         (response.status_code, response.text))
    return True


def get_vuln_report_from_s3(s3_bucket, object_path):
    s3 = boto3.resource('s3')
    obj = s3.Object(s3_bucket, object_path)
    return obj.get()['Body'].read().decode('utf-8')


def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    message = event['Records'][0]['Sns']['Message']
    vuln_scan_report_notification = json.loads(message)
    
    build_url = vuln_scan_report_notification.get("build_url")
    image_name = vuln_scan_report_notification.get("image_name")
    image_tag = vuln_scan_report_notification.get("image_tag")
    vuln_scan_report_s3_bucket = vuln_scan_report_notification.get("vuln_scan_report_s3_bucket")
    vuln_scan_report_s3_object_path = vuln_scan_report_notification.get("vuln_scan_report_s3_object_path")

    print(f"Vuln scan for {image_name}:{image_tag} to be found at s3://{vuln_scan_report_s3_bucket}/{vuln_scan_report_s3_object_path} by {build_url}")

    vuln_report_json = get_vuln_report_from_s3(vuln_scan_report_s3_bucket, vuln_scan_report_s3_object_path)
    vuln_report_data = json.loads(vuln_report_json)
    
    finding_severity_counts = vuln_report_data.get("imageScanFindings").get("findingSeverityCounts")
    print(f"finding severity counts: {finding_severity_counts}")

    slack_message = format_slack_message(image_name, image_tag, finding_severity_counts, build_url)
    post_slack_message(slack_message)

    return True
