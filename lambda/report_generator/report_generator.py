import boto3
import json
import os
import datetime

inspector2_client = boto3.client('inspector2')


def lambda_handler(event, context):
    # Call Inspector API to list findings

    report_bucket = os.getenv('BUCKET_NAME')
    inspector_report_cmk = os.getenv('KMS_KEY')
    output_format = os.getenv('OUTPUT_FORMAT')
    now = datetime.datetime.now() # we could also use "time" from event
    # Partition the data into year,month and day
    key_prefix = f'year={now.year}/month={now.month}/day={now.day}/'
    response = inspector2_client.create_findings_report(
        reportFormat=output_format,
        s3Destination={
            'bucketName': report_bucket,
            'kmsKeyArn': inspector_report_cmk,
            'keyPrefix': key_prefix
        }
    )

    # Return report as JSON
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
