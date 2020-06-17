import json
import boto3
import os
import requests
import logging
import sign_awssigv4


def log_event(status,logger,filename,bucketname,loc,event):
    logger.info('## ACTION TAKEN')
    if status == 200:
        logger.info(
            'The file {} in bucket {} can been scanned successfully at {} and tagged as safe.'.format(
                filename,
                bucketname,
                loc))
    elif status == 406:
        logger.info(
            'The file {} in bucket {} can been scanned at {} and tagged as unsafe. The file is quarantined.'.format(
                filename,
                bucketname,
                loc))
    else:
        logger.info(
            'The file {} in bucket {} couldnt be scanned due to an error. The file is tagged unsafe'.format(
                filename,
                bucketname,
                loc))


def lambda_handler(event, context):
    clamav_addr = os.environ["CLAMAV_ADDR"]
    #clamav_addr = "http://host.docker.internal:9000"
    clamav_qbucket = os.environ['CLAMAV_QBUCKET']

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    aws_session = boto3.Session()
    s3 = aws_session.resource('s3', 'us-east-1')
    client = boto3.client('s3')

    url = clamav_addr + "/scan"
    file = event["Records"][0]
    key = str(file['s3']['object']['key'])
    src_bucket = file['s3']['bucket']['name']
    basename = key.split('/')[-1].strip()
    tmp_file = '/tmp/' + basename
    s3obj = s3.Bucket(src_bucket).Object(key)
    s3obj.download_file(tmp_file)

    payload = {

    }
    files = [
        ('hash', file['s3']['object']['eTag']),
        ('file', open(tmp_file, 'rb'))
    ]
    creds = aws_session.get_credentials().get_frozen_credentials()
    headers = sign_awssigv4.getHeaders(creds.access_key,
                                       creds.secret_key,
                                       creds.token)

    response = requests.request("POST", url, headers=headers, data=payload, files=files, verify=False)

    status_code = 0

    if response.status_code == 200:
        description = json.loads((response.text))['Description']
        signature = json.loads((response.text))['Signature']
        client.put_object_tagging(
            Bucket=src_bucket,
            Key=key,
            Tagging={
                'TagSet': [
                    {
                        'Key': 'virus_scan',
                        'Value': 'safe'
                    },
                    {
                        'Key': 'virus_scan_signature',
                        'Value': signature
                    }
                ]
            }
        )
        status_code = 200
        message = 'No Virus Found. Successfully tagged'
    elif response.status_code == 406:
        description = json.loads((response.text))['Description']
        s3qkey = "{}/{}".format(src_bucket, basename)
        s3.Bucket(clamav_qbucket).upload_file(tmp_file,
                                              s3qkey,
                                              ExtraArgs={
                                                  'Tagging': 'virus_scan=unsafe&virus_scan_signature={}'.format(description)
                                              })
        s3obj.delete()
        status_code = 406
        message = 'Virus Found. Quarantined file'

    elif response.status_code == 403:
        status_code = 403
        message = 'No authorization to perform scan'

    else:
        client.put_object_tagging(
            Bucket=src_bucket,
            Key=key,
            Tagging={
                'TagSet': [
                    {
                        'Key': 'virus_scan',
                        'Value': 'unmarked'
                    },
                    {
                        'Key': 'virus_scan_reason',
                        'Value': '{}'.format('Couldnt complete scan. Internal Error')
                    }
                ]
            }
        )
        status_code = 500
        message = 'Couldnt complete scan. Internal Error'

    log_event(status_code, logger, key, src_bucket, clamav_addr, event)

    return {
        "statusCode": status_code,
        "body": json.dumps({
            "message": message,
        }),
    }