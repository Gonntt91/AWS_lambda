import json
import uuid

import boto3
import multipart
import jwt
import base64
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    headers = {
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
    }
    body = event["body"]

    isBase64Encoded = bool(event["isBase64Encoded"])

    if isBase64Encoded:
        body = base64.b64decode(body)
    else:
        body.encode("utf-8")

    parser = multipart.MultipartParser(body)
    parts = parser.parse()

    hotel_name = parts.get("hotelName")
    hotel_rating = parts.get('hotelRating')
    hotel_city = parts.get("hotelCity")
    hotel_price = parts.get("hotelPrice")
    file_name = parts.get("fileName")
    user_id = parts.get('userId')
    id_token = parts.get('idToken')

    file = parts.get('fileData').file.read()
    token = jwt.decode(id_token, verify=False)

    group = token.get("cognito:groups")

    if group is None or group != "Admin":
        return {
            "statusCode": 401,
            "body": json.dumps({
                "Error": "You are not a member of Admin Group"
            })
        }

    bucket_name = os.environ.get("bucketName")
    region = os.environ.get("AWS_REGION")

    s3_client = boto3.client("s3", region_name=region)
    dynamoDb = boto3.resource("dynamodb", region_name=region)
    table = dynamoDb.Table('hotel')

    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=file
        )
        hotel = {
            "UserId": user_id,
            "Id": str(uuid.uuid4()),
            "Name": hotel_name,
            "CityName": hotel_city,
            "Price": int(hotel_price),
            "Rating": int(hotel_rating),
            "FileName": file_name
        }

        table.put_item(Item=hotel)

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "Error": "Upload photo failed"
            })
        }

    # TODO implement
    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps('Hello from Lambda!')
    }
