import os
import io
import jwt
import json
import uuid
import boto3
import base64
import logging
import multipart as python_multipart

logger = logging.getLogger()
logger.setLevel(logging.INFO)



def parse_multipart(stream, boundary):
    # Convert the boundary into bytes, as required by the parser
    boundary = boundary.encode('utf-8')

    # The body should be in bytes, ensure this before passing to the parser


    # Create the parser
    parser = python_multipart.MultipartParser(stream, boundary)

    # Dictionaries to hold the form fields and files
    fields = {}
    files = {}

    # Iterate over the parts
    for part in parser:
        print("part: ", part.name, part.charset, part.raw, part.file)

        # Content-Disposition header contains the name and filename
        content_disposition = part.headers.get('Content-Disposition', '')
        disposition_params = parse_content_disposition(content_disposition)

        # Check if it's a file or a normal field
        if 'filename' in disposition_params:
            # It's a file, read the content
            files[disposition_params['name']] = {
                'filename': disposition_params['filename'],
                'content': part.file.read(),  # Read the content into memory
                'content_type': part.headers.get('Content-Type', 'application/octet-stream')
            }
        else:
            # It's a regular field, decode the content as UTF-8
            fields[disposition_params['name']] = str(part.raw)

    return fields, files


def lambda_handler(event, context):
    response_headers = {
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*"
    }

    request_headers = event['headers']

    body = event['body']

    if bool(event.get('isBase64Encoded')):
        body = base64.b64decode(body)
    else:
        body = body.encode('utf-8')

    boundary = extract_boundary(request_headers)
    fields, files = parse_multipart(stream=io.BytesIO(body), boundary=boundary)

    hotel_name = fields.get('hotelName')
    hotel_rating = fields.get('hotelRating')
    hotel_city = fields.get('hotelCity')
    hotel_price = fields.get('hotelPrice')
    user_id = fields.get('userId')
    id_token = fields.get('idToken')

    file = files.get('photo')
    file_name = file.get("filename")
    file_content = file.get("content")
    file.get("content").seek(0)

    # We now have the field values and the file.

    # Performing Authorization.
    # Authorization must be done at API Gateway Level using a Custom Lambda Authorizer
    # In this code it is done in the microservice for educational purposes

    token = jwt.decode(id_token, options={"verify_signature": False})
    group = token.get('cognito:groups')

    logger.info(group)

    if group is None or 'Admin' not in group:
        return {
            'statusCode': 401,
            'headers': response_headers,
            'body': json.dumps({
                'Error': 'You are not a member of the Admin group'
            })
        }

    bucket_name = os.environ.get('bucketName')
    region = os.environ.get('AWS_REGION')
    s3_client = boto3.client('s3', region_name=region)
    dynamoDb = boto3.resource('dynamodb', region_name=region)
    table = dynamoDb.Table('Hotels')

    logger.info(bucket_name)
    try:

        # Upload the image to S3
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=file_content
        )

        hotel = {
            "userId": user_id,
            "Id": str(uuid.uuid4()),
            "Name": hotel_name,
            "CityName": hotel_city,
            "Price": int(hotel_price),
            "Rating": int(hotel_rating),
            "FileName": file_name
        }

        # Store the hotel record in DynamoDb
        table.put_item(Item=hotel)

        sns_topic_arn = os.getenv("hotelCreationTopicArn")
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(hotel)
        )

    except Exception as e:
        return {
            "statusCode": 500,
            'headers': response_headers,
            "body": json.dumps({
                "Error": e.__traceback__
            })
        }

    return {
        'statusCode': 200,
        'headers': response_headers,
        'body': json.dumps({"message": "ok"})
    }


def parse_content_disposition(content_disposition):
    # Simple parser for Content-Disposition to handle form-data; name="field"; filename="example.txt"
    parts = content_disposition.split(';')
    disp_type = parts[0].strip()
    params = {}

    for part in parts[1:]:
        param_name, param_value = part.strip().split('=')
        params[param_name.strip()] = param_value.strip().strip('"')

    return params


def extract_boundary(headers):
    content_type = headers.get('content-type', '')
    boundary_start = content_type.find('boundary=')
    if boundary_start != -1:
        boundary_end = content_type.find(';', boundary_start)
        if boundary_end == -1:
            boundary_end = len(content_type)
        boundary = content_type[boundary_start + len('boundary='):boundary_end].strip()

        # Check if the boundary is enclosed in quotes and remove them if present
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]

        return boundary

    return None