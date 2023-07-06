import boto3
from datetime import datetime, timedelta, timezone
import json
import base64
from botocore.exceptions import ClientError
kms_client = boto3.client('kms')

def get_users():
    iam = boto3.client('iam')
    marker = None
    users = []

    while True:
        if marker:
            response = iam.list_users(Marker=marker)
        else:
            response = iam.list_users()

        users += response['Users']
        marker = response.get('Marker')

        if not marker:
            break

    return users

def lambda_handler(event, context):

    # Set the IAM and SES clients
    iam = boto3.client('iam')
    ses = boto3.client('ses')

    # Get the current time and time four minutes ago and six minutes ago in UTC
    now = datetime.now(timezone.utc)
    two_minutes_ago = now - timedelta(minutes=2)
    four_minutes_ago = now - timedelta(minutes=4)
    six_minutes_ago = now - timedelta(minutes=6)
    eight_minutes_ago = now - timedelta(minutes=8)
    ten_minutes_ago = now - timedelta(minutes=10)
    threshold = now - timedelta(minutes=10)
   
    print("printing threshold timing")
    print(threshold)
    print("printing now time")
    print(now)

    # Get a list of all IAM users
    #users = iam.list_users()
    users = get_users()
    
    for user in users:
        user_name = user['UserName']
        access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']

        if len(access_keys) < 2 and len(access_keys) != 0:
            # Get a list of all IAM users
            #users = iam.list_users()
            users = get_users()
            # Loop through each access key and check its last rotation time
            for key in access_keys:
                last_rotated = key['CreateDate'].replace(tzinfo=timezone.utc)
                AccessKeyId = key['AccessKeyId']
                last_used = iam.get_access_key_last_used(AccessKeyId=AccessKeyId)['AccessKeyLastUsed'].get('LastUsedDate', 'N/A')
                print(f"User: {user['UserName']} AccessKeyId: {AccessKeyId} Last used: {last_used}")
                print("printing last_rotated")
                print(last_rotated)

                if last_rotated < four_minutes_ago and last_rotated > ten_minutes_ago:
                    print ("1")
                    print (last_rotated)
                    print("the keys are not older than ten minutes")
                    # Check if the key has not been rotated in the last four minutes
                    tags = iam.list_user_tags(UserName=user_name)['Tags']
                    email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                    #secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                    secret_name = user_name
                    user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                    application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                    environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                    if user_type_id == "service":
                        if email_id is not None and secret_name is not None and application_id is not None and environment is not None:

                            key_id = "99db2bd8-b54f-438a-8ca8-f4d21abb0d30"
                            # Create new access key and secret key
                            new_key = iam.create_access_key(UserName=user_name)['AccessKey']
                            access_key_id = str(new_key['AccessKeyId'])
                            secret_access_key = str(new_key['SecretAccessKey'])
                            print("printing new access key and secret key")
                            print (access_key_id)
                            #print (secret_access_key)
                            encrypted_access_key_id = kms_client.encrypt(KeyId=key_id, Plaintext=access_key_id)['CiphertextBlob']
                            encrypted_secret_access_key = kms_client.encrypt(KeyId=key_id, Plaintext=secret_access_key)['CiphertextBlob']
                            # Encode the encrypted values to base64 strings
                            encoded_access_key_id = base64.b64encode(encrypted_access_key_id).decode('utf-8')
                            encoded_secret_access_key = base64.b64encode(encrypted_secret_access_key).decode('utf-8')

                            # Check if the secret already exists
                            try:
                                secret_description = boto3.client('secretsmanager').describe_secret(SecretId=secret_name)
                                # Update the existing secret with the new key values
                                secret_value = {
                                    'AccessKeyId': encoded_access_key_id,
                                    'SecretAccessKey': encoded_secret_access_key
                                }
                                secret_arn = secret_description['ARN']
                                boto3.client('secretsmanager').update_secret(SecretId=secret_name, SecretString=json.dumps(secret_value))
                            except ClientError as e:
                                # If the secret doesn't exist, create a new secret
                                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                                    secret_value = {
                                      'AccessKeyId': encoded_access_key_id,
                                    'SecretAccessKey': encoded_secret_access_key
                                    }
                                    secret_arn = boto3.client('secretsmanager').create_secret(Name=secret_name, SecretString=json.dumps(secret_value))['ARN']
                                else:
                                    # Handle other errors that may occur
                                    print("Error updating or creating secret:", e)
                            # Replicate the secret to us-east-1
                            try:
                                boto3.client('secretsmanager').replicate_secret_to_regions(
                                    SecretId=secret_arn,
                                    AddReplicaRegions=[{'Region': 'us-east-1'}]
                                )
                            except ClientError as e:
                                print("Error replicating secret to us-east-1:", e)

                        
                # Check if the key has not been rotated in the last two minutes
                if last_rotated < two_minutes_ago and last_rotated > four_minutes_ago:
                # Get the email ID and secret name from the user's tags
                  print ("2")
                  print (last_rotated)
                  tags = iam.list_user_tags(UserName=user_name)['Tags']
                  email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                  secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                  user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                  application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                  environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                  if user_type_id == "service":        
                      if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                          # Create new access key and secret key
                          # Send an email to the user using SES
                          """message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of two minutes of age  your keys will be created if the age of four minutes the new key will be created and shared through mail"
                          ses.send_email(
                              Source='rizwanabegum.d@gmail.com',
                              Destination={
                                  'ToAddresses': [
                                      email_id
                                  ]
                              },
                              Message={
                                      'Subject': {
                                      'Data': 'IAM Access Key Rotation Alert'
                                      },
                                      'Body': {
                                          'Text': {
                                              'Data': message
                                                  }
                                              }
                                          }
                                      ) """
                         
                if last_rotated < ten_minutes_ago:
                  print (last_rotated)
                  print (ten_minutes_ago)
                  print ("the keys are not rotated for last ten minutes")
                    # Get the email ID and secret name from the user's tags
                  tags = iam.list_user_tags(UserName=user_name)['Tags']
                  email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                  secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                  user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                  application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                  environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                  if user_type_id == "service":
                      if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                              # Check if the key has not been rotated in the last ten minutes
                      # Send an email to the user using SES
                          """message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of ten minutes or hence the older keys are not rorated, Thank you."
                          ses.send_email(
                              Source='rizwanabegum.d@gmail.com',
                              Destination={
                                  'ToAddresses': [
                                                  email_id
                                          ]
                                      },
                                      Message={
                                          'Subject': {
                                          'Data': 'IAM Access Key Rotation Alert'
                                          },
                                          'Body': {
                                              'Text': {
                                                  'Data': message
                                                      }
                                                  }
                                              }
                                          )"""
                    
                            
    # Loop through each user and check their access keys
    for user in users:
        user_name = user['UserName']
        access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        if len(access_keys) == 2:
            print("lenth of access keys is 2")
            print ("printing the list of access keys for the user:")
            print (user_name)
            print (access_keys)
            for key in access_keys:
                AccessKeyId = key['AccessKeyId']
                last_used = iam.get_access_key_last_used(AccessKeyId=AccessKeyId)['AccessKeyLastUsed'].get('LastUsedDate', 'N/A')
                print("printing last used ")
                print(last_used)
                print(f"User: {user['UserName']} AccessKeyId: {AccessKeyId} Last used: {last_used}")
                last_rotated = key['CreateDate'].replace(tzinfo=timezone.utc)
                print("for the users")
                print(user_name)
                print("printing last used time")
                print(last_used)
                
                print("printing last_rotated")
                print (last_rotated)
                
                if last_rotated > ten_minutes_ago:
                  if last_rotated < four_minutes_ago:
                    print("we are inside the loop now of below ten minutes")
                    # Check if the key has not been rotated in the last four minutes
                    # Get the email ID and secret name from the user's tags
                    tags = iam.list_user_tags(UserName=user_name)['Tags']
                    email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                    secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                    user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                    application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                    environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                    if user_type_id == "service":
                        if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                        # Check if the key has not been rotated in the last six minutes
                            if last_rotated < six_minutes_ago:
                                if last_rotated > eight_minutes_ago:
                                    #if last_used > threshold:
                                        print ("we are in deactivated")
                                        # Deactivate the older key
                                        if access_keys[0]['AccessKeyId'] == key['AccessKeyId']:
                                            older_key = access_keys[0]
                                        else:
                                            older_key = access_keys[1]
                                        print (older_key)
                                        if older_key['CreateDate'].replace(tzinfo=timezone.utc) < (now - timedelta(minutes=6)):
                                            iam.update_access_key(AccessKeyId=older_key['AccessKeyId'], Status='Inactive', UserName=user_name)
                                            # Send an email to the user using SES
                                            """message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of six minutes or more older key is deactivated. Thank you."
                                            ses.send_email(
                                                Source='rizwanabegum.d@gmail.com',
                                                Destination={
                                                    'ToAddresses': [
                                                        email_id
                                                    ]
                                                },
                                                Message={
                                                    'Subject': {
                    
                                                    'Data': 'IAM Access Key Rotation Alert'
                                                    },
                                                    'Body': {
                                                        'Text': {
                                                            'Data': message
                                                                }
                                                            }
                                                        }
                                                    ) """   
                                        
                            if last_rotated < eight_minutes_ago :
                                print ("we are in loop of of four minutes")
                                #and last_used < threshold:
                                # Delete the older key if the age is eight minutes
                                if access_keys[0]['AccessKeyId'] == key['AccessKeyId']:
                                    older_key = access_keys[0]
                                else:
                                    older_key = access_keys[1]
                                print (older_key)
                                if older_key['CreateDate'].replace(tzinfo=timezone.utc) < (now - timedelta(minutes=8)):
                                    print ("printing older key")
                                    print (older_key)
                                    iam.delete_access_key(AccessKeyId=older_key['AccessKeyId'], UserName=user_name)
                                    # Send an email to the user using SES
                                    """message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of eight minutes or more hence the older key is deleted Thank you."
                                    ses.send_email(
                                        Source='rizwanabegum.d@gmail.com',
                                        Destination={
                                            'ToAddresses': [
                                                email_id
                                            ]
                                        },
                                        Message={
                                            'Subject': {
                                            'Data': 'IAM Access Key Rotation Alert'
                                            },
                                            'Body': {
                                                'Text': {
                                                    'Data': message
                                                        }
                                                    }
                                                }
                                            )"""
                  
                elif last_rotated < ten_minutes_ago:
                        print ("the keys are not rotated for last ten minutes")
                         # Get the email ID and secret name from the user's tags
                        tags = iam.list_user_tags(UserName=user_name)['Tags']
                        email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                        secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                        user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                        application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                        environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                        if user_type_id == "service":
                            if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                                    # Check if the key has not been rotated in the last six minutes
                            # Send an email to the user using SES
                                """message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has crossed the age of ten minutes or hence the older keys are not rorated, Thank you."
                                ses.send_email(
                                    Source='rizwanabegum.d@gmail.com',
                                    Destination={
                                        'ToAddresses': [
                                                        email_id
                                                ]
                                            },
                                            Message={
                                                'Subject': {
                                                'Data': 'IAM Access Key Rotation Alert'
                                                },
                                                'Body': {
                                                    'Text': {
                                                        'Data': message
                                                            }
                                                        }
                                                    }
                                                )"""
