import boto3
from datetime import datetime, timedelta, timezone
import json

def lambda_handler(event, context):

    # Set the IAM and SES clients
    iam = boto3.client('iam')
    ses = boto3.client('ses')

    # Get the current time and time 2 hours ago and 3 hours ago in UTC
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    two_hours_ago = now - timedelta(hours=2)
    three_hours_ago = now - timedelta(hours=3)
    four_hours_ago = now - timedelta(hours=4)
    five_hours_ago = now - timedelta(hours=5)
    threshold = now - timedelta(hours=5)
    if now > one_hour_ago:
        print ("now is greater than one hour ago")
    if now > five_hours_ago:
        print ("now greater than of five hours ago")    
        
    print("printing threshold timing")
    print(threshold)
    print("printing now time")
    print(now)
    

    # Get a list of all IAM users
    users = iam.list_users()
    
    for user in users['Users']:
        user_name = user['UserName']
        access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        #print("printing access keys")
        #print (access_keys) 
        
        if len(access_keys) < 2 and len(access_keys)!= 0:
                # Get a list of all IAM users
                users = iam.list_users()
                # Loop through each access key and check its last rotation time
                for key in access_keys:
                    last_rotated = key['CreateDate'].replace(tzinfo=timezone.utc)
                    AccessKeyId = key['AccessKeyId']
                    last_used = iam.get_access_key_last_used(AccessKeyId=AccessKeyId)['AccessKeyLastUsed'].get('LastUsedDate', 'N/A')
                    print(f"User: {user['UserName']} AccessKeyId: {AccessKeyId} Last used: {last_used}")
                    print ("printing last_rotated")                    
                    print (last_rotated)
                    '''
                    if last_rotated < one_hour_ago:
                        print ("last_rotated is greater than one hour ago")
                    '''
                    if last_rotated < two_hours_ago and last_rotated > five_hours_ago:
                        print ("1")
                        print (last_rotated)
                        print("the keys are not older than five hours")
                        # Check if the key has not been rotated in the last 2 hours
                            #if last_rotated < three_hours_ago:
                            # Get the email ID and secret name from the user's tags
                        tags = iam.list_user_tags(UserName=user_name)['Tags']
                        email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                        secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                        user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                        application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                        environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                        if user_type_id == "service":            
                            if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                                # Create new access key and secret key
                                new_key = iam.create_access_key(UserName=user_name)['AccessKey']
                                    
                                # Store the new keys in AWS Secrets Manager
                                secret_value = {
                                                'AccessKeyId': new_key['AccessKeyId'],
                                                'SecretAccessKey': new_key['SecretAccessKey']
                                }
                                secret_arn = boto3.client('secretsmanager').create_secret(Name=secret_name, SecretString=json.dumps(secret_value))['ARN']
                                    
                                # Send an email to the user using SES
                                message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of 2 hours or more. A new access key ({new_key['AccessKeyId']}) and secret key have been created for you and stored in AWS Secrets Manager (ARN: {secret_arn}). Please use these new credentials for future authentication. Thank you."
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
                                        )
                        
                    # Check if the key has not been rotated in the last 1 hours
                    if last_rotated < one_hour_ago and last_rotated > two_hours_ago:
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
                              message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of 1 hours of age  your keys will be created if the age of two hours the new key will be created and shared through mail"
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
                                          )  
                         
                    if last_rotated < five_hours_ago:
                      print ("3")
                      print (last_rotated)
                      print (five_hours_ago)
                      print ("the keys are not rotated for last five hours")
                        # Get the email ID and secret name from the user's tags
                      tags = iam.list_user_tags(UserName=user_name)['Tags']
                      email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                      secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                      user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                      application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                      environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                      if user_type_id == "service":
                          if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                                  # Check if the key has not been rotated in the last 5 hours
                          # Send an email to the user using SES
                              message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of 5 hours or hence the older keys are not rorated, Thank you."
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
                                              )
                        
                            
    # Loop through each user and check their access keys
    for user in users['Users']:
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
                
                if last_rotated > five_hours_ago:
                  if last_rotated < two_hours_ago:
                    print("we are inside the loop now of below five hours")
                    # Check if the key has not been rotated in the last 2 hours
                    # Get the email ID and secret name from the user's tags
                    tags = iam.list_user_tags(UserName=user_name)['Tags']
                    email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                    secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                    user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                    application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                    environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                    if user_type_id == "service":
                        if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                        # Check if the key has not been rotated in the last 3 hours
                            if last_rotated < three_hours_ago:
                                if last_rotated > four_hours_ago:
                                    #if last_used > threshold:
                                        print ("we are in deactivated")
                                        # Deactivate the older key
                                        if access_keys[0]['AccessKeyId'] == key['AccessKeyId']:
                                            older_key = access_keys[0]
                                        else:
                                            older_key = access_keys[1]
                                        print (older_key)
                                        if older_key['CreateDate'].replace(tzinfo=timezone.utc) < (now - timedelta(hours=3)):
                                            iam.update_access_key(AccessKeyId=older_key['AccessKeyId'], Status='Inactive', UserName=user_name)
                                            # Send an email to the user using SES
                                            message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of 3 hours or more older key is deactivated. Thank you."
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
                                                    )    
                                        
                            if last_rotated < four_hours_ago :
                                print ("we are in loop of of four hours")
                                #and last_used < threshold:
                                # Delete the older key if the age is 4 hours
                                if access_keys[0]['AccessKeyId'] == key['AccessKeyId']:
                                    older_key = access_keys[0]
                                else:
                                    older_key = access_keys[1]
                                print (older_key)
                                if older_key['CreateDate'].replace(tzinfo=timezone.utc) < (now - timedelta(hours=4)):
                                    print ("printing older key")
                                    print (older_key)
                                    iam.delete_access_key(AccessKeyId=older_key['AccessKeyId'], UserName=user_name)
                                    # Send an email to the user using SES
                                    message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has reached the age of 4 hours or more hence the older key is deleted Thank you."
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
                                            )
                  
                elif last_rotated < five_hours_ago:
                        print ("the keys are not rotated for last five hours")
                         # Get the email ID and secret name from the user's tags
                        tags = iam.list_user_tags(UserName=user_name)['Tags']
                        email_id = next((tag['Value'] for tag in tags if tag['Key'] == 'email_id'), None)
                        secret_name = next((tag['Value'] for tag in tags if tag['Key'] == 'secretnames'), None)
                        user_type_id = next((tag['Value'] for tag in tags if tag['Key'] == 'user_type'), None)
                        application_id = next((tag['Value'] for tag in tags if tag['Key'] == 'application'), None)
                        environment = next((tag['Value'] for tag in tags if tag['Key'] == 'environment'), None)
                        if user_type_id == "service":
                            if email_id is not None and secret_name is not None and application_id is not None and environment is not None:
                                    # Check if the key has not been rotated in the last 3 hours
                            # Send an email to the user using SES
                                message = f"Hello {user_name}, your IAM access key ({key['AccessKeyId']}) has crossed the age of 5 hours or hence the older keys are not rorated, Thank you."
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
                                                )  
                    
                
    
