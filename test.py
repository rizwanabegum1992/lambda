import boto3
import base64
import json

def decode_and_decrypt_secret(secret_name, key_id):
    # Retrieve the secret value from AWS Secrets Manager
    secret_value = boto3.client('secretsmanager').get_secret_value(SecretId=secret_name)['SecretString']

    # Parse the secret value from JSON format
    secret_data = json.loads(secret_value)

    # Decode the base64-encoded secret values
    encoded_access_key_id = secret_data['AccessKeyId']
    encoded_secret_access_key = secret_data['SecretAccessKey']
    decoded_access_key_id = base64.b64decode(encoded_access_key_id)
    decoded_secret_access_key = base64.b64decode(encoded_secret_access_key)

    # Decrypt the decoded secret values using AWS Key Management Service (KMS)
    kms_client = boto3.client('kms')
    decrypted_access_key_id = kms_client.decrypt(KeyId=key_id, CiphertextBlob=decoded_access_key_id)['Plaintext']
    decrypted_secret_access_key = kms_client.decrypt(KeyId=key_id, CiphertextBlob=decoded_secret_access_key)['Plaintext']

    return decrypted_access_key_id, decrypted_secret_access_key

# Usage example
secret_name = 'user_2'
key_id = 'a5969944-505c-4fae-840e-489199b5d42a'

access_key_id, secret_access_key = decode_and_decrypt_secret(secret_name, key_id)

print(f"Decoded Access Key ID: {access_key_id}")
print(f"Decoded Secret Access Key: {secret_access_key}")
