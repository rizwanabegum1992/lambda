<?php
require 'vendor/autoload.php';
require __DIR__ . '/vendor/autoload.php';

use Aws\SecretsManager\SecretsManagerClient;
use Aws\Kms\KmsClient;

function decode_and_decrypt_secret($secret_name, $key_id)
{
    // Retrieve the secret value from AWS Secrets Manager
    $secretsManagerClient = new SecretsManagerClient([
        'version' => 'latest',
        'region' => 'ap-south-1' // Replace with your desired region
    ]);
    
    $secret = $secretsManagerClient->getSecretValue([
        'SecretId' => $secret_name
    ]);
    
    $secret_data = json_decode($secret['SecretString'], true);

    // Decode the base64-encoded secret values
    $encoded_access_key_id = $secret_data['AccessKeyId'];
    $encoded_secret_access_key = $secret_data['SecretAccessKey'];
    $decoded_access_key_id = base64_decode($encoded_access_key_id);
    $decoded_secret_access_key = base64_decode($encoded_secret_access_key);

    // Decrypt the decoded secret values using AWS Key Management Service (KMS)
    $kmsClient = new KmsClient([
        'version' => 'latest',
        'region' => 'ap-south-1' // Replace with your desired region
    ]);

    $decrypted_access_key_id = $kmsClient->decrypt([
        'KeyId' => $key_id,
        'CiphertextBlob' => $decoded_access_key_id
    ])['Plaintext'];

    $decrypted_secret_access_key = $kmsClient->decrypt([
        'KeyId' => $key_id,
        'CiphertextBlob' => $decoded_secret_access_key
    ])['Plaintext'];

    return [$decrypted_access_key_id, $decrypted_secret_access_key];
}

// Usage example
$secret_name = 'serviceuser_1';
$key_id = '99db2bd8-b54f-438a-8ca8-f4d21abb0d30';

[$access_key_id, $secret_access_key] = decode_and_decrypt_secret($secret_name, $key_id);

echo "Decoded Access Key ID: $access_key_id\n";
echo "Decoded Secret Access Key: $secret_access_key\n";
?>
