<?php
// Learnt from:
// https://www.pixelite.co.nz/article/how-to-generate-a-csr-with-sans-in-php/

// The Distinguished Name to be used in the certificate.
$dn = [
    'commonName' => 'example.com',
    'organizationName' => 'ACME Inc',
    'organizationalUnitName' => 'IT',
    'localityName' => 'Seattle',
    'stateOrProvinceName' => 'Washington',
    'countryName' => 'US',
    'emailAddress' => 'foo@example.com',
];

 // Generates a new private key
$privateKey = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 4096
]);
$csrResource = openssl_csr_new($dn, $privateKey, [
    'digest_alg' => 'sha256',
    'config' => 'openssl.cnf',
]);
openssl_csr_export($csrResource, $csrString);
//openssl_pkey_export($privateKey, $privateKeyString, "HY6EQ3RRO5HHQWTLPNTS4ZS5IB6WM3RY");
openssl_pkey_export($privateKey, $privateKeyString);

// Generate user cert
$userCsr = $csrString;
$caCert = file_get_contents('ca.crt');
$caKey = file_get_contents('ca.key');
$userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, [
    'digest_alg'=>'sha256',
    'config' => 'openssl.cnf',
]);
openssl_x509_export($userCert, $userCertOut);

file_put_contents('generated/private.key', $privateKeyString);
file_put_contents('generated/user.crt', $userCertOut);

// Firefox needs pkcs12 formated cert.
openssl_pkcs12_export($userCertOut, $userCertOutPkcs12, $privateKeyString, "zhe0ops");
file_put_contents('generated/user_pkcs12.crt', $userCertOutPkcs12);
?>
