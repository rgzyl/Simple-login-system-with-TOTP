<?php
$pdo = new PDO(
    'mysql:host=localhost;dbname=test;charset=utf8mb4',
    'root',
    '',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);

session_start();

//echo base64_encode(random_bytes(32));
const TOTP_ENC_KEY = 'LDl4cJw/6dVHJFhApJMLCZdB0O2KG+aNmP5jJJ39xlY=';

function getTotpKey(): string {
    return base64_decode(TOTP_ENC_KEY);
}

const TRUSTED_COOKIE_NAME = 'trusted_device';
const TRUSTED_COOKIE_LIFETIME = 60 * 60 * 24 * 30; 
const TRUSTED_TOKEN_BYTES = 32; 
