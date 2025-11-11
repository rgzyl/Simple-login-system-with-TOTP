<?php
function base32_decode_custom(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper($b32);
    $bits = '';
    for ($i = 0; $i < strlen($b32); $i++) {
        $val = strpos($alphabet, $b32[$i]);
        if ($val === false) continue;
        $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
    }
    $result = '';
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $result .= chr(bindec(substr($bits, $i, 8)));
    }
    return $result;
}

function generate_totp(string $secret, int $timeStep = 30, int $digits = 6): string {
    $counter = floor(time() / $timeStep);
    $key = base32_decode_custom($secret);
    $binaryCounter = pack('N*', 0) . pack('N*', $counter);
    $hash = hash_hmac('sha1', $binaryCounter, $key, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $truncatedHash = substr($hash, $offset, 4);
    $value = unpack('N', $truncatedHash)[1] & 0x7FFFFFFF;
    $mod = 10 ** $digits;
    return str_pad((string)($value % $mod), $digits, '0', STR_PAD_LEFT);
}

function verify_totp(string $secret, string $code, int $window = 1): bool {
    $code = trim($code);
    for ($i = -$window; $i <= $window; $i++) {
        $testTime = time() + ($i * 30);
        $counter = floor($testTime / 30);
        $key = base32_decode_custom($secret);
        $binaryCounter = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $binaryCounter, $key, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncatedHash = substr($hash, $offset, 4);
        $value = unpack('N', $truncatedHash)[1] & 0x7FFFFFFF;
        $mod = 10 ** 6;
        $calcCode = str_pad((string)($value % $mod), 6, '0', STR_PAD_LEFT);
        if (hash_equals($calcCode, $code)) {
            return true;
        }
    }
    return false;
}

function generate_totp_secret(int $length = 16): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $secret;
}

function check_trusted_device(PDO $pdo): ?int {
    if (empty($_COOKIE[TRUSTED_COOKIE_NAME])) {
        return null;
    }
    $token = $_COOKIE[TRUSTED_COOKIE_NAME];

    $tokenHash = hash('sha256', $token);
    $uaHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'no-ua');

    $stmt = $pdo->prepare("SELECT user_id FROM trusted_devices 
                           WHERE device_token = :token AND user_agent_hash = :uah 
                             AND expires_at > NOW() 
                           LIMIT 1");
    $stmt->execute([
        ':token' => $tokenHash,
        ':uah' => $uaHash,
    ]);
    $row = $stmt->fetch();
    return $row ? (int)$row['user_id'] : null;
}

function add_trusted_device(PDO $pdo, int $userId): void {
    $rawToken = bin2hex(random_bytes(TRUSTED_TOKEN_BYTES)); 
    $tokenHash = hash('sha256', $rawToken);
    $uaHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'no-ua');

    $expiresAt = (new DateTime('+30 days'))->format('Y-m-d H:i:s');

    $stmt = $pdo->prepare("INSERT INTO trusted_devices (user_id, device_token, user_agent_hash, expires_at)
                           VALUES (:uid, :token, :uah, :exp)");
    $stmt->execute([
        ':uid' => $userId,
        ':token' => $tokenHash,
        ':uah' => $uaHash,
        ':exp' => $expiresAt,
    ]);

    setcookie(
        TRUSTED_COOKIE_NAME,
        $rawToken,
        [
            'expires' => time() + TRUSTED_COOKIE_LIFETIME,
            'path' => '/',
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
}


function generate_backup_codes(int $count = 5): array {
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $codes[] = strtoupper(bin2hex(random_bytes(4))); 
    }
    return $codes;
}

function store_backup_codes(PDO $pdo, int $userId, array $codes): void {
    $stmt = $pdo->prepare("INSERT INTO backup_codes (user_id, code_hash) VALUES (:uid, :hash)");
    foreach ($codes as $code) {
        $stmt->execute([
            ':uid' => $userId,
            ':hash' => password_hash($code, PASSWORD_DEFAULT),
        ]);
    }
}

function verify_backup_code(PDO $pdo, int $userId, string $code): bool {
    $stmt = $pdo->prepare("SELECT id, code_hash FROM backup_codes 
                           WHERE user_id = :uid AND used_at IS NULL");
    $stmt->execute([':uid' => $userId]);
    $codes = $stmt->fetchAll();

    foreach ($codes as $row) {
        if (password_verify($code, $row['code_hash'])) {
            $update = $pdo->prepare("UPDATE backup_codes SET used_at = NOW() WHERE id = :id");
            $update->execute([':id' => $row['id']]);
            return true;
        }
    }
    return false;
}

function start_totp_reset(PDO $pdo, int $userId): void {
    $newSecret = generate_totp_secret();
    $enc = encrypt_totp_secret($newSecret);

    $stmt = $pdo->prepare("UPDATE users SET totp_secret = :secret, totp_confirmed = 0 WHERE id = :id");
    $stmt->execute([
        ':secret' => $enc,
        ':id' => $userId,
    ]);

    $_SESSION['totp_setup_user_id'] = $userId;
    $_SESSION['totp_setup_secret'] = $newSecret;
}


function log_login(PDO $pdo, int $userId, string $step, bool $success, bool $trustedSkipped = false): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'no-ua', 0, 255);

    $stmt = $pdo->prepare("INSERT INTO login_logs (user_id, ip, user_agent, success, step, trusted_skipped)
                           VALUES (:uid, :ip, :ua, :success, :step, :ts)");
    $stmt->execute([
        ':uid' => $userId,
        ':ip' => $ip,
        ':ua' => $ua,
        ':success' => $success ? 1 : 0,
        ':step' => $step,
        ':ts' => $trustedSkipped ? 1 : 0,
    ]);
}


function encrypt_totp_secret(string $plain): string {
    $key = getTotpKey();
    $iv = random_bytes(12);
    $cipher = openssl_encrypt(
        $plain,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );
    return base64_encode($iv) . ':' . base64_encode($cipher) . ':' . base64_encode($tag);
}

function decrypt_totp_secret(string $stored): ?string {
    $key = getTotpKey();
    $parts = explode(':', $stored);
    if (count($parts) !== 3) {
        return null; 
    }
    [$ivB64, $cipherB64, $tagB64] = $parts;
    $iv = base64_decode($ivB64);
    $cipher = base64_decode($cipherB64);
    $tag = base64_decode($tagB64);

    $plain = openssl_decrypt(
        $cipher,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );
    return $plain === false ? null : $plain;
}

function rate_limit_allow(PDO $pdo, string $action, ?string $ip, ?int $userId, int $limit, int $minutes): bool {
    $ip = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $since = (new DateTime("-{$minutes} minutes"))->format('Y-m-d H:i:s');

    if ($userId) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts
                               WHERE action = :action
                                 AND created_at >= :since
                                 AND (ip = :ip OR user_id = :uid)");
        $stmt->execute([
            ':action' => $action,
            ':since' => $since,
            ':ip' => $ip,
            ':uid' => $userId,
        ]);
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts
                               WHERE action = :action
                                 AND created_at >= :since
                                 AND ip = :ip");
        $stmt->execute([
            ':action' => $action,
            ':since' => $since,
            ':ip' => $ip,
        ]);
    }

    $count = (int)$stmt->fetchColumn();
    return $count < $limit;
}

function rate_limit_log(PDO $pdo, string $action, ?string $ip, ?int $userId): void {
    $ip = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $stmt = $pdo->prepare("INSERT INTO login_attempts (user_id, ip, action) VALUES (:uid, :ip, :action)");
    $stmt->execute([
        ':uid' => $userId,
        ':ip' => $ip,
        ':action' => $action,
    ]);
}
