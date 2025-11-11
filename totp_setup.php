<?php
require 'config.php';
require 'functions.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int)$_SESSION['user_id'];
$error = '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

$secret = $_SESSION['totp_setup_secret'] ?? null;

if ($secret === null) {
    $stmt = $pdo->prepare("SELECT totp_secret, totp_confirmed FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $userId]);
    $u = $stmt->fetch();
    if (!$u) {
        header('Location: dashboard.php');
        exit;
    }
    if ((int)$u['totp_confirmed'] === 1) {
        header('Location: dashboard.php');
        exit;
    }
    $encSecret = $u['totp_secret'];
    $secret = decrypt_totp_secret($encSecret);
}

if (empty($_SESSION['csrf_token_totp_setup'])) {
    $_SESSION['csrf_token_totp_setup'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token_totp_setup']) || !hash_equals($_SESSION['csrf_token_totp_setup'], $csrf)) {
        $error = 'Nie udało się potwierdzić kodu. Odśwież stronę i spróbuj ponownie.';
    } else {

        $_SESSION['csrf_token_totp_setup'] = bin2hex(random_bytes(32));

        if (!rate_limit_allow($pdo, 'totp_setup', $ip, $userId, 5, 5)) {
            $error = 'Zbyt wiele prób. Spróbuj za kilka minut.';
        } else {
            $code = trim($_POST['code'] ?? '');
            if (verify_totp($secret, $code)) {
                rate_limit_log($pdo, 'totp_setup', $ip, $userId);

                $stmt = $pdo->prepare("UPDATE users SET totp_confirmed = 1 WHERE id = :id");
                $stmt->execute([':id' => $userId]);

                $backupCodes = generate_backup_codes(5);
                store_backup_codes($pdo, $userId, $backupCodes);
                $_SESSION['just_generated_backup_codes'] = $backupCodes;

                unset($_SESSION['totp_setup_user_id'], $_SESSION['totp_setup_secret']);

                header('Location: show_backup_codes.php');
                exit;
            } else {
                rate_limit_log($pdo, 'totp_setup', $ip, $userId);
                $error = 'Kod z aplikacji jest nieprawidłowy.';
            }
        }
    }
}

$stmt = $pdo->prepare("SELECT email FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $userId]);
$user = $stmt->fetch();
$email = $user ? $user['email'] : ('user'.$userId);

$issuer = urlencode('MojaAplikacja');
$label = urlencode('MojaAplikacja:' . $email);
$otpauth = "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}";
$qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' . urlencode($otpauth);
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Ustaw 2FA</title></head>
<body>
<h1>Ustaw 2FA ponownie</h1>
<p>Zeskanuj kod i wpisz pierwszy kod z aplikacji.</p>
<p><img src="<?= htmlspecialchars($qrUrl) ?>" alt="QR TOTP"></p>
<p>Secret: <strong><?= htmlspecialchars($secret) ?></strong></p>

<?php if ($error): ?>
<p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="post" action="">
    <label>Kod z aplikacji: <input type="text" name="code" required></label><br>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_totp_setup'], ENT_QUOTES, 'UTF-8') ?>">
    <button type="submit">Potwierdź</button>
</form>
</body>
</html>
