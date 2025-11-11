<?php
require 'config.php';
require 'functions.php';

if (empty($_SESSION['pending_user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int)$_SESSION['pending_user_id'];
$error = '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (empty($_SESSION['csrf_token_totp'])) {
    $_SESSION['csrf_token_totp'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token_totp']) || !hash_equals($_SESSION['csrf_token_totp'], $csrf)) {
        $error = 'Nie udało się zweryfikować kodu. Odśwież stronę i spróbuj ponownie.';
    } else {
        $_SESSION['csrf_token_totp'] = bin2hex(random_bytes(32));

        if (isset($_POST['use_backup'])) {

            if (!rate_limit_allow($pdo, 'backup', $ip, $userId, 5, 10)) {
                $error = 'Zbyt wiele prób użycia kodu zapasowego. Spróbuj za chwilę.';
            } else {
                $backupCode = trim($_POST['code'] ?? '');

                if ($backupCode !== '' && verify_backup_code($pdo, $userId, $backupCode)) {

                    rate_limit_log($pdo, 'backup', $ip, $userId);

                    log_login($pdo, $userId, 'backup', true, false);

                    $_SESSION['user_id'] = $userId;
                    unset($_SESSION['pending_user_id']);

                    start_totp_reset($pdo, $userId);

                    header('Location: totp_setup.php');
                    exit;

                } else {
                    rate_limit_log($pdo, 'backup', $ip, $userId);

                    log_login($pdo, $userId, 'backup', false, false);
                    $error = 'Kod zapasowy nieprawidłowy lub już użyty.';
                }
            }

        } else {
            if (!rate_limit_allow($pdo, 'totp', $ip, $userId, 5, 5)) {
                $error = 'Zbyt wiele prób wpisania kodu. Spróbuj za chwilę.';
            } else {
                $code = trim($_POST['code'] ?? '');

                $stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = :id LIMIT 1");
                $stmt->execute([':id' => $userId]);
                $user = $stmt->fetch();

                $plainSecret = null;
                if ($user) {
                    $plainSecret = decrypt_totp_secret($user['totp_secret']);
                }

                if ($user && $plainSecret && verify_totp($plainSecret, $code)) {

                    rate_limit_log($pdo, 'totp', $ip, $userId);

                    log_login($pdo, $userId, 'totp', true, false);

                    $_SESSION['user_id'] = $userId;
                    unset($_SESSION['pending_user_id']);

                    if (!empty($_SESSION['remember_device'])) {
                        add_trusted_device($pdo, $userId);
                        unset($_SESSION['remember_device']);
                    }

                    header('Location: dashboard.php');
                    exit;

                } else {
                    rate_limit_log($pdo, 'totp', $ip, $userId);

                    log_login($pdo, $userId, 'totp', false, false);
                    $error = 'Niepoprawny kod TOTP.';
                }
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Weryfikacja 2FA</title>
</head>
<body>
<h1>Weryfikacja 2FA</h1>

<?php if ($error): ?>
    <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<p>Podaj kod z aplikacji TOTP <strong>albo</strong> kod zapasowy.</p>

<form method="post" action="">
    <label>Kod: <input type="text" name="code" required></label><br><br>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_totp'], ENT_QUOTES, 'UTF-8') ?>">
    <button type="submit" name="use_totp" value="1">Użyj kodu TOTP</button>
    <button type="submit" name="use_backup" value="1">Użyj kodu zapasowego</button>
</form>

</body>
</html>
