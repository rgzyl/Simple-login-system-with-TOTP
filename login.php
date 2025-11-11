<?php
require 'config.php';
require 'functions.php';

if (!empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (empty($_SESSION['csrf_token_login'])) {
    $_SESSION['csrf_token_login'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token_login']) || !hash_equals($_SESSION['csrf_token_login'], $csrf)) {
        $error = 'Nie udało się zalogować. Odśwież stronę i spróbuj ponownie.';
    } else {
        $_SESSION['csrf_token_login'] = bin2hex(random_bytes(32));

        $email = $_POST['email'] ?? '';
        $pass  = $_POST['password'] ?? '';

        if (!rate_limit_allow($pdo, 'password', $ip, null, 5, 10)) {
            $error = 'Zbyt wiele prób logowania z tego adresu. Spróbuj za kilka minut.';
        } else {
            $stmt = $pdo->prepare("SELECT id, password_hash, totp_confirmed FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();
            $userId = $user ? (int)$user['id'] : null;

            if ($userId !== null && !rate_limit_allow($pdo, 'password', $ip, $userId, 5, 10)) {
                $error = 'Zbyt wiele prób logowania na to konto. Spróbuj za kilka minut.';
            } else {
                if (!$user || !password_verify($pass, $user['password_hash'])) {

                    rate_limit_log($pdo, 'password', $ip, $userId);

                    if ($user) {
                        log_login($pdo, $userId, 'password', false);
                    }

                    $error = 'Niepoprawny email lub hasło.';
                } else {
                    rate_limit_log($pdo, 'password', $ip, $userId);
                    log_login($pdo, $userId, 'password', true);

                    $trustedUserId = check_trusted_device($pdo);

                    if ($trustedUserId && $trustedUserId === $userId) {
                        $_SESSION['user_id'] = $userId;

                        log_login($pdo, $userId, 'totp', true, true);

                        header('Location: dashboard.php');
                        exit;
                    }

                    if ((int)$user['totp_confirmed'] === 0) {
                        unset($_SESSION['pending_user_id'], $_SESSION['remember_device']);
                        $error = 'Twoje 2FA nie jest jeszcze potwierdzone.';
                    } else {
                        $_SESSION['pending_user_id'] = $userId;
                        $_SESSION['remember_device'] = !empty($_POST['remember_device']);
                        header('Location: totp.php');
                        exit;
                    }
                }
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Logowanie</title></head>
<body>
<h1>Logowanie</h1>
<?php if ($error): ?>
<p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>
<form method="post" action="">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Hasło: <input type="password" name="password" required></label><br>
    <label><input type="checkbox" name="remember_device" value="1"> Zaufaj temu urządzeniu (pomiń TOTP następnym razem)</label><br>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_login'], ENT_QUOTES, 'UTF-8') ?>">
    <button type="submit">Dalej</button>
	<p><a href="forgot_password.php">Przypomnij hasło</a></p>
	<p><a href="register.php">Utwórz konto</a></p>
</form>
</body>
</html>
