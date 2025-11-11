<?php
require 'config.php';
require 'functions.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int)$_SESSION['user_id'];
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$error = '';
$success = '';

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$stmt = $pdo->prepare("SELECT password_hash, totp_secret, totp_confirmed FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $userId]);
$user = $stmt->fetch();
if (!$user) {
    header('Location: login.php');
    exit;
}

$hasTotp = (int)$user['totp_confirmed'] === 1;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!rate_limit_allow($pdo, 'password_change', $ip, $userId, 3, 10)) {
        $error = 'Zbyt wiele prób zmiany hasła. Spróbuj za kilka minut.';
    } else {
        $csrf = $_POST['csrf'] ?? '';
        if (!hash_equals($_SESSION['csrf'], $csrf)) {
            $error = 'Błędny token CSRF.';
        } else {
            $oldPass = $_POST['old_password'] ?? '';
            $newPass = $_POST['new_password'] ?? '';
            $newPass2 = $_POST['new_password2'] ?? '';
            $totpCode = $_POST['totp_code'] ?? '';

            if (!password_verify($oldPass, $user['password_hash'])) {
                $error = 'Stare hasło jest nieprawidłowe.';
                rate_limit_log($pdo, 'password_change', $ip, $userId);
            } elseif (strlen($newPass) < 8) {
                $error = 'Nowe hasło musi mieć co najmniej 8 znaków.';
                rate_limit_log($pdo, 'password_change', $ip, $userId);
            } elseif ($newPass !== $newPass2) {
                $error = 'Nowe hasła nie są takie same.';
                rate_limit_log($pdo, 'password_change', $ip, $userId);
            } else {
                if ($hasTotp) {
                    $secret = decrypt_totp_secret($user['totp_secret']);
                    if (!$secret || !verify_totp($secret, trim($totpCode))) {
                        $error = 'Kod TOTP jest nieprawidłowy.';
                        rate_limit_log($pdo, 'password_change', $ip, $userId);
                    } else {
                        $hash = password_hash($newPass, PASSWORD_DEFAULT);
                        $upd = $pdo->prepare("UPDATE users SET password_hash = :ph WHERE id = :id");
                        $upd->execute([
                            ':ph' => $hash,
                            ':id' => $userId,
                        ]);

                        $del = $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = :id");
                        $del->execute([':id' => $userId]);

                        log_login($pdo, $userId, 'password_change', true, false);

                        rate_limit_log($pdo, 'password_change', $ip, $userId);

                        session_destroy();

                        $success = 'Hasło zostało zmienione. Zaloguj się ponownie.';
                    }
                } else {
                    $hash = password_hash($newPass, PASSWORD_DEFAULT);
                    $upd = $pdo->prepare("UPDATE users SET password_hash = :ph WHERE id = :id");
                    $upd->execute([
                        ':ph' => $hash,
                        ':id' => $userId,
                    ]);

                    $del = $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = :id");
                    $del->execute([':id' => $userId]);

                    log_login($pdo, $userId, 'password_change', true, false);
                    rate_limit_log($pdo, 'password_change', $ip, $userId);

                    session_destroy();

                    $success = 'Hasło zostało zmienione. Zaloguj się ponownie.';
                }
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Zmiana hasła</title></head>
<body>
<h1>Zmiana hasła</h1>

<?php if ($error): ?>
    <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<?php if ($success): ?>
    <p style="color:green"><?= htmlspecialchars($success) ?></p>
    <p><a href="login.php">Przejdź do logowania</a></p>
<?php else: ?>
    <form method="post" action="">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
        <label>Stare hasło: <input type="password" name="old_password" required></label><br>
        <label>Nowe hasło: <input type="password" name="new_password" required></label><br>
        <label>Powtórz nowe hasło: <input type="password" name="new_password2" required></label><br>

        <?php if ($hasTotp): ?>
            <label>Kod TOTP: <input type="text" name="totp_code" required></label><br>
        <?php endif; ?>

        <button type="submit">Zmień hasło</button>
    </form>
<?php endif; ?>

<p><a href="dashboard.php">Wróć</a></p>
</body>
</html>
