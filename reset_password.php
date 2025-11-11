<?php
require 'config.php';
require 'functions.php';

$token = $_GET['token'] ?? '';
$token = trim($token);
$error = '';
$success = '';
$canReset = false;
$userId = null;
$resetRowId = null;
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if ($token !== '') {
    $stmt = $pdo->prepare("SELECT id, user_id, token_hash, expires_at FROM password_resets 
                           WHERE used_at IS NULL AND expires_at > NOW()");
    $stmt->execute();
    $rows = $stmt->fetchAll();

    foreach ($rows as $row) {
        if (password_verify($token, $row['token_hash'])) {
            $canReset = true;
            $userId = (int)$row['user_id'];
            $resetRowId = (int)$row['id'];
            break;
        }
    }

    if (!$canReset) {
        $error = 'Link resetujący jest nieprawidłowy lub wygasł.';
    }
} else {
    $error = 'Brak tokenu resetującego.';
}

if ($canReset && empty($_SESSION['csrf_token_reset'])) {
    $_SESSION['csrf_token_reset'] = bin2hex(random_bytes(32));
}

if ($canReset && $_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token_reset']) || !hash_equals($_SESSION['csrf_token_reset'], $csrf)) {
        $error = 'Nie udało się zapisać hasła. Odśwież stronę i spróbuj ponownie.';
    } else {

        $_SESSION['csrf_token_reset'] = bin2hex(random_bytes(32));

        if (!rate_limit_allow($pdo, 'password_reset_apply', $ip, $userId, 5, 10)) {
            $error = 'Zbyt wiele prób ustawienia hasła. Spróbuj za kilka minut.';
        } else {
            $pass1 = $_POST['password'] ?? '';
            $pass2 = $_POST['password2'] ?? '';

            if ($pass1 === '' || strlen($pass1) < 8) {
                $error = 'Hasło musi mieć co najmniej 8 znaków.';
                rate_limit_log($pdo, 'password_reset_apply', $ip, $userId);
            } elseif ($pass1 !== $pass2) {
                $error = 'Hasła nie są takie same.';
                rate_limit_log($pdo, 'password_reset_apply', $ip, $userId);
            } else {
                $hash = password_hash($pass1, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password_hash = :ph WHERE id = :id");
                $stmt->execute([
                    ':ph' => $hash,
                    ':id' => $userId,
                ]);

                $stmt = $pdo->prepare("UPDATE password_resets SET used_at = NOW() WHERE id = :id");
                $stmt->execute([':id' => $resetRowId]);

                $stmt = $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = :id");
                $stmt->execute([':id' => $userId]);

                log_login($pdo, $userId, 'password_reset', true, false);

                rate_limit_log($pdo, 'password_reset_apply', $ip, $userId);

                session_destroy();

                $success = 'Hasło zostało zmienione. Zaloguj się ponownie.';
                $canReset = false;
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Ustaw nowe hasło</title></head>
<body>
<h1>Ustaw nowe hasło</h1>

<?php if ($error): ?>
    <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<?php if ($success): ?>
    <p style="color:green"><?= htmlspecialchars($success) ?></p>
    <p><a href="login.php">Przejdź do logowania</a></p>
<?php elseif ($canReset): ?>
    <form method="post" action="">
        <label>Nowe hasło: <input type="password" name="password" required></label><br>
        <label>Powtórz hasło: <input type="password" name="password2" required></label><br>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_reset'], ENT_QUOTES, 'UTF-8') ?>">
        <button type="submit">Zapisz</button>
    </form>
<?php endif; ?>

</body>
</html>
