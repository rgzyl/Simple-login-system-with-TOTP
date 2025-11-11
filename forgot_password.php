<?php
require 'config.php';
require 'functions.php';

$info = '';
$error = '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $info = 'Jeśli podany e-mail istnieje w naszym systemie, wysłaliśmy link do resetu hasła.';
    } else {
        $email = trim($_POST['email'] ?? '');
		
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        if (!rate_limit_allow($pdo, 'password_reset', $ip, null, 3, 15)) {
            $info = 'Jeśli podany e-mail istnieje w naszym systemie, wysłaliśmy link do resetu hasła.';
        } else {
            if ($email !== '') {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
                $stmt->execute([':email' => $email]);
                $user = $stmt->fetch();

                if ($user) {
                    $userId = (int)$user['id'];

                    $rawToken = bin2hex(random_bytes(32)); // do linka
                    $tokenHash = password_hash($rawToken, PASSWORD_DEFAULT);
                    $expiresAt = (new DateTime('+1 hour'))->format('Y-m-d H:i:s');

                    $pdo->prepare("UPDATE password_resets SET used_at = NOW() WHERE user_id = :uid AND used_at IS NULL")
                        ->execute([':uid' => $userId]);

                    $stmt = $pdo->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at) 
                                           VALUES (:uid, :th, :exp)");
                    $stmt->execute([
                        ':uid' => $userId,
                        ':th' => $tokenHash,
                        ':exp' => $expiresAt,
                    ]);

                    $resetLink = 'https://twoja-domena.pl/reset_password.php?token=' . urlencode($rawToken);

                    @mail($email, 'Reset hasła', "Kliknij, aby zresetować hasło: $resetLink");

                    log_login($pdo, $userId, 'password_reset_request', true, false);
                    rate_limit_log($pdo, 'password_reset', $ip, $userId);
                } else {
                    rate_limit_log($pdo, 'password_reset', $ip, null);
                }

                $info = 'Jeśli podany e-mail istnieje w naszym systemie, wysłaliśmy link do resetu hasła.';
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Reset hasła</title></head>
<body>
<h1>Reset hasła</h1>
<?php if ($info): ?>
    <p><?= htmlspecialchars($info) ?></p>
<?php else: ?>
    <form method="post" action="">
        <label>E-mail: <input type="email" name="email" required></label><br>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
        <button type="submit">Wyślij link resetujący</button>
    </form>
<?php endif; ?>
</body>
</html>
