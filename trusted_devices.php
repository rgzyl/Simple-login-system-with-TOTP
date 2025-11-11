<?php
require 'config.php';
require 'functions.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int)$_SESSION['user_id'];

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['device_id'])) {
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $csrf)) {
        $message = 'Błędny token CSRF.';
    } else {
        $deviceId = (int)$_POST['device_id'];

        $stmt = $pdo->prepare("SELECT id, device_token FROM trusted_devices WHERE id = :id AND user_id = :uid LIMIT 1");
        $stmt->execute([
            ':id' => $deviceId,
            ':uid' => $userId,
        ]);
        $device = $stmt->fetch();

        if ($device) {
            $del = $pdo->prepare("DELETE FROM trusted_devices WHERE id = :id AND user_id = :uid");
            $del->execute([
                ':id' => $deviceId,
                ':uid' => $userId,
            ]);

            if (!empty($_COOKIE['trusted_device'])) {
                $currentToken = $_COOKIE['trusted_device'];         
                $currentTokenHash = hash('sha256', $currentToken); 

                if (hash_equals($device['device_token'], $currentTokenHash)) {
                    setcookie('trusted_device', '', [
                        'expires'  => time() - 3600,
                        'path'     => '/',
                        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                        'httponly' => true,
                        'samesite' => 'Lax',
                    ]);
                }
            }

            $message = 'Urządzenie zostało usunięte.';
        } else {
            $message = 'Nie znaleziono takiego urządzenia.';
        }
    }
}

$pdo->exec("DELETE FROM trusted_devices WHERE expires_at IS NOT NULL AND expires_at < NOW()");

$stmt = $pdo->prepare("SELECT id, user_agent_hash, created_at, expires_at
                       FROM trusted_devices
                       WHERE user_id = :uid
                       ORDER BY created_at DESC");
$stmt->execute([':uid' => $userId]);
$devices = $stmt->fetchAll();
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Zaufane urządzenia</title>
</head>
<body>
<h1>Zaufane urządzenia</h1>

<?php if ($message): ?>
    <p style="color:green"><?= htmlspecialchars($message) ?></p>
<?php endif; ?>

<?php if (!$devices): ?>
    <p>Brak zapisanych zaufanych urządzeń.</p>
<?php else: ?>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>Urządzenie</th>
            <th>Dodano</th>
            <th>Wygasa</th>
            <th>Akcje</th>
        </tr>
        <?php foreach ($devices as $d): ?>
            <tr>
                <td>
                    UA hash: <?= htmlspecialchars(substr($d['user_agent_hash'], 0, 12)) ?>…
                </td>
                <td><?= htmlspecialchars($d['created_at'] ?? '-') ?></td>
                <td><?= htmlspecialchars($d['expires_at'] ?? '-') ?></td>
                <td>
                    <form method="post" action="" style="display:inline">
                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
                        <input type="hidden" name="device_id" value="<?= (int)$d['id'] ?>">
                        <button type="submit" onclick="return confirm('Usunąć to urządzenie?')">Usuń</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>
<?php endif; ?>

<p><a href="dashboard.php">Wróć</a></p>
</body>
</html>
