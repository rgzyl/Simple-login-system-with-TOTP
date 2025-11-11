<?php
require 'config.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int)$_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT ip, user_agent, success, step, trusted_skipped, created_at
                       FROM login_logs
                       WHERE user_id = :uid
                       ORDER BY created_at DESC
                       LIMIT 20");
$stmt->execute([':uid' => $userId]);
$logs = $stmt->fetchAll();
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Logi bezpieczeństwa</title></head>
<body>
<h1>Ostatnie logowania</h1>
<table border="1" cellpadding="5" cellspacing="0">
    <tr>
        <th>Data</th>
        <th>Krok</th>
        <th>Sukces</th>
        <th>IP</th>
        <th>Urządzenie</th>
        <th>TOTP pominięte?</th>
    </tr>
    <?php foreach ($logs as $row): ?>
        <tr>
            <td><?= htmlspecialchars($row['created_at']) ?></td>
            <td><?= htmlspecialchars($row['step']) ?></td>
            <td><?= $row['success'] ? 'tak' : 'nie' ?></td>
            <td><?= htmlspecialchars($row['ip']) ?></td>
            <td><?= htmlspecialchars($row['user_agent']) ?></td>
            <td><?= $row['trusted_skipped'] ? 'tak' : 'nie' ?></td>
        </tr>
    <?php endforeach; ?>
</table>

<p><a href="dashboard.php">Wróć</a></p>
</body>
</html>
