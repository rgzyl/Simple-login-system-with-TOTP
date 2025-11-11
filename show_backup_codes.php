<?php
require 'config.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$codes = $_SESSION['just_generated_backup_codes'] ?? [];
unset($_SESSION['just_generated_backup_codes']);
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Kody zapasowe</title></head>
<body>
<h1>Twoje kody zapasowe</h1>
<p>Zapisz je w bezpiecznym miejscu. Każdy działa tylko raz.</p>
<?php if ($codes): ?>
    <ul>
        <?php foreach ($codes as $c): ?>
            <li><code><?= htmlspecialchars($c) ?></code></li>
        <?php endforeach; ?>
    </ul>
<?php else: ?>
    <p>Brak nowych kodów.</p>
<?php endif; ?>

<p><a href="dashboard.php">Przejdź do panelu</a></p>
</body>
</html>
