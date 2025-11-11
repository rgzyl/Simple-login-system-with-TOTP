<?php
require 'config.php';
if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Panel</title></head>
<body>
<h1>Witaj!</h1>
<p>Jesteś zalogowany.</p>
<p><a href="logout.php">Wyloguj</a></p>
<p><a href="security_log.php">Zobacz ostatnie logowania</a></p>
<p><a href="trusted_devices.php">Zaufane urządzenia</a></p>
<p><a href="change_password.php">Zmień hasło</a></p>

</body>
</html>
