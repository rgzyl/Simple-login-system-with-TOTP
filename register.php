<?php
require 'config.php';
require 'functions.php';

$error = '';
$step = 1;
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (!empty($_SESSION['totp_setup_user_id']) && !empty($_SESSION['totp_setup_secret'])) {
    $step = 2;
}

if (empty($_SESSION['csrf_token_register'])) {
    $_SESSION['csrf_token_register'] = bin2hex(random_bytes(32));
}
if (empty($_SESSION['csrf_token_register_totp'])) {
    $_SESSION['csrf_token_register_totp'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['totp_code']) && $step === 2) {

        $csrf = $_POST['csrf_token'] ?? '';
        if (empty($_SESSION['csrf_token_register_totp']) || !hash_equals($_SESSION['csrf_token_register_totp'], $csrf)) {
            $error = 'Nie udało się potwierdzić kodu. Odśwież stronę i spróbuj ponownie.';
            $step = 2;
        } else {

            $userId = (int)$_SESSION['totp_setup_user_id'];
            $secret = $_SESSION['totp_setup_secret'];

            $_SESSION['csrf_token_register_totp'] = bin2hex(random_bytes(32));

            if (!rate_limit_allow($pdo, 'register_totp', $ip, $userId, 5, 5)) {
                $error = 'Zbyt wiele prób potwierdzenia kodu. Spróbuj za chwilę.';
                $step = 2;
            } else {
                $code = trim($_POST['totp_code']);

                if (verify_totp($secret, $code)) {
                    $stmt = $pdo->prepare("UPDATE users SET totp_confirmed = 1 WHERE id = :id");
                    $stmt->execute([':id' => $userId]);

                    $backupCodes = generate_backup_codes(5);
                    store_backup_codes($pdo, $userId, $backupCodes);

                    $_SESSION['just_generated_backup_codes'] = $backupCodes;

                    $_SESSION['user_id'] = $userId;

                    unset($_SESSION['totp_setup_user_id'], $_SESSION['totp_setup_secret']);

                    rate_limit_log($pdo, 'register_totp', $ip, $userId);

                    header('Location: show_backup_codes.php');
                    exit;

                } else {
                    rate_limit_log($pdo, 'register_totp', $ip, $userId);
                    $error = 'Kod TOTP nie pasuje. Upewnij się, że zeskanowałeś właściwy QR i wpisujesz aktualny kod.';
                    $step = 2; 
                }
            }
        }

    } else {
        $csrf = $_POST['csrf_token'] ?? '';
        if (empty($_SESSION['csrf_token_register']) || !hash_equals($_SESSION['csrf_token_register'], $csrf)) {
            $error = 'Nie udało się utworzyć konta. Odśwież stronę i spróbuj ponownie.';
            $step = 1;
        } else {

            $_SESSION['csrf_token_register'] = bin2hex(random_bytes(32));

            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $password2 = $_POST['password2'] ?? '';

            if (!rate_limit_allow($pdo, 'register', $ip, null, 3, 15)) {
                $error = 'Zbyt wiele rejestracji z tego adresu. Spróbuj za chwilę.';
            } else {
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $error = 'Podaj poprawny e-mail.';
                } elseif (strlen($password) < 8) {
                    $error = 'Hasło musi mieć co najmniej 8 znaków.';
                } elseif ($password !== $password2) {
                    $error = 'Hasła nie są takie same.';
                } else {
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
                    $stmt->execute([':email' => $email]);
                    if ($stmt->fetch()) {
                        $error = 'Użytkownik z takim e-mailem już istnieje.';
                    } else {
                        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                        $secret = generate_totp_secret();
                        $encryptedSecret = encrypt_totp_secret($secret);

                        $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, totp_secret, totp_confirmed)
                                               VALUES (:email, :ph, :secret, 0)");
                        $stmt->execute([
                            ':email' => $email,
                            ':ph' => $passwordHash,
                            ':secret' => $encryptedSecret,
                        ]);

                        $userId = (int)$pdo->lastInsertId();

                        $_SESSION['totp_setup_user_id'] = $userId;
                        $_SESSION['totp_setup_secret'] = $secret;

                        rate_limit_log($pdo, 'register', $ip, $userId);

                        $_SESSION['csrf_token_register_totp'] = bin2hex(random_bytes(32));

                        $step = 2;
                    }
                }
            }
        }
    }
}

$qrUrl = '';
$otpauth = '';
if ($step === 2) {
    $secret = $_SESSION['totp_setup_secret'];
    $userId = (int)$_SESSION['totp_setup_user_id'];

    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch();
    $email = $user ? $user['email'] : ('user'.$userId);

    $issuer = urlencode('MojaAplikacja');
    $label = urlencode('MojaAplikacja:' . $email);
    $otpauth = "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}";

    $qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' . urlencode($otpauth);
}
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Rejestracja</title>
</head>
<body>
<h1>Rejestracja</h1>

<?php if ($error): ?>
    <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<?php if ($step === 1): ?>

    <form method="post" action="">
        <label>Email: <input type="email" name="email" required></label><br>
        <label>Hasło: <input type="password" name="password" required></label><br>
        <label>Powtórz hasło: <input type="password" name="password2" required></label><br>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_register'], ENT_QUOTES, 'UTF-8') ?>">
        <button type="submit">Utwórz konto</button>
    </form>

	<p><a href="login.php">Zaloguj się</a></p>

<?php elseif ($step === 2): ?>

    <h2>Krok 2: dodaj TOTP</h2>
    <p>Zeskanuj ten kod QR w aplikacji (Google Authenticator, Aegis, itp.):</p>
    <p><img src="<?= htmlspecialchars($qrUrl) ?>" alt="QR TOTP"></p>
    <p>Albo wpisz ręcznie sekret: <strong><?= htmlspecialchars($_SESSION['totp_setup_secret']) ?></strong></p>

    <p>Teraz wpisz kod, który pokazuje aplikacja, żeby potwierdzić, że wszystko działa:</p>
    <form method="post" action="">
        <label>Kod z aplikacji: <input type="text" name="totp_code" required></label><br>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token_register_totp'], ENT_QUOTES, 'UTF-8') ?>">
        <button type="submit">Potwierdź TOTP</button>
    </form>

<?php endif; ?>

</body>
</html>
