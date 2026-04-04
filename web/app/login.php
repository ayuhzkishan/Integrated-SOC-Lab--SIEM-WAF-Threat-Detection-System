<?php
/**
 * VulnCorp Login - Deliberately Vulnerable to SQL Injection
 * ⚠️  FOR EDUCATIONAL / LAB USE ONLY
 *
 * Vulnerability: Unsanitized user input concatenated directly into SQL query.
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 */

$login_error = "";
$login_success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // --- INTENTIONALLY VULNERABLE SQL ---
    // A real app would use prepared statements. This is meant to be exploited.
    $db = new SQLite3('/tmp/vulncorp.db');
    $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");

    // Seed default users if empty
    $count = $db->querySingle("SELECT COUNT(*) FROM users");
    if ($count == 0) {
        $db->exec("INSERT INTO users (username, password, role) VALUES ('admin', 'P@ssw0rd!', 'administrator')");
        $db->exec("INSERT INTO users (username, password, role) VALUES ('jsmith', 'Welcome123', 'employee')");
        $db->exec("INSERT INTO users (username, password, role) VALUES ('analyst', 'Spl0nk2025', 'soc_analyst')");
    }

    // 🔴 VULNERABLE: Direct string concatenation (SQLi target)
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $db->querySingle($query, true);

    if ($result) {
        $login_success = true;
    } else {
        $login_error = "Invalid credentials. Access denied.";
        // Log failed attempt (visible in Apache access log)
        error_log("LOGIN_FAILED: user=$username src=" . $_SERVER['REMOTE_ADDR']);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCorp — Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-box { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 40px; width: 100%; max-width: 420px; }
        .login-box h1 { color: #3b82f6; text-align: center; margin-bottom: 8px; }
        .login-box p { color: #94a3b8; text-align: center; margin-bottom: 30px; font-size: 0.9rem; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #93c5fd; margin-bottom: 6px; font-weight: 600; }
        .form-group input { width: 100%; padding: 12px 16px; background: #0f172a; border: 1px solid #475569; border-radius: 8px; color: #e2e8f0; font-size: 1rem; outline: none; transition: border-color 0.2s; }
        .form-group input:focus { border-color: #3b82f6; }
        .btn { width: 100%; padding: 12px; background: #3b82f6; color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        .btn:hover { background: #2563eb; }
        .error { color: #ef4444; background: rgba(239,68,68,0.1); padding: 10px; border-radius: 8px; text-align: center; margin-bottom: 20px; border: 1px solid #7f1d1d; }
        .success { color: #22c55e; background: rgba(34,197,94,0.1); padding: 10px; border-radius: 8px; text-align: center; margin-bottom: 20px; border: 1px solid #14532d; }
        .back { display: block; text-align: center; margin-top: 20px; color: #93c5fd; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🔐 VulnCorp Login</h1>
        <p>Authorized personnel only. All access is logged.</p>

        <?php if ($login_success): ?>
            <div class="success">✅ Welcome back, <?= htmlspecialchars($result['username']) ?>! Role: <?= htmlspecialchars($result['role']) ?></div>
        <?php elseif ($login_error): ?>
            <div class="error">❌ <?= htmlspecialchars($login_error) ?></div>
        <?php endif; ?>

        <form method="POST" action="/login.php">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <a class="back" href="/">← Back to Portal</a>
    </div>
</body>
</html>
