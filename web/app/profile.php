<?php
/**
 * VulnCorp Profile - Deliberately Vulnerable to Reflected XSS
 * ⚠️  FOR EDUCATIONAL / LAB USE ONLY
 */
$user = $_GET['user'] ?? 'guest';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCorp — Profile</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 600px; margin: 60px auto; padding: 0 20px; }
        .profile-card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 40px; text-align: center; }
        .avatar { width: 80px; height: 80px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        h1 { color: #3b82f6; margin-bottom: 8px; }
        .role { color: #f59e0b; font-weight: 600; }
        .info { color: #94a3b8; margin-top: 20px; line-height: 1.8; }
        .back { display: inline-block; margin-top: 20px; color: #93c5fd; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="profile-card">
            <div class="avatar">👤</div>
            <!-- 🔴 VULNERABLE: Reflected XSS via unsanitized GET parameter -->
            <h1>Welcome, <?= $user ?></h1>
            <p class="role">Employee</p>
            <div class="info">
                <p>Profile page for: <strong><?= $user ?></strong></p>
                <p>Last login: <?= date('Y-m-d H:i:s') ?></p>
                <p>IP: <?= $_SERVER['REMOTE_ADDR'] ?></p>
            </div>
        </div>
        <a class="back" href="/">← Back to Portal</a>
    </div>
</body>
</html>
