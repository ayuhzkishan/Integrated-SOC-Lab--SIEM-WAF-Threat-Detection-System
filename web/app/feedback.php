<?php
/**
 * VulnCorp Feedback - Deliberately Vulnerable to Stored XSS
 * ⚠️  FOR EDUCATIONAL / LAB USE ONLY
 *
 * Vulnerability: User feedback stored and rendered without sanitization.
 * MITRE ATT&CK: T1059 (Command and Scripting Interpreter - JavaScript)
 */

$feedback_file = '/tmp/feedback.json';

// Load existing feedback
$feedbacks = [];
if (file_exists($feedback_file)) {
    $feedbacks = json_decode(file_get_contents($feedback_file), true) ?? [];
}

// Handle submission
$submitted = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? 'Anonymous';
    $message = $_POST['message'] ?? '';
    
    if (!empty($message)) {
        $feedbacks[] = [
            'name' => $name,
            'message' => $message,
            'time' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR']
        ];
        file_put_contents($feedback_file, json_encode($feedbacks));
        $submitted = true;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCorp — Feedback</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #3b82f6; margin-bottom: 8px; }
        .subtitle { color: #94a3b8; margin-bottom: 30px; }
        .form-box { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 30px; margin-bottom: 30px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; color: #93c5fd; margin-bottom: 6px; font-weight: 600; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #475569; border-radius: 8px; color: #e2e8f0; font-size: 1rem; outline: none; }
        .form-group textarea { height: 100px; resize: vertical; font-family: inherit; }
        .btn { padding: 12px 24px; background: #3b82f6; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
        .success { color: #22c55e; background: rgba(34,197,94,0.1); padding: 10px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #14532d; }
        .feedback-item { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 12px; }
        .feedback-meta { color: #94a3b8; font-size: 0.85rem; margin-bottom: 8px; }
        .feedback-msg { line-height: 1.6; }
        .back { display: inline-block; margin-top: 20px; color: #93c5fd; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>💬 Employee Feedback</h1>
        <p class="subtitle">Share your thoughts with the management team</p>

        <?php if ($submitted): ?>
            <div class="success">✅ Thank you for your feedback!</div>
        <?php endif; ?>

        <div class="form-box">
            <form method="POST" action="/feedback.php">
                <div class="form-group">
                    <label for="name">Your Name</label>
                    <input type="text" id="name" name="name" placeholder="Enter your name">
                </div>
                <div class="form-group">
                    <label for="message">Feedback</label>
                    <textarea id="message" name="message" placeholder="Write your feedback here..." required></textarea>
                </div>
                <button type="submit" class="btn">Submit Feedback</button>
            </form>
        </div>

        <h2 style="color:#60a5fa; margin-bottom:16px;">Recent Feedback</h2>
        <?php if (empty($feedbacks)): ?>
            <p style="color:#94a3b8;">No feedback submitted yet.</p>
        <?php else: ?>
            <?php foreach (array_reverse($feedbacks) as $fb): ?>
                <div class="feedback-item">
                    <div class="feedback-meta">
                        <strong><?= $fb['name'] ?></strong> — <?= $fb['time'] ?>
                    </div>
                    <!-- 🔴 VULNERABLE: Unescaped output = Stored XSS -->
                    <div class="feedback-msg"><?= $fb['message'] ?></div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>

        <a class="back" href="/">← Back to Portal</a>
    </div>
</body>
</html>
