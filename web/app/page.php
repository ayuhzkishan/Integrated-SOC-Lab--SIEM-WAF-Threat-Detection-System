<?php
/**
 * VulnCorp Page Loader - Deliberately Vulnerable to LFI / RFI
 * ⚠️  FOR EDUCATIONAL / LAB USE ONLY
 *
 * Vulnerability: Unsanitized file parameter used in include().
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 */

$page = $_GET['file'] ?? 'about';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCorp — <?= htmlspecialchars(ucfirst($page)) ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #3b82f6; margin-bottom: 20px; }
        .content { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 30px; line-height: 1.8; }
        .content pre { background: #0f172a; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; color: #fbbf24; }
        .back { display: inline-block; margin-top: 20px; color: #93c5fd; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📄 Document Viewer</h1>
        <div class="content">
            <?php
            // 🔴 VULNERABLE: Direct file include with no sanitization (LFI/RFI)
            $filepath = "pages/" . $page . ".php";
            if (file_exists($filepath)) {
                include($filepath);
            } else {
                // Attempt raw include — allows path traversal
                // e.g., ?file=../../../../etc/passwd
                $raw = @file_get_contents($page);
                if ($raw !== false) {
                    echo "<pre>" . htmlspecialchars($raw) . "</pre>";
                } else {
                    echo "<p style='color:#ef4444;'>⚠️ Page not found: " . htmlspecialchars($page) . "</p>";
                }
            }
            ?>
        </div>
        <a class="back" href="/">← Back to Portal</a>
    </div>
</body>
</html>
