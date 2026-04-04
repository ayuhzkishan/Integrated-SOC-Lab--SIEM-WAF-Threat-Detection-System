<?php
/**
 * VulnCorp Search - Deliberately Vulnerable to SQL Injection
 * ⚠️  FOR EDUCATIONAL / LAB USE ONLY
 *
 * Vulnerability: Unsanitized GET param used directly in SQL WHERE clause.
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 */

$results = [];
$search_query = "";
$error_msg = "";

if (isset($_GET['q'])) {
    $search_query = $_GET['q'];
    
    $db = new SQLite3('/tmp/vulncorp.db');
    $db->exec("CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT, role TEXT, email TEXT)");

    // Seed employees if empty
    $count = $db->querySingle("SELECT COUNT(*) FROM employees");
    if ($count == 0) {
        $employees = [
            ['Alice Johnson', 'Engineering', 'DevOps Engineer', 'alice@vulncorp.com'],
            ['Bob Williams', 'Security', 'SOC Analyst L2', 'bob@vulncorp.com'],
            ['Carol Martinez', 'HR', 'Recruiter', 'carol@vulncorp.com'],
            ['David Chen', 'Engineering', 'Backend Developer', 'david@vulncorp.com'],
            ['Eve Thompson', 'Security', 'Penetration Tester', 'eve@vulncorp.com'],
            ['Frank Harris', 'Finance', 'Accountant', 'frank@vulncorp.com'],
            ['Grace Lee', 'Engineering', 'Site Reliability Engineer', 'grace@vulncorp.com'],
            ['Henry Wilson', 'IT', 'System Administrator', 'henry@vulncorp.com'],
        ];
        foreach ($employees as $emp) {
            $db->exec("INSERT INTO employees (name, department, role, email) VALUES ('{$emp[0]}', '{$emp[1]}', '{$emp[2]}', '{$emp[3]}')");
        }
    }

    // 🔴 VULNERABLE: Direct string interpolation (SQLi target)
    $query = "SELECT * FROM employees WHERE name LIKE '%$search_query%' OR department LIKE '%$search_query%'";
    
    try {
        $stmt = $db->query($query);
        while ($row = $stmt->fetchArray(SQLITE3_ASSOC)) {
            $results[] = $row;
        }
    } catch (Exception $e) {
        // 🔴 VULNERABLE: Verbose error output (information disclosure)
        $error_msg = "Database error: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnCorp — Employee Search</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #3b82f6; margin-bottom: 8px; }
        .subtitle { color: #94a3b8; margin-bottom: 30px; }
        .search-box { display: flex; gap: 10px; margin-bottom: 30px; }
        .search-box input { flex: 1; padding: 12px 16px; background: #1e293b; border: 1px solid #475569; border-radius: 8px; color: #e2e8f0; font-size: 1rem; outline: none; }
        .search-box input:focus { border-color: #3b82f6; }
        .search-box button { padding: 12px 24px; background: #3b82f6; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }
        th { background: #334155; color: #93c5fd; padding: 14px 16px; text-align: left; font-weight: 600; }
        td { padding: 12px 16px; border-bottom: 1px solid #334155; }
        tr:hover { background: #334155; }
        .error { color: #ef4444; background: rgba(239,68,68,0.1); padding: 12px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #7f1d1d; font-family: monospace; font-size: 0.85rem; }
        .no-results { color: #94a3b8; text-align: center; padding: 40px; }
        .back { display: inline-block; margin-top: 20px; color: #93c5fd; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Employee Directory Search</h1>
        <p class="subtitle">Search by name or department</p>

        <form method="GET" action="/search.php">
            <div class="search-box">
                <input type="text" name="q" placeholder="Search employees..." value="<?= htmlspecialchars($search_query) ?>">
                <button type="submit">Search</button>
            </div>
        </form>

        <?php if ($error_msg): ?>
            <div class="error">⚠️ <?= $error_msg ?></div>
        <?php endif; ?>

        <?php if (!empty($results)): ?>
            <table>
                <thead>
                    <tr><th>ID</th><th>Name</th><th>Department</th><th>Role</th><th>Email</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $row): ?>
                    <tr>
                        <td><?= htmlspecialchars($row['id'] ?? '') ?></td>
                        <td><?= htmlspecialchars($row['name'] ?? '') ?></td>
                        <td><?= htmlspecialchars($row['department'] ?? '') ?></td>
                        <td><?= htmlspecialchars($row['role'] ?? '') ?></td>
                        <td><?= htmlspecialchars($row['email'] ?? '') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php elseif ($search_query && !$error_msg): ?>
            <div class="no-results">No employees found matching "<?= htmlspecialchars($search_query) ?>"</div>
        <?php endif; ?>

        <a class="back" href="/">← Back to Portal</a>
    </div>
</body>
</html>
