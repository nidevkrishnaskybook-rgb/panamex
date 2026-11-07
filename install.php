<?php
/**
 * Panamex Logistics Management OS - 1-Click Database Installer
 * Designed for Hostinger / Apache / Nginx PHP & MySQL environments
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$configFile = __DIR__ . '/config/config.php';
$schemaFile = __DIR__ . '/database/schema.sql';
$isInstalled = file_exists($configFile);
$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dbHost = trim($_POST['db_host'] ?? 'localhost');
    $dbPort = trim($_POST['db_port'] ?? '3306');
    $dbName = trim($_POST['db_name'] ?? '');
    $dbUser = trim($_POST['db_user'] ?? '');
    $dbPass = trim($_POST['db_pass'] ?? '');
    
    $adminName = trim($_POST['admin_name'] ?? 'Captain David Vagi');
    $adminEmail = trim($_POST['admin_email'] ?? 'd.vagi@panamex.com.pg');
    $adminPass = trim($_POST['admin_pass'] ?? 'admin123');

    if (empty($dbName) || empty($dbUser)) {
        $error = "Please fill in all required database details (Database Name & Username).";
    } else {
        try {
            // 1. Test PDO connection
            $dsn = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4";
            $pdo = new PDO($dsn, $dbUser, $dbPass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);

            // 2. Read and execute database/schema.sql
            if (!file_exists($schemaFile)) {
                throw new Exception("schema.sql file not found at " . htmlspecialchars($schemaFile));
            }
            $sql = file_get_contents($schemaFile);
            $pdo->exec($sql);

            // 2.1 Schema auto-migration: Ensure new security audit columns exist if table was already created
            try {
                $cols = $pdo->query("SHOW COLUMNS FROM audit_logs LIKE 'ip_address'")->fetchAll();
                if (empty($cols)) {
                    $pdo->exec("ALTER TABLE audit_logs 
                        ADD COLUMN `user_role` VARCHAR(32) DEFAULT NULL AFTER `user_name`,
                        ADD COLUMN `ip_address` VARCHAR(45) DEFAULT NULL AFTER `user_role`,
                        ADD COLUMN `user_agent` VARCHAR(255) DEFAULT NULL AFTER `ip_address`,
                        ADD COLUMN `cf_ray` VARCHAR(64) DEFAULT NULL AFTER `user_agent`,
                        ADD COLUMN `cf_country` VARCHAR(8) DEFAULT NULL AFTER `cf_ray`");
                }
            } catch (Exception $ign) {
                // Ignore if already altered or not supported
            }

            // 3. Insert or update default users
            $initialUsers = [
                [
                    'id' => 'usr_admin',
                    'username' => 'admin',
                    'name' => $adminName,
                    'email' => $adminEmail,
                    'password' => $adminPass,
                    'role' => 'admin',
                    'active' => 1,
                    'memoji' => '🧔🏻‍♂️'
                ],
                [
                    'id' => 'usr_mgr',
                    'username' => 'manager',
                    'name' => 'Sarah Kila (Shipping Lead)',
                    'email' => 's.kila@panamex.com.pg',
                    'password' => 'manager123',
                    'role' => 'manager',
                    'active' => 1,
                    'memoji' => '👩🏽‍💼'
                ],
                [
                    'id' => 'usr_yard',
                    'username' => 'yard',
                    'name' => 'John Auka (Yard Officer)',
                    'email' => 'j.auka@panamex.com.pg',
                    'password' => 'yard123',
                    'role' => 'yard_staff',
                    'active' => 1,
                    'memoji' => '👷🏾‍♂️'
                ]
            ];

            $userStmt = $pdo->prepare("INSERT INTO users (id, username, name, email, password, role, active, memoji, raw_data)
                VALUES (:id, :username, :name, :email, :password, :role, :active, :memoji, :raw_data)
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    email = VALUES(email),
                    password = VALUES(password),
                    role = VALUES(role),
                    active = VALUES(active)");

            foreach ($initialUsers as $u) {
                $userStmt->execute([
                    ':id' => $u['id'],
                    ':username' => $u['username'],
                    ':name' => $u['name'],
                    ':email' => $u['email'],
                    ':password' => $u['password'],
                    ':role' => $u['role'],
                    ':active' => $u['active'],
                    ':memoji' => $u['memoji'],
                    ':raw_data' => json_encode($u, JSON_UNESCAPED_UNICODE)
                ]);
            }

            // 4. Write config/config.php
            if (!is_dir(__DIR__ . '/config')) {
                mkdir(__DIR__ . '/config', 0755, true);
            }

            $configContent = "<?php\n/**\n * Panamex Database Config\n * Auto-generated by install.php on " . date('Y-m-d H:i:s') . "\n */\nreturn " . var_export([
                'db_host' => $dbHost,
                'db_port' => $dbPort,
                'db_name' => $dbName,
                'db_user' => $dbUser,
                'db_pass' => $dbPass,
                'charset' => 'utf8mb4'
            ], true) . ";\n";

            file_put_contents($configFile, $configContent);
            $success = true;
            $isInstalled = true;

        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Panamex Logistics OS - 1-Click Database Setup</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #09131C;
    color: #E2E8F0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding: 24px 16px;
  }
  .card {
    background: #11202D;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    width: 100%;
    max-width: 580px;
    padding: 32px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.4);
  }
  .brand-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 24px;
    padding-bottom: 18px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
  }
  .brand-logo {
    width: 44px;
    height: 44px;
    background: #10B981;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #FFFFFF;
    font-size: 22px;
    font-weight: 800;
  }
  .brand-title h1 {
    font-size: 18px;
    font-weight: 800;
    color: #FFFFFF;
  }
  .brand-title p {
    font-size: 11.5px;
    color: #94A3B8;
  }
  .alert-error {
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid #EF4444;
    color: #FCA5A5;
    padding: 12px 14px;
    border-radius: 8px;
    font-size: 12px;
    margin-bottom: 20px;
    line-height: 1.4;
  }
  .alert-success {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid #10B981;
    color: #6EE7B7;
    padding: 16px;
    border-radius: 8px;
    font-size: 13px;
    margin-bottom: 20px;
    text-align: center;
  }
  .form-group {
    margin-bottom: 16px;
  }
  .form-group label {
    display: block;
    font-size: 11px;
    font-weight: 700;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
  }
  .form-group input {
    width: 100%;
    background: #09131C;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 8px;
    padding: 10px 14px;
    color: #FFFFFF;
    font-size: 13px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.2s;
  }
  .form-group input:focus {
    border-color: #10B981;
  }
  .form-row {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 12px;
  }
  .section-tag {
    font-size: 11px;
    font-weight: 800;
    color: #10B981;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 20px;
    margin-bottom: 12px;
    display: block;
  }
  .btn-submit {
    width: 100%;
    background: #10B981;
    color: #FFFFFF;
    border: none;
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 800;
    border-radius: 8px;
    cursor: pointer;
    margin-top: 10px;
    transition: background 0.2s;
  }
  .btn-submit:hover {
    background: #059669;
  }
  .btn-launch {
    display: inline-block;
    background: #10B981;
    color: #FFFFFF;
    text-decoration: none;
    padding: 12px 28px;
    font-size: 14px;
    font-weight: 800;
    border-radius: 8px;
    margin-top: 14px;
  }
  .hint-box {
    background: rgba(255,255,255,0.03);
    border: 1px dashed rgba(255,255,255,0.1);
    padding: 12px;
    border-radius: 8px;
    font-size: 11px;
    color: #94A3B8;
    margin-top: 18px;
    line-height: 1.5;
  }
</style>
</head>
<body>

<div class="card">
  <div class="brand-header">
    <div class="brand-logo">P</div>
    <div class="brand-title">
      <h1>Panamex Logistics Management OS</h1>
      <p>Hostinger &amp; MySQL 1-Click Environment Setup</p>
    </div>
  </div>

  <?php if ($success): ?>
    <div class="alert-success">
      <h3 style="font-size: 16px; margin-bottom: 6px;">🎉 Installation Completed Successfully!</h3>
      <p style="color: #A7F3D0; font-size: 12px;">Database tables created, initial admin user initialized, and <code>config/config.php</code> written.</p>
      <div style="margin-top: 12px;">
        <a href="index.php" class="btn-launch">Launch Panamex System &rarr;</a>
      </div>
    </div>
  <?php else: ?>

    <?php if ($error): ?>
      <div class="alert-error">
        <strong>Error:</strong> <?php echo htmlspecialchars($error); ?>
      </div>
    <?php elseif ($isInstalled): ?>
      <div style="background: rgba(59, 130, 246, 0.12); border: 1px solid #3B82F6; color: #93C5FD; padding: 12px 14px; border-radius: 8px; font-size: 12px; margin-bottom: 20px;">
        <strong>Notice:</strong> Panamex is already installed and connected. Submitting below will re-check and update database credentials.
        <div style="margin-top: 8px;">
          <a href="index.php" style="color: #60A5FA; font-weight: 700;">&rarr; Go directly to Panamex Login</a>
        </div>
      </div>
    <?php endif; ?>

    <form method="POST">
      <span class="section-tag">1. Hostinger MySQL Database Settings</span>
      
      <div class="form-row">
        <div class="form-group">
          <label>MySQL Host</label>
          <input type="text" name="db_host" value="<?php echo htmlspecialchars($_POST['db_host'] ?? 'localhost'); ?>" required>
        </div>
        <div class="form-group">
          <label>Port</label>
          <input type="text" name="db_port" value="<?php echo htmlspecialchars($_POST['db_port'] ?? '3306'); ?>" required>
        </div>
      </div>

      <div class="form-group">
        <label>Database Name (from Hostinger hPanel)</label>
        <input type="text" name="db_name" placeholder="e.g. u123456789_panamex" value="<?php echo htmlspecialchars($_POST['db_name'] ?? ''); ?>" required>
      </div>

      <div class="form-group">
        <label>Database Username</label>
        <input type="text" name="db_user" placeholder="e.g. u123456789_panamex_user" value="<?php echo htmlspecialchars($_POST['db_user'] ?? ''); ?>" required>
      </div>

      <div class="form-group">
        <label>Database Password</label>
        <input type="password" name="db_pass" placeholder="Database user password" value="<?php echo htmlspecialchars($_POST['db_pass'] ?? ''); ?>">
      </div>

      <span class="section-tag">2. Admin User Credentials</span>
      <div class="form-group">
        <label>Admin Full Name</label>
        <input type="text" name="admin_name" value="<?php echo htmlspecialchars($_POST['admin_name'] ?? 'Captain David Vagi'); ?>">
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Admin Email</label>
          <input type="email" name="admin_email" value="<?php echo htmlspecialchars($_POST['admin_email'] ?? 'd.vagi@panamex.com.pg'); ?>">
        </div>
        <div class="form-group">
          <label>Admin Password</label>
          <input type="text" name="admin_pass" value="<?php echo htmlspecialchars($_POST['admin_pass'] ?? 'admin123'); ?>">
        </div>
      </div>

      <button type="submit" class="btn-submit">Test &amp; Complete Installation &rarr;</button>
    </form>

    <div class="hint-box">
      <strong>Hostinger Tip:</strong> In Hostinger hPanel &rarr; <em>Databases</em> &rarr; <em>MySQL Databases</em>, create a new database &amp; user. Then copy the exact Database Name, Username, and Password into the form above.
    </div>

  <?php endif; ?>
</div>

</body>
</html>
