<?php
/**
 * Panamex Logistics Management OS
 * Main Application Entry Point
 * Hostinger PHP & MySQL Runtime with Cloudflare Edge Security
 */

require_once __DIR__ . '/config/security.php';
applySecurityHeaders();

$configFile = __DIR__ . '/config/config.php';

// Check if database installation is completed
if (!file_exists($configFile)) {
    header('Location: install.php');
    exit;
}

$dbConfigured = true;
$dbError = null;

try {
    require_once __DIR__ . '/config/db.php';
    $pdo = getDbConnection();
} catch (Exception $e) {
    $dbConfigured = false;
    $dbError = $e->getMessage();
}

// Get Cloudflare & security metadata
$cf = getCloudflareMetadata();
$csrfToken = getCsrfToken();

// Serve the main application
$html = file_get_contents(__DIR__ . '/index.html');

// Inject live database and security status variables
$dbStatusScript = "<script>
  window.PANAMEX_PHP_BACKEND = true;
  window.PANAMEX_DB_CONNECTED = " . ($dbConfigured ? 'true' : 'false') . ";
  window.PANAMEX_SECURITY = {
    csrfToken: " . json_encode($csrfToken) . ",
    cloudflareWaf: " . ($cf['is_cloudflare'] ? 'true' : 'false') . ",
    cfRay: " . json_encode($cf['cf_ray']) . ",
    cfCountry: " . json_encode($cf['cf_country']) . ",
    clientIp: " . json_encode($cf['client_ip']) . "
  };
  " . ($dbError ? "console.warn('Panamex DB Error: " . addslashes($dbError) . "');" : "") . "
</script>";

$html = str_replace('</head>', $dbStatusScript . "\n</head>", $html);

echo $html;
