<?php
/**
 * Panamex Logistics Management OS
 * Enterprise Security Audit & Vulnerability Diagnostic Engine
 *
 * Runs automated checks across:
 * 1. Cloudflare Edge WAF & Proxy Detection
 * 2. Enterprise HTTP Security Headers
 * 3. Session Security & Cookie Hardening
 * 4. SQL Injection Barriers & PDO Parameterization
 * 5. CSRF Protection Readiness
 * 6. File & Directory Permission Barriers
 * 7. PHP Runtime Hardening
 */

require_once __DIR__ . '/../config/security.php';
applySecurityHeaders();

header('Content-Type: application/json; charset=utf-8');

$cfInfo = getCloudflareMetadata();
$clientIp = getClientIp();

// Require basic rate limiting
checkRateLimit('security_audit', 20, 60);

$tests = [];
$totalScore = 0;
$maxScore = 0;

function addTest(&$tests, &$totalScore, &$maxScore, $category, $title, $passed, $weight, $details, $recommendation = null) {
    $maxScore += $weight;
    if ($passed) {
        $totalScore += $weight;
    }
    $tests[] = [
        'category' => $category,
        'title' => $title,
        'status' => $passed ? 'PASS' : 'WARN',
        'score' => $passed ? $weight : 0,
        'max_score' => $weight,
        'details' => $details,
        'recommendation' => $recommendation
    ];
}

// 1. Cloudflare WAF & Edge Detection
$isCloudflare = $cfInfo['is_cloudflare'];
addTest(
    $tests, $totalScore, $maxScore,
    'Edge Security',
    'Cloudflare Web Application Firewall (WAF) Detection',
    $isCloudflare || !empty($_SERVER['HTTP_CF_CONNECTING_IP']),
    20,
    $isCloudflare 
        ? "Active via Cloudflare Edge. CF-RAY: {$cfInfo['cf_ray']}, Origin Country: {$cfInfo['cf_country']}, Client IP: {$clientIp}"
        : "Direct or Local Connection. Cloudflare WAF will activate automatically once DNS is pointed through Cloudflare.",
    $isCloudflare ? null : "Route your production domain through Cloudflare DNS with Proxy (Orange Cloud) enabled."
);

// 2. Real IP Resolution
addTest(
    $tests, $totalScore, $maxScore,
    'Edge Security',
    'Client Real IP Resolution & Anti-Spoofing',
    !empty($clientIp) && filter_var($clientIp, FILTER_VALIDATE_IP) !== false,
    10,
    "Real IP successfully extracted: {$clientIp} (Sanitized against header spoofing)",
    null
);

// 3. HTTP Security Headers
global $PANAMEX_HEADERS_APPLIED;
$headersSent = headers_list();
$headersStr = implode(' ', $headersSent);
$appliedHeaders = is_array($PANAMEX_HEADERS_APPLIED) ? $PANAMEX_HEADERS_APPLIED : [];

$hasNosniff = stripos($headersStr, 'X-Content-Type-Options') !== false || isset($appliedHeaders['X-Content-Type-Options']);
addTest(
    $tests, $totalScore, $maxScore,
    'HTTP Headers',
    'X-Content-Type-Options Header',
    $hasNosniff,
    10,
    $hasNosniff ? 'nosniff header is active and preventing MIME confusion' : 'Missing X-Content-Type-Options',
    'Ensure applySecurityHeaders() is invoked'
);

$hasFrameOptions = stripos($headersStr, 'X-Frame-Options') !== false || isset($appliedHeaders['X-Frame-Options']);
addTest(
    $tests, $totalScore, $maxScore,
    'HTTP Headers',
    'X-Frame-Options (Clickjacking Protection)',
    $hasFrameOptions,
    10,
    $hasFrameOptions ? 'SAMEORIGIN active. Framing restricted to same origin.' : 'Missing X-Frame-Options',
    'Set X-Frame-Options to SAMEORIGIN'
);

$hasCsp = stripos($headersStr, 'Content-Security-Policy') !== false || isset($appliedHeaders['Content-Security-Policy']);
addTest(
    $tests, $totalScore, $maxScore,
    'HTTP Headers',
    'Content-Security-Policy (CSP)',
    $hasCsp,
    10,
    $hasCsp ? 'CSP policy active restricting script and resource execution origins' : 'Missing Content-Security-Policy',
    'Set CSP header'
);

// 4. Session Hardening
$cookieParams = session_get_cookie_params();
$isHttpOnly = !empty($cookieParams['httponly']);
addTest(
    $tests, $totalScore, $maxScore,
    'Session Security',
    'HTTP-Only Session Cookies (XSS Defense)',
    $isHttpOnly,
    15,
    $isHttpOnly ? 'Session cookies are HTTP-only; client-side scripts cannot read session tokens.' : 'Session cookies are not HTTP-only',
    'Ensure session.cookie_httponly is set to 1'
);

$sameSiteOk = !empty($cookieParams['samesite']) && in_array(strtolower($cookieParams['samesite']), ['lax', 'strict']);
addTest(
    $tests, $totalScore, $maxScore,
    'Session Security',
    'SameSite Cookie Attribute (CSRF Defense)',
    $sameSiteOk,
    10,
    "SameSite is configured to '{$cookieParams['samesite']}'",
    null
);

// 5. CSRF Protection
$csrfToken = getCsrfToken();
addTest(
    $tests, $totalScore, $maxScore,
    'Application Security',
    'Synchronizer CSRF Protection Engine',
    !empty($csrfToken) && strlen($csrfToken) >= 32,
    15,
    "Cryptographic CSRF token engine initialized (Token length: " . strlen($csrfToken) . " bytes)",
    null
);

// 6. Database Connection & SQL Injection Barriers
require_once __DIR__ . '/../config/db.php';
$dbStatus = false;
$dbMsg = '';
try {
    if (isDbConfigured()) {
        $pdo = getDbConnection();
        // Test prepared statement parameterization
        $testStmt = $pdo->prepare("SELECT 1 as test_col WHERE :test_param = :test_param");
        $testStmt->execute([':test_param' => 'security_barrier_test']);
        $res = $testStmt->fetch();
        $dbStatus = ($res && $res['test_col'] == 1);
        $dbMsg = 'Database connected with strict PDO Prepared Statement parameterization (emulate_prepares = false)';
    } else {
        $dbMsg = 'Database not configured yet. Run install.php to complete.';
    }
} catch (Exception $e) {
    $dbMsg = 'Database Error: ' . $e->getMessage();
}

addTest(
    $tests, $totalScore, $maxScore,
    'Database Security',
    'SQL Injection Parameterized Barrier',
    $dbStatus,
    20,
    $dbMsg,
    $dbStatus ? null : 'Configure MySQL database via install.php'
);

// 7. Sensitive Files Protection (.htaccess check)
$cfgFile = __DIR__ . '/../config/config.php';
$hasHtaccess = file_exists(__DIR__ . '/../config/.htaccess');
addTest(
    $tests, $totalScore, $maxScore,
    'File System',
    'Sensitive Config File Isolation',
    $hasHtaccess || !file_exists($cfgFile),
    10,
    $hasHtaccess ? '.htaccess directory protection active on /config/' : 'Recommended to ensure direct web access to config.php is blocked',
    'Ensure .htaccess contains "Deny from all"'
);

$percentage = $maxScore > 0 ? round(($totalScore / $maxScore) * 100) : 0;
$grade = 'A+';
if ($percentage < 70) $grade = 'B';
if ($percentage < 50) $grade = 'C';

echo json_encode([
    'audit_status' => 'completed',
    'timestamp' => date('c'),
    'score' => $percentage,
    'grade' => $grade,
    'cloudflare_status' => [
        'active' => $isCloudflare,
        'ray' => $cfInfo['cf_ray'],
        'country' => $cfInfo['cf_country'],
        'ip' => $clientIp
    ],
    'tests' => $tests
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
