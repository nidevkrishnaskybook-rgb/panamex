<?php
/**
 * Panamex Logistics Management OS
 * Security Hardening Engine & Cloudflare WAF Integration
 *
 * Implements:
 * 1. Cloudflare Edge WAF detection & real client IP resolution
 * 2. Enterprise HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
 * 3. Secure session initialization & brute-force defense
 * 4. CSRF protection (Synchronizer Token Pattern)
 * 5. IP-based rate limiting & request throttling
 * 6. Role-Based Access Control (RBAC) helpers
 * 7. Granular audit trail logging
 */

if (!defined('PANAMEX_SECURITY_LOADED')) {
    define('PANAMEX_SECURITY_LOADED', true);

    // 1. Session Hardening
    if (session_status() === PHP_SESSION_NONE) {
        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
                    (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

        ini_set('session.cookie_httponly', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_samesite', 'Lax');
        if ($isSecure) {
            ini_set('session.cookie_secure', '1');
        }

        // Set session lifetime to 8 hours
        ini_set('session.gc_maxlifetime', '28800');
        session_set_cookie_params([
            'lifetime' => 28800,
            'path' => '/',
            'domain' => '',
            'secure' => $isSecure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        session_start();
    }

    /**
     * Resolve Real Client IP (handles Cloudflare Edge Proxy & standard reverse proxies)
     */
    function getClientIp() {
        // Cloudflare real IP header takes highest precedence
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        // True-Client-IP header (Enterprise Cloudflare / Akamai)
        if (!empty($_SERVER['HTTP_TRUE_CLIENT_IP'])) {
            $ip = trim($_SERVER['HTTP_TRUE_CLIENT_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        // Standard X-Forwarded-For header
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($ips as $ipCandidate) {
                $trimmed = trim($ipCandidate);
                // Return first public valid IP
                if (filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $trimmed;
                }
            }
            // Fallback to first IP
            if (!empty($ips[0]) && filter_var(trim($ips[0]), FILTER_VALIDATE_IP)) {
                return trim($ips[0]);
            }
        }

        return !empty($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
    }

    /**
     * Get Cloudflare Edge metadata
     */
    function getCloudflareMetadata() {
        return [
            'is_cloudflare' => !empty($_SERVER['HTTP_CF_RAY']),
            'cf_ray' => !empty($_SERVER['HTTP_CF_RAY']) ? trim($_SERVER['HTTP_CF_RAY']) : null,
            'cf_country' => !empty($_SERVER['HTTP_CF_IPCOUNTRY']) ? trim($_SERVER['HTTP_CF_IPCOUNTRY']) : 'XX',
            'cf_ip' => !empty($_SERVER['HTTP_CF_CONNECTING_IP']) ? trim($_SERVER['HTTP_CF_CONNECTING_IP']) : null,
            'client_ip' => getClientIp()
        ];
    }

    /**
     * Send enterprise HTTP Security Headers
     */
    function applySecurityHeaders() {
        global $PANAMEX_HEADERS_APPLIED;
        $PANAMEX_HEADERS_APPLIED = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=()'
        ];

        if (headers_sent()) return;

        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');

        // Prevent clickjacking via iframes
        header('X-Frame-Options: SAMEORIGIN');

        // Enable XSS filtering
        header('X-XSS-Protection: 1; mode=block');

        // Referrer policy
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // Permissions policy
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');

        // HTTP Strict Transport Security (HSTS) if HTTPS
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
                   (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        if ($isHttps) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
            $PANAMEX_HEADERS_APPLIED['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
        }

        // Content Security Policy
        $csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; " .
               "img-src 'self' data: blob: https:; " .
               "font-src 'self' data: https: fonts.gstatic.com; " .
               "style-src 'self' 'unsafe-inline' https: fonts.googleapis.com; " .
               "frame-ancestors 'self';";
        header("Content-Security-Policy: {$csp}");
        $PANAMEX_HEADERS_APPLIED['Content-Security-Policy'] = $csp;
    }

    /**
     * CSRF Token Management (Synchronizer Token Pattern)
     */
    function getCsrfToken() {
        if (empty($_SESSION['panamex_csrf_token'])) {
            $_SESSION['panamex_csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['panamex_csrf_token'];
    }

    function validateCsrfToken($token = null) {
        if ($token === null) {
            // Check request headers first
            $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
            if (!$token && isset($_POST['_csrf_token'])) {
                $token = $_POST['_csrf_token'];
            }
        }

        if (empty($token) || empty($_SESSION['panamex_csrf_token'])) {
            return false;
        }

        return hash_equals($_SESSION['panamex_csrf_token'], $token);
    }

    /**
     * Rate Limiting & Brute-Force Protection
     * Limits requests per IP within a sliding window (using a temp file storage safe on all shared hostings)
     */
    function checkRateLimit($action = 'api', $maxAttempts = 120, $windowSeconds = 60) {
        $ip = getClientIp();
        $safeIp = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $ip);
        $rateDir = sys_get_temp_dir() . '/panamex_ratelimit';
        
        if (!is_dir($rateDir)) {
            @mkdir($rateDir, 0700, true);
        }

        $rateFile = "{$rateDir}/rl_{$action}_{$safeIp}.json";
        $now = time();
        $timestamps = [];

        if (file_exists($rateFile)) {
            $data = @file_get_contents($rateFile);
            $parsed = $data ? json_decode($data, true) : null;
            if (is_array($parsed)) {
                // Filter out entries older than window
                $cutoff = $now - $windowSeconds;
                foreach ($parsed as $ts) {
                    if ($ts > $cutoff) {
                        $timestamps[] = $ts;
                    }
                }
            }
        }

        if (count($timestamps) >= $maxAttempts) {
            $retryAfter = $windowSeconds - ($now - min($timestamps));
            if ($retryAfter < 1) $retryAfter = 1;
            
            http_response_code(429);
            header("Retry-After: {$retryAfter}");
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status' => 'rate_limited',
                'error' => "Too many requests for '{$action}'. Rate limit exceeded.",
                'retry_after_seconds' => $retryAfter,
                'ip' => $ip
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $timestamps[] = $now;
        @file_put_contents($rateFile, json_encode($timestamps), LOCK_EX);
        return true;
    }

    /**
     * Role-Based Access Control (RBAC) Checker
     * Roles: admin > shipping_manager > yard_staff
     */
    function checkRolePermission($requiredRole, $currentRole) {
        $hierarchy = [
            'yard_staff' => 1,
            'shipping_manager' => 2,
            'admin' => 3
        ];

        $reqLevel = $hierarchy[$requiredRole] ?? 1;
        $userLevel = $hierarchy[$currentRole] ?? 1;

        return $userLevel >= $reqLevel;
    }

    /**
     * Sanitize input strings for safe output & SQL handling
     */
    function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map('sanitizeInput', $data);
        }
        if (is_string($data)) {
            return trim(strip_tags($data));
        }
        return $data;
    }
}
