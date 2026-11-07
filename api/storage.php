<?php
/**
 * Panamex Logistics Management OS
 * Unified Storage & Synchronization REST API
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../config/security.php';
require_once __DIR__ . '/../config/db.php';

// Apply enterprise HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
applySecurityHeaders();

// Rate limiting check: 120 API calls / minute per IP
checkRateLimit('api_read', 120, 60);

// Check if database is configured
if (!isDbConfigured()) {
    http_response_code(503);
    echo json_encode([
        'status' => 'not_configured',
        'error' => 'Database not configured. Please visit install.php to complete setup.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $pdo = getDbConnection();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'db_error',
        'error' => $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];

// Handle GET request
if ($method === 'GET') {
    $key = isset($_GET['key']) ? trim($_GET['key']) : '';
    
    // Health / Ping check
    if ($key === 'ping' || isset($_GET['ping'])) {
        $cf = getCloudflareMetadata();
        echo json_encode([
            'status' => 'ok',
            'server_time' => date('c'),
            'database' => 'connected',
            'security' => [
                'cloudflare_waf' => $cf['is_cloudflare'],
                'cf_ray' => $cf['cf_ray'],
                'client_ip' => $cf['client_ip'],
                'csrf_active' => !empty($_SESSION['panamex_csrf_token'])
            ]
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // CSRF Token retrieval
    if ($key === 'csrf-token') {
        echo json_encode([
            'csrf_token' => getCsrfToken()
        ]);
        exit;
    }

    // Cloudflare Edge status check
    if ($key === 'cloudflare-info') {
        echo json_encode(getCloudflareMetadata(), JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Security audit & health check endpoint
    if ($key === 'security-audit') {
        require_once __DIR__ . '/security-audit.php';
        exit;
    }

    try {
        switch ($key) {
            case 'containers-v2':
                $stmt = $pdo->query("SELECT * FROM containers ORDER BY created_at DESC");
                $rows = $stmt->fetchAll();
                $result = [];
                foreach ($rows as $row) {
                    $item = !empty($row['raw_data']) ? json_decode($row['raw_data'], true) : [];
                    if (!is_array($item)) $item = [];
                    // Ensure core fields are accurately synced from table columns
                    $item['id'] = $row['id'];
                    $item['containerNo'] = $row['container_no'] ?? ($item['containerNo'] ?? '');
                    $item['invoiceNo'] = $row['invoice_no'] ?? ($item['invoiceNo'] ?? '');
                    $item['jobNo'] = $row['job_no'] ?? ($item['jobNo'] ?? '');
                    $item['customsJobNo'] = $row['customs_job_no'] ?? ($item['customsJobNo'] ?? '');
                    $item['pplNo'] = $row['ppl_no'] ?? ($item['pplNo'] ?? '');
                    $item['shippingLine'] = $row['shipping_line'] ?? ($item['shippingLine'] ?? '');
                    $item['dischargePort'] = $row['discharge_port'] ?? ($item['dischargePort'] ?? '');
                    $item['vesselVoyage'] = $row['vessel_voyage'] ?? ($item['vesselVoyage'] ?? '');
                    $item['containerType'] = $row['container_type'] ?? ($item['containerType'] ?? '');
                    $item['containerCount'] = (int)($row['container_count'] ?? ($item['containerCount'] ?? 1));
                    $item['operationalStage'] = $row['operational_stage'] ?? ($item['operationalStage'] ?? 'Stage 1');
                    $item['status'] = $row['status'] ?? ($item['status'] ?? 'Within Free Time');
                    $item['depot'] = $row['depot'] ?? ($item['depot'] ?? '');
                    $item['etaDate'] = $row['eta_date'] ?? ($item['etaDate'] ?? '');
                    $item['dischargeDate'] = $row['discharge_date'] ?? ($item['dischargeDate'] ?? '');
                    $item['dueDate'] = $row['due_date'] ?? ($item['dueDate'] ?? '');
                    $item['destuffDate'] = $row['destuff_date'] ?? ($item['destuffDate'] ?? '');
                    $item['returnedDate'] = $row['returned_date'] ?? ($item['returnedDate'] ?? '');
                    $item['stage2Moved'] = !empty($row['stage2_moved']);
                    $item['stage2InProgress'] = !empty($row['stage2_in_progress']);
                    $item['stage3Moved'] = !empty($row['stage3_moved']);
                    $item['statusLocked'] = !empty($row['status_locked']);
                    $item['notes'] = $row['notes'] ?? ($item['notes'] ?? '');
                    $item['createdAt'] = $row['created_at'] ?? ($item['createdAt'] ?? date('c'));
                    $item['updatedAt'] = $row['updated_at'] ?? ($item['updatedAt'] ?? date('c'));
                    $result[] = $item;
                }
                echo json_encode($result, JSON_UNESCAPED_UNICODE);
                break;

            case 'clearance-shipments-v2':
                $stmt = $pdo->query("SELECT * FROM clearance_shipments ORDER BY created_at DESC");
                $rows = $stmt->fetchAll();
                $result = [];
                foreach ($rows as $row) {
                    $item = !empty($row['raw_data']) ? json_decode($row['raw_data'], true) : [];
                    if (!is_array($item)) $item = [];
                    $item['id'] = $row['id'];
                    $item['invoiceNo'] = $row['invoice_no'] ?? ($item['invoiceNo'] ?? '');
                    $item['customsJobNo'] = $row['customs_job_no'] ?? ($item['customsJobNo'] ?? '');
                    $item['status'] = $row['status'] ?? ($item['status'] ?? 'Pending Customs Clearance');
                    $result[] = $item;
                }
                echo json_encode($result, JSON_UNESCAPED_UNICODE);
                break;

            case 'users-v1':
                $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at ASC");
                $rows = $stmt->fetchAll();
                $result = [];
                foreach ($rows as $row) {
                    $item = !empty($row['raw_data']) ? json_decode($row['raw_data'], true) : [];
                    if (!is_array($item)) $item = [];
                    $item['id'] = $row['id'];
                    $item['username'] = $row['username'];
                    $item['name'] = $row['name'];
                    $item['email'] = $row['email'];
                    $item['role'] = $row['role'];
                    $item['active'] = !empty($row['active']);
                    $item['memoji'] = $row['memoji'] ?? ($item['memoji'] ?? '👤');
                    $item['password'] = $row['password']; // preserved for client-side password verification
                    $result[] = $item;
                }
                echo json_encode($result, JSON_UNESCAPED_UNICODE);
                break;

            case 'audit-log-v1':
                $stmt = $pdo->query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500");
                $rows = $stmt->fetchAll();
                $result = [];
                foreach ($rows as $row) {
                    $changes = !empty($row['changes']) ? json_decode($row['changes'], true) : [];
                    $result[] = [
                        'id' => $row['id'],
                        'action' => $row['action'],
                        'containerId' => $row['container_id'],
                        'containerNo' => $row['container_no'],
                        'userName' => $row['user_name'],
                        'changes' => $changes,
                        'timestamp' => $row['created_at']
                    ];
                }
                echo json_encode($result, JSON_UNESCAPED_UNICODE);
                break;

            case 'current-user-v1':
                $currUser = $_SESSION['panamex_current_user_id'] ?? null;
                echo json_encode($currUser);
                break;

            default:
                // Check app_settings table for any other key (e.g. app-settings-v1, email-log-v1)
                $stmt = $pdo->prepare("SELECT setting_value FROM app_settings WHERE setting_key = ?");
                $stmt->execute([$key]);
                $val = $stmt->fetchColumn();
                if ($val !== false && $val !== null) {
                    echo $val;
                } else {
                    echo json_encode(null);
                }
                break;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// Handle POST request (Save / Sync)
if ($method === 'POST') {
    // Write Rate Limiting: 60 write requests / minute per IP
    checkRateLimit('api_write', 60, 60);

    $rawInput = file_get_contents('php://input');
    $data = json_decode($rawInput, true);

    if (!is_array($data) || !isset($data['key'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid payload. "key" is required.']);
        exit;
    }

    $key = trim($data['key']);
    $value = $data['value'] ?? null;
    $clientIp = getClientIp();
    $cf = getCloudflareMetadata();
    $userAgent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 255);

    try {
        switch ($key) {
            case 'containers-v2':
                if (is_array($value)) {
                    $pdo->beginTransaction();

                    $sql = "INSERT INTO containers (
                        id, container_no, invoice_no, job_no, customs_job_no, ppl_no,
                        shipping_line, discharge_port, vessel_voyage, container_type,
                        container_count, operational_stage, status, depot, eta_date,
                        discharge_date, due_date, destuff_date, returned_date,
                        stage2_moved, stage2_in_progress, stage3_moved, status_locked,
                        notes, raw_data, created_by, updated_by
                    ) VALUES (
                        :id, :container_no, :invoice_no, :job_no, :customs_job_no, :ppl_no,
                        :shipping_line, :discharge_port, :vessel_voyage, :container_type,
                        :container_count, :operational_stage, :status, :depot, :eta_date,
                        :discharge_date, :due_date, :destuff_date, :returned_date,
                        :stage2_moved, :stage2_in_progress, :stage3_moved, :status_locked,
                        :notes, :raw_data, :created_by, :updated_by
                    ) ON DUPLICATE KEY UPDATE
                        container_no = VALUES(container_no),
                        invoice_no = VALUES(invoice_no),
                        job_no = VALUES(job_no),
                        customs_job_no = VALUES(customs_job_no),
                        ppl_no = VALUES(ppl_no),
                        shipping_line = VALUES(shipping_line),
                        discharge_port = VALUES(discharge_port),
                        vessel_voyage = VALUES(vessel_voyage),
                        container_type = VALUES(container_type),
                        container_count = VALUES(container_count),
                        operational_stage = VALUES(operational_stage),
                        status = VALUES(status),
                        depot = VALUES(depot),
                        eta_date = VALUES(eta_date),
                        discharge_date = VALUES(discharge_date),
                        due_date = VALUES(due_date),
                        destuff_date = VALUES(destuff_date),
                        returned_date = VALUES(returned_date),
                        stage2_moved = VALUES(stage2_moved),
                        stage2_in_progress = VALUES(stage2_in_progress),
                        stage3_moved = VALUES(stage3_moved),
                        status_locked = VALUES(status_locked),
                        notes = VALUES(notes),
                        raw_data = VALUES(raw_data),
                        updated_by = VALUES(updated_by)";

                    $stmt = $pdo->prepare($sql);
                    $existingIds = [];

                    foreach ($value as $c) {
                        if (!is_array($c) || empty($c['id'])) continue;
                        $existingIds[] = $c['id'];

                        // Format dates to YYYY-MM-DD or NULL
                        $formatDate = function($d) {
                            if (empty($d)) return null;
                            $ts = strtotime($d);
                            return $ts ? date('Y-m-d', $ts) : null;
                        };

                        $stmt->execute([
                            ':id' => $c['id'],
                            ':container_no' => $c['containerNo'] ?? ($c['container_no'] ?? null),
                            ':invoice_no' => $c['invoiceNo'] ?? ($c['invoice_no'] ?? null),
                            ':job_no' => $c['jobNo'] ?? ($c['job_no'] ?? null),
                            ':customs_job_no' => $c['customsJobNo'] ?? ($c['customs_job_no'] ?? null),
                            ':ppl_no' => $c['pplNo'] ?? ($c['ppl_no'] ?? null),
                            ':shipping_line' => $c['shippingLine'] ?? ($c['shipping_line'] ?? null),
                            ':discharge_port' => $c['dischargePort'] ?? ($c['discharge_port'] ?? null),
                            ':vessel_voyage' => $c['vesselVoyage'] ?? ($c['vessel_voyage'] ?? null),
                            ':container_type' => $c['containerType'] ?? ($c['container_type'] ?? null),
                            ':container_count' => (int)($c['containerCount'] ?? ($c['container_count'] ?? 1)),
                            ':operational_stage' => $c['operationalStage'] ?? ($c['operational_stage'] ?? 'Stage 1'),
                            ':status' => $c['status'] ?? 'Within Free Time',
                            ':depot' => $c['depot'] ?? null,
                            ':eta_date' => $formatDate($c['etaDate'] ?? null),
                            ':discharge_date' => $formatDate($c['dischargeDate'] ?? null),
                            ':due_date' => $formatDate($c['dueDate'] ?? null),
                            ':destuff_date' => $formatDate($c['destuffDate'] ?? null),
                            ':returned_date' => $formatDate($c['returnedDate'] ?? null),
                            ':stage2_moved' => !empty($c['stage2Moved']) ? 1 : 0,
                            ':stage2_in_progress' => !empty($c['stage2InProgress']) ? 1 : 0,
                            ':stage3_moved' => !empty($c['stage3Moved']) ? 1 : 0,
                            ':status_locked' => !empty($c['statusLocked']) ? 1 : 0,
                            ':notes' => $c['notes'] ?? null,
                            ':raw_data' => json_encode($c, JSON_UNESCAPED_UNICODE),
                            ':created_by' => $c['createdBy'] ?? null,
                            ':updated_by' => $c['updatedBy'] ?? null
                        ]);
                    }

                    // Optional pruning: delete records removed from UI list if explicit delete happened
                    if (count($existingIds) > 0) {
                        $placeholders = implode(',', array_fill(0, count($existingIds), '?'));
                        $delStmt = $pdo->prepare("DELETE FROM containers WHERE id NOT IN ($placeholders)");
                        $delStmt->execute($existingIds);
                    } else {
                        $pdo->exec("DELETE FROM containers");
                    }

                    $pdo->commit();
                }
                echo json_encode(['status' => 'success', 'count' => is_array($value) ? count($value) : 0]);
                break;

            case 'clearance-shipments-v2':
                if (is_array($value)) {
                    $pdo->beginTransaction();
                    $stmt = $pdo->prepare("INSERT INTO clearance_shipments (id, invoice_no, customs_job_no, status, raw_data)
                        VALUES (:id, :invoice_no, :customs_job_no, :status, :raw_data)
                        ON DUPLICATE KEY UPDATE
                            invoice_no = VALUES(invoice_no),
                            customs_job_no = VALUES(customs_job_no),
                            status = VALUES(status),
                            raw_data = VALUES(raw_data)");

                    $ids = [];
                    foreach ($value as $item) {
                        if (!is_array($item) || empty($item['id'])) continue;
                        $ids[] = $item['id'];
                        $stmt->execute([
                            ':id' => $item['id'],
                            ':invoice_no' => $item['invoiceNo'] ?? null,
                            ':customs_job_no' => $item['customsJobNo'] ?? null,
                            ':status' => $item['status'] ?? 'Pending Customs Clearance',
                            ':raw_data' => json_encode($item, JSON_UNESCAPED_UNICODE)
                        ]);
                    }

                    if (count($ids) > 0) {
                        $placeholders = implode(',', array_fill(0, count($ids), '?'));
                        $delStmt = $pdo->prepare("DELETE FROM clearance_shipments WHERE id NOT IN ($placeholders)");
                        $delStmt->execute($ids);
                    } else {
                        $pdo->exec("DELETE FROM clearance_shipments");
                    }

                    $pdo->commit();
                }
                echo json_encode(['status' => 'success']);
                break;

            case 'users-v1':
                if (is_array($value)) {
                    $pdo->beginTransaction();
                    $stmt = $pdo->prepare("INSERT INTO users (id, username, name, email, password, role, active, memoji, raw_data)
                        VALUES (:id, :username, :name, :email, :password, :role, :active, :memoji, :raw_data)
                        ON DUPLICATE KEY UPDATE
                            username = VALUES(username),
                            name = VALUES(name),
                            email = VALUES(email),
                            password = VALUES(password),
                            role = VALUES(role),
                            active = VALUES(active),
                            memoji = VALUES(memoji),
                            raw_data = VALUES(raw_data)");

                    foreach ($value as $u) {
                        if (!is_array($u) || empty($u['id'])) continue;
                        $stmt->execute([
                            ':id' => $u['id'],
                            ':username' => $u['username'] ?? ('user_' . substr(md5(uniqid()), 0, 8)),
                            ':name' => $u['name'] ?? 'User',
                            ':email' => $u['email'] ?? '',
                            ':password' => $u['password'] ?? '123456',
                            ':role' => $u['role'] ?? 'yard_staff',
                            ':active' => !empty($u['active']) ? 1 : 0,
                            ':memoji' => $u['memoji'] ?? '👤',
                            ':raw_data' => json_encode($u, JSON_UNESCAPED_UNICODE)
                        ]);
                    }
                    $pdo->commit();
                }
                echo json_encode(['status' => 'success']);
                break;

            case 'audit-log-v1':
                if (is_array($value)) {
                    $pdo->beginTransaction();
                    $stmt = $pdo->prepare("INSERT INTO audit_logs (
                        id, action, container_id, container_no, user_name, user_role,
                        ip_address, user_agent, cf_ray, cf_country, changes, created_at
                    ) VALUES (
                        :id, :action, :container_id, :container_no, :user_name, :user_role,
                        :ip_address, :user_agent, :cf_ray, :cf_country, :changes, :created_at
                    ) ON DUPLICATE KEY UPDATE action = VALUES(action)");

                    foreach ($value as $log) {
                        if (!is_array($log) || empty($log['id'])) continue;
                        $stmt->execute([
                            ':id' => $log['id'],
                            ':action' => $log['action'] ?? 'action',
                            ':container_id' => $log['containerId'] ?? null,
                            ':container_no' => $log['containerNo'] ?? null,
                            ':user_name' => $log['userName'] ?? ($log['user'] ?? null),
                            ':user_role' => $log['userRole'] ?? ($_SESSION['panamex_user_role'] ?? 'user'),
                            ':ip_address' => $clientIp,
                            ':user_agent' => $userAgent,
                            ':cf_ray' => $cf['cf_ray'],
                            ':cf_country' => $cf['cf_country'],
                            ':changes' => json_encode($log['changes'] ?? [], JSON_UNESCAPED_UNICODE),
                            ':created_at' => $log['timestamp'] ?? date('Y-m-d H:i:s')
                        ]);
                    }
                    $pdo->commit();
                }
                echo json_encode(['status' => 'success']);
                break;

            case 'current-user-v1':
                $_SESSION['panamex_current_user_id'] = $value;
                echo json_encode(['status' => 'success', 'user' => $value]);
                break;

            default:
                // Save arbitrary key into app_settings (e.g. app-settings-v1, email-log-v1)
                $json = is_string($value) ? $value : json_encode($value, JSON_UNESCAPED_UNICODE);
                $stmt = $pdo->prepare("INSERT INTO app_settings (setting_key, setting_value)
                    VALUES (:k, :v)
                    ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
                $stmt->execute([':k' => $key, ':v' => $json]);
                echo json_encode(['status' => 'success', 'key' => $key]);
                break;
        }
    } catch (Exception $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'Method Not Allowed']);
