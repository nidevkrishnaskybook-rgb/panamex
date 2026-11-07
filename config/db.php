<?php
/**
 * Panamex Logistics Management OS
 * Database Connection & Helper Functions
 */

if (!function_exists('getDbConfigFile')) {
    function getDbConfigFile() {
        return __DIR__ . '/config.php';
    }
}

if (!function_exists('isDbConfigured')) {
    function isDbConfigured() {
        $file = getDbConfigFile();
        if (!file_exists($file)) return false;
        $cfg = include $file;
        return is_array($cfg) && !empty($cfg['db_name']) && !empty($cfg['db_user']);
    }
}

if (!function_exists('getDbConnection')) {
    function getDbConnection() {
        static $pdo = null;
        if ($pdo !== null) return $pdo;

        $file = getDbConfigFile();
        if (!file_exists($file)) {
            throw new Exception("Database configuration file not found. Please run install.php first.");
        }

        $cfg = include $file;
        if (!is_array($cfg) || empty($cfg['db_name'])) {
            throw new Exception("Invalid database configuration. Please re-run install.php.");
        }

        $host = !empty($cfg['db_host']) ? $cfg['db_host'] : 'localhost';
        $port = !empty($cfg['db_port']) ? $cfg['db_port'] : '3306';
        $dbname = $cfg['db_name'];
        $user = $cfg['db_user'];
        $pass = isset($cfg['db_pass']) ? $cfg['db_pass'] : '';
        $charset = !empty($cfg['charset']) ? $cfg['charset'] : 'utf8mb4';

        $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset={$charset}";

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$charset} COLLATE {$charset}_unicode_ci"
        ];

        try {
            $pdo = new PDO($dsn, $user, $pass, $options);
            return $pdo;
        } catch (PDOException $e) {
            throw new Exception("Database Connection Error: " . $e->getMessage());
        }
    }
}
