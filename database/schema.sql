-- ============================================================
-- Panamex Logistics Management OS - Database Schema
-- Target: MySQL 5.7+ / MariaDB 10.3+ (Hostinger Compatible)
-- Charset: utf8mb4 / Collation: utf8mb4_unicode_ci
-- ============================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------
-- 1. Table: containers
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `containers` (
  `id` VARCHAR(64) NOT NULL,
  `container_no` VARCHAR(64) DEFAULT NULL,
  `invoice_no` VARCHAR(128) DEFAULT NULL,
  `job_no` VARCHAR(128) DEFAULT NULL,
  `customs_job_no` VARCHAR(128) DEFAULT NULL,
  `ppl_no` VARCHAR(128) DEFAULT NULL,
  `shipping_line` VARCHAR(128) DEFAULT NULL,
  `discharge_port` VARCHAR(128) DEFAULT NULL,
  `vessel_voyage` VARCHAR(128) DEFAULT NULL,
  `container_type` VARCHAR(64) DEFAULT NULL,
  `container_count` INT DEFAULT 1,
  `operational_stage` VARCHAR(32) DEFAULT 'Stage 1',
  `status` VARCHAR(32) DEFAULT 'Within Free Time',
  `depot` VARCHAR(64) DEFAULT NULL,
  `eta_date` DATE DEFAULT NULL,
  `discharge_date` DATE DEFAULT NULL,
  `due_date` DATE DEFAULT NULL,
  `destuff_date` DATE DEFAULT NULL,
  `returned_date` DATE DEFAULT NULL,
  `stage2_moved` TINYINT(1) DEFAULT 0,
  `stage2_in_progress` TINYINT(1) DEFAULT 0,
  `stage3_moved` TINYINT(1) DEFAULT 0,
  `status_locked` TINYINT(1) DEFAULT 0,
  `notes` TEXT DEFAULT NULL,
  `raw_data` LONGTEXT DEFAULT NULL,
  `created_by` VARCHAR(128) DEFAULT NULL,
  `updated_by` VARCHAR(128) DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_container_no` (`container_no`),
  KEY `idx_invoice_no` (`invoice_no`),
  KEY `idx_job_no` (`job_no`),
  KEY `idx_customs_job_no` (`customs_job_no`),
  KEY `idx_ppl_no` (`ppl_no`),
  KEY `idx_operational_stage` (`operational_stage`),
  KEY `idx_status` (`status`),
  KEY `idx_due_date` (`due_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 2. Table: clearance_shipments
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `clearance_shipments` (
  `id` VARCHAR(64) NOT NULL,
  `invoice_no` VARCHAR(128) DEFAULT NULL,
  `customs_job_no` VARCHAR(128) DEFAULT NULL,
  `status` VARCHAR(64) DEFAULT 'Pending Customs Clearance',
  `raw_data` LONGTEXT DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_clearance_invoice` (`invoice_no`),
  KEY `idx_clearance_job` (`customs_job_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 3. Table: users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
  `id` VARCHAR(64) NOT NULL,
  `username` VARCHAR(64) NOT NULL,
  `name` VARCHAR(128) NOT NULL,
  `email` VARCHAR(128) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `role` VARCHAR(32) NOT NULL DEFAULT 'yard_staff',
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `memoji` VARCHAR(64) DEFAULT '👤',
  `raw_data` LONGTEXT DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`),
  KEY `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 4. Table: audit_logs (Enterprise Tamper-Proof Audit Trail)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` VARCHAR(64) NOT NULL,
  `action` VARCHAR(64) NOT NULL,
  `container_id` VARCHAR(64) DEFAULT NULL,
  `container_no` VARCHAR(64) DEFAULT NULL,
  `user_name` VARCHAR(128) DEFAULT NULL,
  `user_role` VARCHAR(32) DEFAULT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(255) DEFAULT NULL,
  `cf_ray` VARCHAR(64) DEFAULT NULL,
  `cf_country` VARCHAR(8) DEFAULT NULL,
  `changes` LONGTEXT DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_audit_container` (`container_id`),
  KEY `idx_audit_user` (`user_name`),
  KEY `idx_audit_action` (`action`),
  KEY `idx_audit_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 5. Table: login_security_logs (Brute Force & Auth Audit)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_security_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(64) NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `cf_ray` VARCHAR(64) DEFAULT NULL,
  `cf_country` VARCHAR(8) DEFAULT NULL,
  `status` ENUM('SUCCESS', 'FAILED', 'BLOCKED') NOT NULL,
  `failure_reason` VARCHAR(128) DEFAULT NULL,
  `attempted_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  KEY `idx_login_ip` (`ip_address`),
  KEY `idx_login_user` (`username`),
  KEY `idx_login_time` (`attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 5. Table: app_settings
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `app_settings` (
  `setting_key` VARCHAR(64) NOT NULL,
  `setting_value` LONGTEXT NOT NULL,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
