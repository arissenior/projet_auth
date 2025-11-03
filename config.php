<?php
// config.php
session_start();

// Debug mode configuration
define('DEBUG', false);

class Config {
    // Database configuration
    const DB_HOST = 'localhost';
    const DB_NAME = 'secureauth_db';
    const DB_USER = 'postgres';
    const DB_PASS = 'aristide16';
    const DB_PORT = '5432';
    
    // Security configuration
    const JWT_SECRET = 'votre_clé_secrète_très_longue_et_complexe_ici';
    const ENCRYPTION_KEY = 'votre_clé_de_chiffrement_32_caractères';
    const CSRF_TOKEN_NAME = 'csrf_token';
    
    // Application settings
    const APP_NAME = 'SecureAuth';
    const APP_VERSION = '2.0.0';
    const APP_URL = 'http://localhost:8000';
    const UPLOAD_DIR = 'uploads/';
    
    // Session settings
    const SESSION_TIMEOUT = 1800; // 30 minutes
    const REMEMBER_ME_DURATION = 2592000; // 30 days
    
    // Security settings
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOCKOUT_DURATION = 900; // 15 minutes
    const PASSWORD_MIN_LENGTH = 8;
    const PASSWORD_REQUIRE_UPPERCASE = true;
    const PASSWORD_REQUIRE_LOWERCASE = true;
    const PASSWORD_REQUIRE_NUMBERS = true;
    const PASSWORD_REQUIRE_SYMBOLS = true;
}

class Database {
    private static $connection = null;
    
    public static function getConnection() {
        if (self::$connection === null) {
            try {
                $dsn = "pgsql:host=" . Config::DB_HOST . ";port=" . Config::DB_PORT . ";dbname=" . Config::DB_NAME;
                self::$connection = new PDO($dsn, Config::DB_USER, Config::DB_PASS);
                self::$connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$connection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                self::$connection->exec("SET NAMES 'UTF8'");
            } catch (PDOException $e) {
                error_log("Database connection failed: " . $e->getMessage());
                throw new Exception("Database connection error. Please try again later.");
            }
        }
        return self::$connection;
    }
}

class Security {
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
    }
    
    public static function generateCSRFToken() {
        if (empty($_SESSION[Config::CSRF_TOKEN_NAME])) {
            $_SESSION[Config::CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        }
        return $_SESSION[Config::CSRF_TOKEN_NAME];
    }
    
    public static function validateCSRFToken($token) {
        if (!isset($_SESSION[Config::CSRF_TOKEN_NAME]) || !hash_equals($_SESSION[Config::CSRF_TOKEN_NAME], $token)) {
            throw new Exception("CSRF token validation failed.");
        }
        return true;
    }
    
    public static function generateRandomString($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    public static function passwordHash($password) {
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
    }
    
    public static function passwordVerify($password, $hash) {
        return password_verify($password, $hash);
    }
    
    public static function validatePasswordStrength($password) {
        $errors = [];
        
        if (strlen($password) < Config::PASSWORD_MIN_LENGTH) {
            $errors[] = "Le mot de passe doit contenir au moins " . Config::PASSWORD_MIN_LENGTH . " caractères.";
        }
        
        if (Config::PASSWORD_REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins une lettre majuscule.";
        }
        
        if (Config::PASSWORD_REQUIRE_LOWERCASE && !preg_match('/[a-z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins une lettre minuscule.";
        }
        
        if (Config::PASSWORD_REQUIRE_NUMBERS && !preg_match('/[0-9]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins un chiffre.";
        }
        
        if (Config::PASSWORD_REQUIRE_SYMBOLS && !preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins un caractère spécial.";
        }
        
        return $errors;
    }
}

class Auth {
    public static function isLoggedIn() {
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    public static function requireLogin() {
        if (!self::isLoggedIn()) {
            header('Location: login.php');
            exit;
        }
    }
    
    public static function requireGuest() {
        if (self::isLoggedIn()) {
            header('Location: dashboard.php');
            exit;
        }
    }
    
    public static function getUser() {
        if (!self::isLoggedIn()) {
            return null;
        }
        
        try {
            $db = Database::getConnection();
            $stmt = $db->prepare("
                SELECT u.*, s.two_factor_enabled, s.biometric_enabled 
                FROM users u 
                LEFT JOIN security_settings s ON u.id = s.user_id 
                WHERE u.id = ?
            ");
            $stmt->execute([$_SESSION['user_id']]);
            return $stmt->fetch();
        } catch (PDOException $e) {
            error_log("Get user error: " . $e->getMessage());
            return null;
        }
    }
    
    public static function logActivity($userId, $activityType, $description = '', $ipAddress = null, $userAgent = null) {
        try {
            $db = Database::getConnection();
            $stmt = $db->prepare("
                INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $userId, 
                $activityType, 
                $description,
                $ipAddress ?? $_SERVER['REMOTE_ADDR'],
                $userAgent ?? $_SERVER['HTTP_USER_AGENT']
            ]);
        } catch (PDOException $e) {
            error_log("Activity logging error: " . $e->getMessage());
        }
    }
}

// Initialize CSRF token
if (session_status() === PHP_SESSION_ACTIVE && empty($_SESSION[Config::CSRF_TOKEN_NAME])) {
    Security::generateCSRFToken();
}

// Auto-load classes
spl_autoload_register(function ($class_name) {
    $file = 'classes/' . $class_name . '.class.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

// Error handling
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    error_log("Error [$errno]: $errstr in $errfile on line $errline");
    if (defined('DEBUG') && DEBUG) {
        echo "<div class='alert alert-danger'>Error: $errstr</div>";
    }
});

// Timezone
date_default_timezone_set('Europe/Paris');
?>