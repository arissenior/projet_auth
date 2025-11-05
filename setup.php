<?php
// setup.php
// Fichier d'installation et de configuration de SecureAuth

// Désactiver l'affichage des erreurs en production
error_reporting(0);
ini_set('display_errors', 0);

// Vérifier si le système est déjà installé
define('INSTALL_LOCK_FILE', 'install.lock');

if (file_exists(INSTALL_LOCK_FILE)) {
    die('
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Installation déjà effectuée - SecureAuth</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: \'Inter\', sans-serif; 
                    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #4f46e5 100%);
                    min-height: 100vh; 
                    display: flex; 
                    align-items: center; 
                    justify-content: center; 
                    color: white; 
                    padding: 20px;
                }
                .container { 
                    background: rgba(255, 255, 255, 0.1); 
                    backdrop-filter: blur(20px); 
                    border: 1px solid rgba(255, 255, 255, 0.2); 
                    border-radius: 20px; 
                    padding: 40px; 
                    max-width: 500px; 
                    width: 100%; 
                    text-align: center; 
                }
                .icon { 
                    font-size: 4rem; 
                    color: #10b981; 
                    margin-bottom: 20px; 
                }
                h1 { 
                    font-size: 2rem; 
                    margin-bottom: 15px; 
                    font-weight: 700; 
                }
                p { 
                    color: #cbd5e1; 
                    margin-bottom: 25px; 
                    line-height: 1.6; 
                }
                .btn { 
                    display: inline-flex; 
                    align-items: center; 
                    gap: 10px; 
                    padding: 12px 24px; 
                    background: #6366f1; 
                    color: white; 
                    text-decoration: none; 
                    border-radius: 12px; 
                    font-weight: 600; 
                    transition: all 0.3s ease; 
                }
                .btn:hover { 
                    background: #4f46e5; 
                    transform: translateY(-2px); 
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <h1>Installation déjà effectuée</h1>
                <p>Le système SecureAuth est déjà installé et configuré. Vous pouvez accéder à votre application.</p>
                <a href="index.php" class="btn">
                    <i class="fas fa-rocket"></i>
                    Accéder à l\'application
                </a>
            </div>
        </body>
        </html>
    ');
}

// Traitement du formulaire d'installation
$errors = [];
$success = false;
$step = isset($_GET['step']) ? (int)$_GET['step'] : 1;

if ($_POST) {
    try {
        if ($step === 1) {
            // Validation des paramètres de base de données
            $db_host = $_POST['db_host'] ?? 'localhost';
            $db_name = $_POST['db_name'] ?? 'secureauth_db';
            $db_user = $_POST['db_user'] ?? '';
            $db_pass = $_POST['db_pass'] ?? '';
            $db_port = $_POST['db_port'] ?? '5432';

            if (empty($db_user)) {
                throw new Exception("Le nom d'utilisateur de la base de données est requis.");
            }

            // Test de connexion à la base de données
            $dsn = "pgsql:host=$db_host;port=$db_port;dbname=$db_name";
            try {
                $test_pdo = new PDO($dsn, $db_user, $db_pass);
                $test_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                // Vérifier si la base de données existe
                $stmt = $test_pdo->query("SELECT 1 FROM pg_database WHERE datname = '$db_name'");
                if (!$stmt->fetch()) {
                    // Créer la base de données si elle n'existe pas
                    $test_pdo->exec("CREATE DATABASE $db_name");
                }
                
                $test_pdo = null; // Fermer la connexion de test
                
            } catch (PDOException $e) {
                throw new Exception("Impossible de se connecter à la base de données : " . $e->getMessage());
            }

            // Stocker les informations en session pour l'étape suivante
            session_start();
            $_SESSION['db_config'] = [
                'host' => $db_host,
                'name' => $db_name,
                'user' => $db_user,
                'pass' => $db_pass,
                'port' => $db_port
            ];

            $step = 2;

        } elseif ($step === 2) {
            session_start();
            $db_config = $_SESSION['db_config'] ?? null;
            
            if (!$db_config) {
                throw new Exception("Configuration de base de données non trouvée. Veuillez recommencer l'installation.");
            }

            // Configuration de l'application
            $app_name = $_POST['app_name'] ?? 'SecureAuth';
            $app_url = $_POST['app_url'] ?? ($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']);
            $admin_email = $_POST['admin_email'] ?? '';
            $admin_username = $_POST['admin_username'] ?? 'admin';
            $admin_password = $_POST['admin_password'] ?? '';
            $admin_confirm_password = $_POST['admin_confirm_password'] ?? '';

            // Validation
            if (empty($admin_email) || empty($admin_username) || empty($admin_password)) {
                throw new Exception("Tous les champs administrateur sont requis.");
            }

            if ($admin_password !== $admin_confirm_password) {
                throw new Exception("Les mots de passe administrateur ne correspondent pas.");
            }

            if (strlen($admin_password) < 8) {
                throw new Exception("Le mot de passe administrateur doit contenir au moins 8 caractères.");
            }

            // Connexion à la base de données avec la configuration stockée
            $dsn = "pgsql:host={$db_config['host']};port={$db_config['port']};dbname={$db_config['name']}";
            $pdo = new PDO($dsn, $db_config['user'], $db_config['pass']);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Création des tables
            $sql_script = get_sql_schema();
            $pdo->exec($sql_script);

            // Création du compte administrateur
            $admin_password_hash = password_hash($admin_password, PASSWORD_DEFAULT);
            $admin_avatar = 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&h=150&fit=crop&crop=face';
            
            $stmt = $pdo->prepare("
                INSERT INTO users (username, email, password, first_name, last_name, is_verified, is_active, avatar_url) 
                VALUES (?, ?, ?, 'Administrateur', 'Système', TRUE, TRUE, ?)
            ");
            $stmt->execute([$admin_username, $admin_email, $admin_password_hash, $admin_avatar]);
            
            $admin_id = $pdo->lastInsertId();

            // Configuration des paramètres de sécurité pour l'admin
            $stmt = $pdo->prepare("
                INSERT INTO security_settings (user_id, two_factor_enabled, login_notifications, suspicious_activity_alerts) 
                VALUES (?, TRUE, TRUE, TRUE)
            ");
            $stmt->execute([$admin_id]);

            // Création du fichier config.php
            $config_content = generate_config_file($db_config, $app_name, $app_url);
            if (!file_put_contents('config.php', $config_content)) {
                throw new Exception("Impossible de créer le fichier config.php. Vérifiez les permissions.");
            }

            // Création du fichier de verrouillage d'installation
            file_put_contents(INSTALL_LOCK_FILE, 'Installation complétée le ' . date('Y-m-d H:i:s'));

            // Nettoyer la session
            unset($_SESSION['db_config']);
            session_destroy();

            $success = true;
            $step = 3;

        }
    } catch (Exception $e) {
        $errors[] = $e->getMessage();
    }
}

// Fonction pour générer le schéma SQL
function get_sql_schema() {
    return "
        -- Extension pour UUID
        CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";

        -- Table des utilisateurs
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            first_name VARCHAR(50),
            last_name VARCHAR(50),
            avatar_url VARCHAR(255),
            is_active BOOLEAN DEFAULT TRUE,
            is_verified BOOLEAN DEFAULT FALSE,
            verification_token VARCHAR(100),
            reset_token VARCHAR(100),
            reset_token_expires TIMESTAMP,
            last_login TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des sessions
        CREATE TABLE user_sessions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            session_token VARCHAR(255) NOT NULL,
            ip_address INET,
            user_agent TEXT,
            device_info JSONB,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des activités utilisateur
        CREATE TABLE user_activities (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            activity_type VARCHAR(50) NOT NULL,
            description TEXT,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des paramètres de sécurité
        CREATE TABLE security_settings (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            two_factor_secret VARCHAR(100),
            biometric_enabled BOOLEAN DEFAULT FALSE,
            login_notifications BOOLEAN DEFAULT TRUE,
            suspicious_activity_alerts BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des logs de sécurité
        CREATE TABLE security_logs (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            event_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            description TEXT,
            ip_address INET,
            user_agent TEXT,
            metadata JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des statistiques de connexion
        CREATE TABLE login_stats (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            login_date DATE NOT NULL,
            login_count INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des préférences utilisateur
        CREATE TABLE user_preferences (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            theme VARCHAR(20) DEFAULT 'auto',
            language VARCHAR(5) DEFAULT 'fr',
            notifications BOOLEAN DEFAULT TRUE,
            newsletter BOOLEAN DEFAULT FALSE,
            data_sharing BOOLEAN DEFAULT FALSE,
            analytics BOOLEAN DEFAULT TRUE,
            profile_visibility VARCHAR(20) DEFAULT 'private',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Index pour les performances
        CREATE INDEX idx_users_email ON users(email);
        CREATE INDEX idx_users_username ON users(username);
        CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
        CREATE INDEX idx_sessions_token ON user_sessions(session_token);
        CREATE INDEX idx_activities_user_id ON user_activities(user_id);
        CREATE INDEX idx_activities_created_at ON user_activities(created_at);
        CREATE INDEX idx_security_logs_user_id ON security_logs(user_id);
        CREATE INDEX idx_security_logs_created_at ON security_logs(created_at);
        CREATE INDEX idx_login_stats_user_id ON login_stats(user_id);

        -- Fonction pour mettre à jour updated_at
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS \$\$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        \$\$ language 'plpgsql';

        -- Triggers pour updated_at
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        CREATE TRIGGER update_security_settings_updated_at BEFORE UPDATE ON security_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        CREATE TRIGGER update_user_preferences_updated_at BEFORE UPDATE ON user_preferences FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

        -- Vues utiles
        CREATE VIEW user_security_overview AS
        SELECT 
            u.id,
            u.username,
            u.email,
            u.is_active,
            u.is_verified,
            u.last_login,
            u.login_attempts,
            s.two_factor_enabled,
            s.biometric_enabled,
            COUNT(DISTINCT us.id) as active_sessions,
            COUNT(DISTINCT ua.id) as total_activities
        FROM users u
        LEFT JOIN security_settings s ON u.id = s.user_id
        LEFT JOIN user_sessions us ON u.id = us.user_id AND us.expires_at > CURRENT_TIMESTAMP
        LEFT JOIN user_activities ua ON u.id = ua.user_id
        GROUP BY u.id, u.username, u.email, u.is_active, u.is_verified, u.last_login, u.login_attempts, s.two_factor_enabled, s.biometric_enabled;
    ";
}

// Fonction pour générer le fichier config.php
function generate_config_file($db_config, $app_name, $app_url) {
    $secret_key = bin2hex(random_bytes(32));
    $encryption_key = bin2hex(random_bytes(16));
    
    return "<?php
// config.php - Généré automatiquement par l'installateur
session_start();

class Config {
    // Database configuration
    const DB_HOST = '{$db_config['host']}';
    const DB_NAME = '{$db_config['name']}';
    const DB_USER = '{$db_config['user']}';
    const DB_PASS = '{$db_config['pass']}';
    const DB_PORT = '{$db_config['port']}';
    
    // Security configuration
    const JWT_SECRET = '$secret_key';
    const ENCRYPTION_KEY = '$encryption_key';
    const CSRF_TOKEN_NAME = 'csrf_token';
    
    // Application settings
    const APP_NAME = '$app_name';
    const APP_VERSION = '2.0.0';
    const APP_URL = '$app_url';
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
    private static \$connection = null;
    
    public static function getConnection() {
        if (self::\$connection === null) {
            try {
                \$dsn = \"pgsql:host=\" . Config::DB_HOST . \";port=\" . Config::DB_PORT . \";dbname=\" . Config::DB_NAME;
                self::\$connection = new PDO(\$dsn, Config::DB_USER, Config::DB_PASS);
                self::\$connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::\$connection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                self::\$connection->exec(\"SET NAMES 'UTF8'\");
            } catch (PDOException \$e) {
                error_log(\"Database connection failed: \" . \$e->getMessage());
                throw new Exception(\"Database connection error. Please try again later.\");
            }
        }
        return self::\$connection;
    }
}

class Security {
    public static function sanitizeInput(\$data) {
        if (is_array(\$data)) {
            return array_map([self::class, 'sanitizeInput'], \$data);
        }
        return htmlspecialchars(strip_tags(trim(\$data)), ENT_QUOTES, 'UTF-8');
    }
    
    public static function generateCSRFToken() {
        if (empty(\$_SESSION[Config::CSRF_TOKEN_NAME])) {
            \$_SESSION[Config::CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        }
        return \$_SESSION[Config::CSRF_TOKEN_NAME];
    }
    
    public static function validateCSRFToken(\$token) {
        if (!isset(\$_SESSION[Config::CSRF_TOKEN_NAME]) || !hash_equals(\$_SESSION[Config::CSRF_TOKEN_NAME], \$token)) {
            throw new Exception(\"CSRF token validation failed.\");
        }
        return true;
    }
    
    public static function generateRandomString(\$length = 32) {
        return bin2hex(random_bytes(\$length));
    }
    
    public static function passwordHash(\$password) {
        return password_hash(\$password, PASSWORD_DEFAULT, ['cost' => 12]);
    }
    
    public static function passwordVerify(\$password, \$hash) {
        return password_verify(\$password, \$hash);
    }
    
    public static function validatePasswordStrength(\$password) {
        \$errors = [];
        
        if (strlen(\$password) < Config::PASSWORD_MIN_LENGTH) {
            \$errors[] = \"Le mot de passe doit contenir au moins \" . Config::PASSWORD_MIN_LENGTH . \" caractères.\";
        }
        
        if (Config::PASSWORD_REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', \$password)) {
            \$errors[] = \"Le mot de passe doit contenir au moins une lettre majuscule.\";
        }
        
        if (Config::PASSWORD_REQUIRE_LOWERCASE && !preg_match('/[a-z]/', \$password)) {
            \$errors[] = \"Le mot de passe doit contenir au moins une lettre minuscule.\";
        }
        
        if (Config::PASSWORD_REQUIRE_NUMBERS && !preg_match('/[0-9]/', \$password)) {
            \$errors[] = \"Le mot de passe doit contenir au moins un chiffre.\";
        }
        
        if (Config::PASSWORD_REQUIRE_SYMBOLS && !preg_match('/[!@#$%^&*()\\-_=+{};:,<.>]/', \$password)) {
            \$errors[] = \"Le mot de passe doit contenir au moins un caractère spécial.\";
        }
        
        return \$errors;
    }
}

class Auth {
    public static function isLoggedIn() {
        return isset(\$_SESSION['user_id']) && !empty(\$_SESSION['user_id']);
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
            \$db = Database::getConnection();
            \$stmt = \$db->prepare(\"
                SELECT u.*, s.two_factor_enabled, s.biometric_enabled 
                FROM users u 
                LEFT JOIN security_settings s ON u.id = s.user_id 
                WHERE u.id = ?
            \");
            \$stmt->execute([\$_SESSION['user_id']]);
            return \$stmt->fetch();
        } catch (PDOException \$e) {
            error_log(\"Get user error: \" . \$e->getMessage());
            return null;
        }
    }
    
    public static function logActivity(\$userId, \$activityType, \$description = '', \$ipAddress = null, \$userAgent = null) {
        try {
            \$db = Database::getConnection();
            \$stmt = \$db->prepare(\"
                INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            \");
            \$stmt->execute([
                \$userId, 
                \$activityType, 
                \$description,
                \$ipAddress ?? \$_SERVER['REMOTE_ADDR'],
                \$userAgent ?? \$_SERVER['HTTP_USER_AGENT']
            ]);
        } catch (PDOException \$e) {
            error_log(\"Activity logging error: \" . \$e->getMessage());
        }
    }
}

// Initialize CSRF token
if (session_status() === PHP_SESSION_ACTIVE && empty(\$_SESSION[Config::CSRF_TOKEN_NAME])) {
    Security::generateCSRFToken();
}

// Auto-load classes
spl_autoload_register(function (\$class_name) {
    \$file = 'classes/' . \$class_name . '.class.php';
    if (file_exists(\$file)) {
        require_once \$file;
    }
});

// Error handling
set_error_handler(function(\$errno, \$errstr, \$errfile, \$errline) {
    error_log(\"Error [\$errno]: \$errstr in \$errfile on line \$errline\");
    if (defined('DEBUG') && DEBUG) {
        echo \"<div class='alert alert-danger'>Error: \$errstr</div>\";
    }
});

// Timezone
date_default_timezone_set('Europe/Paris');
?>";
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installation - SecureAuth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/setup.css">
</head>
<body>
    <!-- Animation de fond -->
    <div class="background-animation" id="background-animation"></div>
    
    <div class="install-container">
        <div class="install-header">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <span>SecureAuth</span>
            </div>
            <h1>Installation du Système</h1>
        </div>
        
        <div class="install-content">
            <!-- Étapes de progression -->
            <div class="progress-steps">
                <div class="progress-step <?= $step >= 1 ? 'active' : '' ?> <?= $step > 1 ? 'completed' : '' ?>">
                    1
                    <div class="step-label">Base de données</div>
                </div>
                <div class="progress-step <?= $step >= 2 ? 'active' : '' ?> <?= $step > 2 ? 'completed' : '' ?>">
                    2
                    <div class="step-label">Configuration</div>
                </div>
                <div class="progress-step <?= $step >= 3 ? 'active' : '' ?>">
                    3
                    <div class="step-label">Terminé</div>
                </div>
            </div>
            
            <!-- Messages d'erreur -->
            <?php if (!empty($errors)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <div>
                        <?php foreach ($errors as $error): ?>
                            <div><?= htmlspecialchars($error) ?></div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
            
            <!-- Étape 1: Configuration de la base de données -->
            <form method="POST" class="form-step <?= $step === 1 ? 'active' : '' ?>" id="step-1">
                <div class="system-check">
                    <h3>Vérification du système</h3>
                    <?php
                    $checks = [
                        'PHP Version >= 7.4' => version_compare(PHP_VERSION, '7.4.0', '>='),
                        'Extension PDO PostgreSQL' => extension_loaded('pdo_pgsql'),
                        'Extension OpenSSL' => extension_loaded('openssl'),
                        'Permissions en écriture' => is_writable('.'),
                        'Session support' => function_exists('session_start')
                    ];
                    
                    foreach ($checks as $label => $result): 
                        $icon = $result ? 'fa-check-circle success' : 'fa-times-circle error';
                        $class = $result ? 'success' : 'error';
                    ?>
                        <div class="check-item <?= $class ?>">
                            <i class="fas <?= $icon ?>"></i>
                            <span><?= $label ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <div class="form-group">
                    <label for="db_host">Hôte de la base de données</label>
                    <input type="text" id="db_host" name="db_host" class="form-control" value="localhost" required>
                    <div class="form-text">Généralement "localhost" ou l'adresse IP de votre serveur PostgreSQL</div>
                </div>
                
                <div class="form-group">
                    <label for="db_port">Port de la base de données</label>
                    <input type="number" id="db_port" name="db_port" class="form-control" value="5432" required>
                    <div class="form-text">Le port par défaut de PostgreSQL est 5432</div>
                </div>
                
                <div class="form-group">
                    <label for="db_name">Nom de la base de données</label>
                    <input type="text" id="db_name" name="db_name" class="form-control" value="secureauth_db" required>
                    <div class="form-text">La base de données sera créée si elle n'existe pas</div>
                </div>
                
                <div class="form-group">
                    <label for="db_user">Utilisateur de la base de données</label>
                    <input type="text" id="db_user" name="db_user" class="form-control" required>
                    <div class="form-text">L'utilisateur PostgreSQL avec les droits de création de base de données</div>
                </div>
                
                <div class="form-group">
                    <label for="db_pass">Mot de passe de la base de données</label>
                    <input type="password" id="db_pass" name="db_pass" class="form-control">
                    <div class="form-text">Mot de passe de l'utilisateur PostgreSQL</div>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-full">
                        Continuer vers l'étape 2
                        <i class="fas fa-arrow-right"></i>
                    </button>
                </div>
            </form>
            
            <!-- Étape 2: Configuration de l'application -->
            <form method="POST" class="form-step <?= $step === 2 ? 'active' : '' ?>" id="step-2">
                <input type="hidden" name="step" value="2">
                
                <div class="form-group">
                    <label for="app_name">Nom de l'application</label>
                    <input type="text" id="app_name" name="app_name" class="form-control" value="SecureAuth" required>
                    <div class="form-text">Le nom qui sera affiché dans l'application</div>
                </div>
                
                <div class="form-group">
                    <label for="app_url">URL de l'application</label>
                    <input type="url" id="app_url" name="app_url" class="form-control" value="<?= ($_SERVER['REQUEST_SCHEME'] ?? 'http') . '://' . $_SERVER['HTTP_HOST'] ?>" required>
                    <div class="form-text">L'URL complète où sera hébergée l'application</div>
                </div>
                
                <div class="form-group">
                    <label for="admin_username">Nom d'utilisateur administrateur</label>
                    <input type="text" id="admin_username" name="admin_username" class="form-control" value="admin" required>
                    <div class="form-text">Le nom d'utilisateur pour le compte administrateur</div>
                </div>
                
                <div class="form-group">
                    <label for="admin_email">Email administrateur</label>
                    <input type="email" id="admin_email" name="admin_email" class="form-control" required>
                    <div class="form-text">L'adresse email pour le compte administrateur</div>
                </div>
                
                <div class="form-group">
                    <label for="admin_password">Mot de passe administrateur</label>
                    <input type="password" id="admin_password" name="admin_password" class="form-control" required>
                    <div class="form-text">Minimum 8 caractères avec majuscules, minuscules, chiffres et caractères spéciaux</div>
                </div>
                
                <div class="form-group">
                    <label for="admin_confirm_password">Confirmer le mot de passe</label>
                    <input type="password" id="admin_confirm_password" name="admin_confirm_password" class="form-control" required>
                </div>
                
                <div class="form-actions">
                    <a href="?step=1" class="btn" style="background: var(--gray);">
                        <i class="fas fa-arrow-left"></i>
                        Retour
                    </a>
                    <button type="submit" class="btn btn-full">
                        Installer le système
                        <i class="fas fa-rocket"></i>
                    </button>
                </div>
            </form>
            
            <!-- Étape 3: Installation terminée -->
            <div class="form-step <?= $step === 3 ? 'active' : '' ?>" id="step-3">
                <div class="success-screen">
                    <div class="success-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h1 class="success-title">Installation réussie !</h1>
                    <p class="success-message">
                        Félicitations ! SecureAuth a été installé avec succès sur votre serveur. 
                        Vous pouvez maintenant accéder à votre application sécurisée.
                    </p>
                    
                    <div class="form-actions">
                        <a href="index.php" class="btn btn-success">
                            <i class="fas fa-rocket"></i>
                            Accéder à l'application
                        </a>
                        <a href="login.php" class="btn">
                            <i class="fas fa-sign-in-alt"></i>
                            Page de connexion
                        </a>
                    </div>
                    
                    <div class="next-steps">
                        <h3>Prochaines étapes recommandées :</h3>
                        <ul>
                            <li>
                                <i class="fas fa-check"></i>
                                <span>Supprimez le fichier setup.php pour des raisons de sécurité</span>
                            </li>
                            <li>
                                <i class="fas fa-check"></i>
                                <span>Configurez votre serveur web pour utiliser HTTPS</span>
                            </li>
                            <li>
                                <i class="fas fa-check"></i>
                                <span>Sauvegardez régulièrement votre base de données</span>
                            </li>
                            <li>
                                <i class="fas fa-check"></i>
                                <span>Configurez les paramètres d'email pour les notifications</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="js/setup.js"></script>
</body>
</html>