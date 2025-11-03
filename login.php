<?php
// login.php
require_once 'config.php';
Auth::requireGuest();

$csrfToken = Security::generateCSRFToken();
$error = '';
$success = '';

// Traitement du formulaire de connexion
if ($_POST && isset($_POST['login'])) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        $identifier = Security::sanitizeInput($_POST['identifier']);
        $password = $_POST['password'];
        $remember = isset($_POST['remember']) ? true : false;
        
        if (empty($identifier) || empty($password)) {
            throw new Exception("Veuillez remplir tous les champs.");
        }
        
        // Vérifier si l'utilisateur existe par email ou username
        $db = Database::getConnection();
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
        $stmt->execute([$identifier, $identifier]);
        $user = $stmt->fetch();
        
        if ($user && Security::passwordVerify($password, $user['password'])) {
            if (!$user['is_active']) {
                throw new Exception("Votre compte a été désactivé. Veuillez contacter le support.");
            }
            
            // Connexion réussie
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['last_login'] = date('Y-m-d H:i:s');
            
            // Mettre à jour la dernière connexion
            $updateStmt = $db->prepare("UPDATE users SET last_login = ?, login_attempts = 0 WHERE id = ?");
            $updateStmt->execute([date('Y-m-d H:i:s'), $user['id']]);
            
            // Créer une session
            $sessionToken = Security::generateRandomString(64);
            $expiresAt = $remember ? 
                date('Y-m-d H:i:s', time() + Config::REMEMBER_ME_DURATION) : 
                date('Y-m-d H:i:s', time() + Config::SESSION_TIMEOUT);
            
            $sessionStmt = $db->prepare("
                INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $sessionStmt->execute([
                $user['id'],
                $sessionToken,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'],
                $expiresAt
            ]);
            
            $_SESSION['session_id'] = $db->lastInsertId();
            
            // Journaliser l'activité
            Auth::logActivity($user['id'], 'login', 'User logged in successfully', $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
            
            // Redirection vers le dashboard
            header('Location: dashboard.php');
            exit;
            
        } else {
            // Incrémenter les tentatives échouées
            if ($user) {
                $attemptsStmt = $db->prepare("UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?");
                $attemptsStmt->execute([$user['id']]);
                
                // Journaliser la tentative échouée
                Auth::logActivity($user['id'], 'login_failed', 'Failed login attempt', $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
            }
            
            throw new Exception("Identifiants incorrects. Veuillez réessayer.");
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Traitement de la réinitialisation de mot de passe
if ($_POST && isset($_POST['reset_password'])) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        $email = Security::sanitizeInput($_POST['reset_email']);
        
        if (empty($email)) {
            throw new Exception("Veuillez entrer votre adresse email.");
        }
        
        // Vérifier si l'utilisateur existe
        $db = Database::getConnection();
        $stmt = $db->prepare("SELECT id, email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        if ($user) {
            // Générer un token de réinitialisation
            $resetToken = Security::generateRandomString(32);
            $resetExpires = date('Y-m-d H:i:s', time() + 3600); // 1 heure
            
            $updateStmt = $db->prepare("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?");
            $updateStmt->execute([$resetToken, $resetExpires, $user['id']]);
            
            // Ici, vous enverriez un email avec le lien de réinitialisation
            // Pour l'instant, nous simulons l'envoi
            $success = "Un email de réinitialisation a été envoyé à $email";
            
            // Journaliser la demande
            Auth::logActivity($user['id'], 'password_reset_requested', 'Password reset requested');
        } else {
            // Pour des raisons de sécurité, on ne révèle pas si l'email existe
            $success = "Si votre email est enregistré, vous recevrez un lien de réinitialisation.";
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion | SecureAuth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/login.css">
</head>
<body>
    <!-- Animation de fond -->
    <div class="background-animation" id="background-animation"></div>
    
    <div class="login-container">
        <div class="welcome-section">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <span>SecureAuth</span>
            </div>
            
            <div class="welcome-content">
                <h1 class="welcome-title">Content de vous revoir !</h1>
                <p class="welcome-subtitle">
                    Reconnectez-vous à votre compte pour accéder à toutes vos données sécurisées 
                    et continuer là où vous vous étiez arrêté.
                </p>
                
                <div class="features">
                    <div class="feature">
                        <i class="fas fa-fingerprint"></i>
                        <div class="feature-text">
                            <h3>Authentification Sécurisée</h3>
                            <p>Accédez à votre compte en toute sécurité avec nos multiples couches de protection</p>
                        </div>
                    </div>
                    <div class="feature">
                        <i class="fas fa-bolt"></i>
                        <div class="feature-text">
                            <h3>Connexion Rapide</h3>
                            <p>Retrouvez vos données en quelques secondes grâce à notre système optimisé</p>
                        </div>
                    </div>
                    <div class="feature">
                        <i class="fas fa-shield-check"></i>
                        <div class="feature-text">
                            <h3>Protection Avancée</h3>
                            <p>Votre compte est protégé 24h/24 contre les menaces et intrusions</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="form-section">
            <div class="form-container">
                <div class="form-header">
                    <h1>Connexion</h1>
                    <p>Accédez à votre espace sécurisé</p>
                </div>
                
                <!-- Messages d'alerte -->
                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= $error ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <span><?= $success ?></span>
                    </div>
                <?php endif; ?>
                
                <!-- Formulaire de connexion -->
                <form method="POST" id="login-form">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="login" value="1">
                    
                    <div class="form-group">
                        <label for="identifier">Email ou nom d'utilisateur</label>
                        <div class="input-with-icon">
                            <i class="fas fa-user"></i>
                            <input type="text" id="identifier" name="identifier" placeholder="Entrez votre email ou nom d'utilisateur" required 
                                   value="<?= isset($_POST['identifier']) ? htmlspecialchars($_POST['identifier']) : '' ?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Mot de passe</label>
                        <div class="input-with-icon">
                            <i class="fas fa-lock"></i>
                            <input type="password" id="password" name="password" placeholder="Entrez votre mot de passe" required>
                            <i class="fas fa-eye password-toggle" id="password-toggle"></i>
                        </div>
                    </div>
                    
                    <div class="form-options">
                        <div class="remember-me">
                            <input type="checkbox" id="remember" name="remember">
                            <label for="remember">Se souvenir de moi</label>
                        </div>
                        <a href="#" class="forgot-password" id="forgot-password-link">Mot de passe oublié ?</a>
                    </div>
                    
                    <button type="submit" class="btn" id="login-btn">
                        <span class="btn-text">Se connecter</span>
                    </button>
                    
                    <div class="biometric-option" id="biometric-login">
                        <i class="fas fa-fingerprint"></i>
                        <span>Se connecter avec l'empreinte digitale</span>
                    </div>
                    
                    <div class="divider">Ou continuer avec</div>
                    
                    <div class="social-login">
                        <button type="button" class="social-btn google">
                            <i class="fab fa-google"></i>
                        </button>
                        <button type="button" class="social-btn facebook">
                            <i class="fab fa-facebook-f"></i>
                        </button>
                        <button type="button" class="social-btn apple">
                            <i class="fab fa-apple"></i>
                        </button>
                    </div>
                    
                    <div class="security-indicator">
                        <i class="fas fa-shield-check"></i>
                        <span>Connexion sécurisée avec chiffrement de bout en bout</span>
                    </div>
                    
                    <div class="form-footer">
                        Pas encore de compte ? <a href="register.php">Créer un compte</a>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal de réinitialisation de mot de passe -->
    <div class="modal" id="reset-modal">
        <div class="modal-content">
            <button class="modal-close" id="modal-close">&times;</button>
            <h2 class="modal-title">Réinitialiser le mot de passe</h2>
            <p class="modal-text">
                Entrez votre adresse email et nous vous enverrons un lien pour réinitialiser votre mot de passe.
            </p>
            
            <form method="POST" id="reset-form">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <input type="hidden" name="reset_password" value="1">
                
                <div class="form-group">
                    <label for="reset_email">Adresse email</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="reset_email" name="reset_email" placeholder="votre@email.com" required>
                    </div>
                </div>
                
                <button type="submit" class="btn" id="reset-btn">
                    <span class="btn-text">Envoyer le lien de réinitialisation</span>
                </button>
            </form>
        </div>
    </div>

    <script src="js/login.js"></script>
</body>
</html>