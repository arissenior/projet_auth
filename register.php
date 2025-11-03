<?php
// register.php
require_once 'config.php';
Auth::requireGuest();

$csrfToken = Security::generateCSRFToken();
$error = '';
$success = '';

// Traitement du formulaire d'inscription
if ($_POST && isset($_POST['register'])) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        $username = Security::sanitizeInput($_POST['username']);
        $email = Security::sanitizeInput($_POST['email']);
        $password = $_POST['password'];
        $confirmPassword = $_POST['confirm_password'];
        $firstName = Security::sanitizeInput($_POST['first_name']);
        $lastName = Security::sanitizeInput($_POST['last_name']);
        $terms = isset($_POST['terms']) ? true : false;
        $newsletter = isset($_POST['newsletter']) ? true : false;
        
        // Validation des champs
        if (empty($username) || empty($email) || empty($password) || empty($confirmPassword)) {
            throw new Exception("Veuillez remplir tous les champs obligatoires.");
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("L'adresse email n'est pas valide.");
        }
        
        if ($password !== $confirmPassword) {
            throw new Exception("Les mots de passe ne correspondent pas.");
        }
        
        if (!$terms) {
            throw new Exception("Vous devez accepter les conditions d'utilisation.");
        }
        
        // Validation de la force du mot de passe
        $passwordErrors = Security::validatePasswordStrength($password);
        if (!empty($passwordErrors)) {
            throw new Exception(implode(" ", $passwordErrors));
        }
        
        // Vérifier si l'utilisateur existe déjà
        $db = Database::getConnection();
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? OR username = ?");
        $stmt->execute([$email, $username]);
        
        if ($stmt->fetch()) {
            throw new Exception("Un compte avec cet email ou nom d'utilisateur existe déjà.");
        }
        
        // Créer l'utilisateur
        $passwordHash = Security::passwordHash($password);
        $verificationToken = Security::generateRandomString(32);
        
        $stmt = $db->prepare("
            INSERT INTO users (username, email, password, first_name, last_name, verification_token) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([$username, $email, $passwordHash, $firstName, $lastName, $verificationToken]);
        
        $userId = $db->lastInsertId();
        
        // Créer les paramètres de sécurité par défaut
        $stmt = $db->prepare("
            INSERT INTO security_settings (user_id) 
            VALUES (?)
        ");
        $stmt->execute([$userId]);
        
        // Créer les préférences utilisateur
        $stmt = $db->prepare("
            INSERT INTO user_preferences (user_id, newsletter) 
            VALUES (?, ?)
        ");
        $stmt->execute([$userId, $newsletter ? 1 : 0]);
        
        // Journaliser l'activité
        Auth::logActivity($userId, 'registration', 'User registered successfully', $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
        
        // Ici, vous enverriez un email de vérification
        // Pour l'instant, nous connectons directement l'utilisateur
        
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['email'] = $email;
        
        // Redirection vers le dashboard
        header('Location: dashboard.php');
        exit;
        
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
    <title>Inscription | SecureAuth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/register.css">
</head>
<body>
    <!-- Animation de fond -->
    <div class="background-animation" id="background-animation"></div>
    
    <div class="register-container">
        <div class="welcome-section">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <span>SecureAuth</span>
            </div>
            
            <div class="welcome-content">
                <h1 class="welcome-title">Rejoignez-nous !</h1>
                <p class="welcome-subtitle">
                    Créez votre compte SecureAuth et profitez d'une sécurité de niveau 
                    enterprise pour protéger votre identité numérique.
                </p>
                
                <div class="features">
                    <div class="feature">
                        <i class="fas fa-shield-check"></i>
                        <div class="feature-text">
                            <h3>Sécurité Maximale</h3>
                            <p>Protection avancée avec chiffrement de bout en bout</p>
                        </div>
                    </div>
                    <div class="feature">
                        <i class="fas fa-rocket"></i>
                        <div class="feature-text">
                            <h3>Configuration Rapide</h3>
                            <p>Créez votre compte en moins de 2 minutes</p>
                        </div>
                    </div>
                    <div class="feature">
                        <i class="fas fa-gift"></i>
                        <div class="feature-text">
                            <h3>Essai Gratuit</h3>
                            <p>30 jours d'essai gratuit sans engagement</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="form-section">
            <div class="form-container">
                <div class="form-header">
                    <h1>Créer un compte</h1>
                    <p>Rejoignez notre communauté sécurisée</p>
                </div>
                
                <!-- Messages d'alerte -->
                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= $error ?></span>
                    </div>
                <?php endif; ?>
                
                <!-- Étapes de progression -->
                <div class="progress-steps">
                    <div class="progress-step active" id="step-1">
                        1
                        <div class="step-label">Compte</div>
                    </div>
                    <div class="progress-step" id="step-2">
                        2
                        <div class="step-label">Sécurité</div>
                    </div>
                    <div class="progress-step" id="step-3">
                        3
                        <div class="step-label">Confirmation</div>
                    </div>
                </div>
                
                <!-- Formulaire d'inscription en plusieurs étapes -->
                <form method="POST" id="register-form">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="register" value="1">
                    
                    <!-- Étape 1: Informations de compte -->
                    <div class="form-step active" id="form-step-1">
                        <div class="form-group">
                            <label for="username">Nom d'utilisateur *</label>
                            <div class="input-with-icon">
                                <i class="fas fa-user"></i>
                                <input type="text" id="username" name="username" placeholder="Choisissez un nom d'utilisateur" required 
                                       value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : '' ?>">
                            </div>
                            <div class="form-text" style="font-size: 0.8rem; color: var(--gray); margin-top: 5px;">
                                Entre 3 et 20 caractères, lettres, chiffres et underscores uniquement.
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="email">Adresse email *</label>
                            <div class="input-with-icon">
                                <i class="fas fa-envelope"></i>
                                <input type="email" id="email" name="email" placeholder="votre@email.com" required 
                                       value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="first_name">Prénom</label>
                            <div class="input-with-icon">
                                <i class="fas fa-user-circle"></i>
                                <input type="text" id="first_name" name="first_name" placeholder="Votre prénom" 
                                       value="<?= isset($_POST['first_name']) ? htmlspecialchars($_POST['first_name']) : '' ?>">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="last_name">Nom</label>
                            <div class="input-with-icon">
                                <i class="fas fa-user-circle"></i>
                                <input type="text" id="last_name" name="last_name" placeholder="Votre nom" 
                                       value="<?= isset($_POST['last_name']) ? htmlspecialchars($_POST['last_name']) : '' ?>">
                            </div>
                        </div>
                        
                        <button type="button" class="btn" id="next-step-1">
                            Continuer
                            <i class="fas fa-arrow-right"></i>
                        </button>
                    </div>
                    
                    <!-- Étape 2: Sécurité -->
                    <div class="form-step" id="form-step-2">
                        <div class="form-group">
                            <label for="password">Mot de passe *</label>
                            <div class="input-with-icon">
                                <i class="fas fa-lock"></i>
                                <input type="password" id="password" name="password" placeholder="Créez un mot de passe sécurisé" required>
                                <i class="fas fa-eye password-toggle" id="password-toggle"></i>
                            </div>
                            <div class="password-strength">
                                <div class="password-strength-bar" id="password-strength-bar"></div>
                            </div>
                            <div class="password-requirements" id="password-requirements">
                                <div class="requirement unmet" id="req-length">
                                    <i class="fas fa-circle"></i>
                                    <span>Au moins 8 caractères</span>
                                </div>
                                <div class="requirement unmet" id="req-uppercase">
                                    <i class="fas fa-circle"></i>
                                    <span>Une lettre majuscule</span>
                                </div>
                                <div class="requirement unmet" id="req-lowercase">
                                    <i class="fas fa-circle"></i>
                                    <span>Une lettre minuscule</span>
                                </div>
                                <div class="requirement unmet" id="req-number">
                                    <i class="fas fa-circle"></i>
                                    <span>Un chiffre</span>
                                </div>
                                <div class="requirement unmet" id="req-special">
                                    <i class="fas fa-circle"></i>
                                    <span>Un caractère spécial</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="confirm_password">Confirmer le mot de passe *</label>
                            <div class="input-with-icon">
                                <i class="fas fa-lock"></i>
                                <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirmez votre mot de passe" required>
                                <i class="fas fa-eye password-toggle" id="confirm-password-toggle"></i>
                            </div>
                            <div id="password-match" style="font-size: 0.8rem; margin-top: 5px;"></div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="button" class="btn btn-outline" id="prev-step-2">
                                <i class="fas fa-arrow-left"></i>
                                Retour
                            </button>
                            <button type="button" class="btn" id="next-step-2">
                                Continuer
                                <i class="fas fa-arrow-right"></i>
                            </button>
                        </div>
                    </div>
                    
                    <!-- Étape 3: Confirmation -->
                    <div class="form-step" id="form-step-3">
                        <div class="checkbox-group">
                            <input type="checkbox" id="terms" name="terms" required>
                            <label for="terms">
                                J'accepte les <a href="#" target="_blank">conditions d'utilisation</a> 
                                et la <a href="#" target="_blank">politique de confidentialité</a> *
                            </label>
                        </div>
                        
                        <div class="checkbox-group">
                            <input type="checkbox" id="newsletter" name="newsletter">
                            <label for="newsletter">
                                Je souhaite recevoir des actualités, des offres exclusives et des conseils de sécurité par email
                            </label>
                        </div>
                        
                        <div class="security-indicator">
                            <i class="fas fa-shield-check"></i>
                            <span>Vos données sont sécurisées avec un chiffrement de niveau militaire</span>
                        </div>
                        
                        <div class="form-actions">
                            <button type="button" class="btn btn-outline" id="prev-step-3">
                                <i class="fas fa-arrow-left"></i>
                                Retour
                            </button>
                            <button type="submit" class="btn" id="register-btn">
                                <span class="btn-text">Créer mon compte</span>
                            </button>
                        </div>
                    </div>
                </form>
                
                <div class="form-footer">
                    Déjà un compte ? <a href="login.php">Se connecter</a>
                </div>
            </div>
        </div>
    </div>
<script src="js/register.js"></script>
</body>
</html>