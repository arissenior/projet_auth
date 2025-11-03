<?php
// settings.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$userId = $_SESSION['user_id'];
$csrfToken = Security::generateCSRFToken();

// Récupération des paramètres
try {
    $db = Database::getConnection();
    
    // Paramètres de sécurité
    $stmt = $db->prepare("SELECT * FROM security_settings WHERE user_id = ?");
    $stmt->execute([$userId]);
    $securitySettings = $stmt->fetch() ?: [];
    
    // Préférences utilisateur
    $stmt = $db->prepare("SELECT * FROM user_preferences WHERE user_id = ?");
    $stmt->execute([$userId]);
    $userPreferences = $stmt->fetch() ?: [];
    
} catch (PDOException $e) {
    error_log("Settings data error: " . $e->getMessage());
    $securitySettings = [];
    $userPreferences = [];
}

// Traitement des formulaires
if ($_POST) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        if (isset($_POST['update_preferences'])) {
            $theme = Security::sanitizeInput($_POST['theme']);
            $language = Security::sanitizeInput($_POST['language']);
            $notifications = isset($_POST['notifications']) ? 1 : 0;
            $newsletter = isset($_POST['newsletter']) ? 1 : 0;
            
            if (empty($userPreferences)) {
                $stmt = $db->prepare("
                    INSERT INTO user_preferences (user_id, theme, language, notifications, newsletter) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$userId, $theme, $language, $notifications, $newsletter]);
            } else {
                $stmt = $db->prepare("
                    UPDATE user_preferences 
                    SET theme = ?, language = ?, notifications = ?, newsletter = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE user_id = ?
                ");
                $stmt->execute([$theme, $language, $notifications, $newsletter, $userId]);
            }
            
            Auth::logActivity($userId, 'preferences_updated', 'User preferences updated');
            $success = "Préférences mises à jour avec succès!";
        }
        
        if (isset($_POST['update_privacy'])) {
            $dataSharing = isset($_POST['data_sharing']) ? 1 : 0;
            $analytics = isset($_POST['analytics']) ? 1 : 0;
            $profileVisibility = Security::sanitizeInput($_POST['profile_visibility']);
            
            $stmt = $db->prepare("
                UPDATE user_preferences 
                SET data_sharing = ?, analytics = ?, profile_visibility = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE user_id = ?
            ");
            $stmt->execute([$dataSharing, $analytics, $profileVisibility, $userId]);
            
            Auth::logActivity($userId, 'privacy_updated', 'Privacy settings updated');
            $success = "Paramètres de confidentialité mis à jour avec succès!";
        }
        
        if (isset($_POST['export_data'])) {
            // Simulation d'export de données
            Auth::logActivity($userId, 'data_export', 'Data export requested');
            $success = "Votre demande d'export de données a été reçue. Vous recevrez un email avec vos données sous 24 heures.";
        }
        
        if (isset($_POST['delete_account'])) {
            $confirmText = Security::sanitizeInput($_POST['confirm_text']);
            
            if ($confirmText !== 'SUPPRIMER MON COMPTE') {
                throw new Exception("Veuillez taper 'SUPPRIMER MON COMPTE' pour confirmer la suppression.");
            }
            
            Auth::logActivity($userId, 'account_deletion_requested', 'Account deletion requested');
            $warning = "Demande de suppression de compte enregistrée. Un email de confirmation vous a été envoyé.";
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Log de l'accès aux paramètres
Auth::logActivity($userId, 'settings_access', 'Viewed settings page');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paramètres | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="css/setting.css">
</head>
<body>
    <div class="dashboard-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <span><?= Config::APP_NAME ?></span>
            </div>
            
            <div class="user-profile">
                <img src="<?= htmlspecialchars($user['avatar_url'] ?? 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&h=150&fit=crop&crop=face') ?>" 
                     alt="Avatar" class="user-avatar">
                <div class="user-info">
                    <h3><?= htmlspecialchars($user['first_name'] . ' ' . $user['last_name']) ?></h3>
                    <p>@<?= htmlspecialchars($user['username']) ?></p>
                </div>
            </div>
            
            <nav class="nav-menu">
                <a href="dashboard.php" class="nav-item">
                    <i class="fas fa-home"></i>
                    <span>Tableau de bord</span>
                </a>
                <a href="profile.php" class="nav-item">
                    <i class="fas fa-user"></i>
                    <span>Mon profil</span>
                </a>
                <a href="security.php" class="nav-item">
                    <i class="fas fa-shield-alt"></i>
                    <span>Sécurité</span>
                </a>
                <a href="sessions.php" class="nav-item">
                    <i class="fas fa-laptop"></i>
                    <span>Sessions actives</span>
                </a>
                <a href="activities.php" class="nav-item">
                    <i class="fas fa-history"></i>
                    <span>Activités</span>
                </a>
                <a href="settings.php" class="nav-item active">
                    <i class="fas fa-cog"></i>
                    <span>Paramètres</span>
                </a>
                <a href="logout.php" class="nav-item">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Déconnexion</span>
                </a>
            </nav>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="header">
                <h1>Paramètres</h1>
                <div class="header-actions">
                    <a href="dashboard.php" class="btn btn-outline">
                        <i class="fas fa-arrow-left"></i>
                        Retour
                    </a>
                </div>
            </div>
            
            <!-- Alertes -->
            <?php if (isset($success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> <?= $success ?>
                </div>
            <?php endif; ?>
            
            <?php if (isset($error)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i> <?= $error ?>
                </div>
            <?php endif; ?>
            
            <?php if (isset($warning)): ?>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i> <?= $warning ?>
                </div>
            <?php endif; ?>
            
            <!-- Vue d'ensemble des paramètres -->
            <div class="settings-grid">
                <div class="setting-card">
                    <div class="setting-icon">
                        <i class="fas fa-palette"></i>
                    </div>
                    <div class="setting-title">Apparence</div>
                    <div class="setting-description">
                        Personnalisez l'apparence de votre interface utilisateur selon vos préférences.
                    </div>
                    <a href="#appearance" class="btn btn-outline" style="width: 100%; justify-content: center;">
                        Configurer
                    </a>
                </div>
                
                <div class="setting-card">
                    <div class="setting-icon">
                        <i class="fas fa-bell"></i>
                    </div>
                    <div class="setting-title">Notifications</div>
                    <div class="setting-description">
                        Gérez les notifications que vous recevez par email et dans l'application.
                    </div>
                    <a href="#notifications" class="btn btn-outline" style="width: 100%; justify-content: center;">
                        Configurer
                    </a>
                </div>
                
                <div class="setting-card">
                    <div class="setting-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="setting-title">Confidentialité</div>
                    <div class="setting-description">
                        Contrôlez comment vos données sont utilisées et partagées.
                    </div>
                    <a href="#privacy" class="btn btn-outline" style="width: 100%; justify-content: center;">
                        Configurer
                    </a>
                </div>
                
                <div class="setting-card">
                    <div class="setting-icon">
                        <i class="fas fa-download"></i>
                    </div>
                    <div class="setting-title">Données</div>
                    <div class="setting-description">
                        Exportez vos données ou gérez votre compte.
                    </div>
                    <a href="#data" class="btn btn-outline" style="width: 100%; justify-content: center;">
                        Gérer
                    </a>
                </div>
            </div>
            
            <!-- Apparence -->
            <div class="section" id="appearance">
                <div class="section-header">
                    <h2 class="section-title">Apparence</h2>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="update_preferences" value="1">
                    
                    <div class="form-group">
                        <label for="theme">Thème</label>
                        <select id="theme" name="theme" class="form-control">
                            <option value="auto" <?= ($userPreferences['theme'] ?? 'auto') === 'auto' ? 'selected' : '' ?>>Automatique (selon le système)</option>
                            <option value="light" <?= ($userPreferences['theme'] ?? '') === 'light' ? 'selected' : '' ?>>Clair</option>
                            <option value="dark" <?= ($userPreferences['theme'] ?? '') === 'dark' ? 'selected' : '' ?>>Sombre</option>
                        </select>
                        <div class="form-text">Choisissez le thème d'affichage de l'application.</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="language">Langue</label>
                        <select id="language" name="language" class="form-control">
                            <option value="fr" <?= ($userPreferences['language'] ?? 'fr') === 'fr' ? 'selected' : '' ?>>Français</option>
                            <option value="en" <?= ($userPreferences['language'] ?? '') === 'en' ? 'selected' : '' ?>>English</option>
                            <option value="es" <?= ($userPreferences['language'] ?? '') === 'es' ? 'selected' : '' ?>>Español</option>
                        </select>
                        <div class="form-text">Sélectionnez votre langue préférée.</div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Enregistrer les préférences
                    </button>
                </form>
            </div>
            
            <!-- Notifications -->
            <div class="section" id="notifications">
                <div class="section-header">
                    <h2 class="section-title">Notifications</h2>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="update_preferences" value="1">
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="notifications" name="notifications" value="1" 
                               <?= ($userPreferences['notifications'] ?? true) ? 'checked' : '' ?>>
                        <label for="notifications">Notifications par email</label>
                    </div>
                    <div class="form-text">Recevez des notifications importantes par email.</div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="newsletter" name="newsletter" value="1" 
                               <?= ($userPreferences['newsletter'] ?? false) ? 'checked' : '' ?>>
                        <label for="newsletter">Newsletter</label>
                    </div>
                    <div class="form-text">Recevez notre newsletter avec les dernières nouveautés et conseils.</div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Enregistrer les préférences
                    </button>
                </form>
            </div>
            
            <!-- Confidentialité -->
            <div class="section" id="privacy">
                <div class="section-header">
                    <h2 class="section-title">Confidentialité</h2>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="update_privacy" value="1">
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="data_sharing" name="data_sharing" value="1" 
                               <?= ($userPreferences['data_sharing'] ?? false) ? 'checked' : '' ?>>
                        <label for="data_sharing">Partage de données anonymisées</label>
                    </div>
                    <div class="form-text">Autorisez-nous à utiliser des données anonymisées pour améliorer nos services.</div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="analytics" name="analytics" value="1" 
                               <?= ($userPreferences['analytics'] ?? true) ? 'checked' : '' ?>>
                        <label for="analytics">Analytics et statistiques</label>
                    </div>
                    <div class="form-text">Autorisez le suivi analytique pour améliorer votre expérience.</div>
                    
                    <div class="form-group">
                        <label for="profile_visibility">Visibilité du profil</label>
                        <select id="profile_visibility" name="profile_visibility" class="form-control">
                            <option value="public" <?= ($userPreferences['profile_visibility'] ?? 'private') === 'public' ? 'selected' : '' ?>>Public</option>
                            <option value="private" <?= ($userPreferences['profile_visibility'] ?? 'private') === 'private' ? 'selected' : '' ?>>Privé</option>
                            <option value="friends" <?= ($userPreferences['profile_visibility'] ?? '') === 'friends' ? 'selected' : '' ?>>Amis uniquement</option>
                        </select>
                        <div class="form-text">Contrôlez qui peut voir votre profil.</div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Enregistrer les paramètres
                    </button>
                </form>
            </div>
            
            <!-- Données et compte -->
            <div class="section" id="data">
                <div class="section-header">
                    <h2 class="section-title">Données et compte</h2>
                </div>
                
                <div class="form-group">
                    <label>Export de données</label>
                    <p class="form-text">
                        Téléchargez une copie de toutes vos données personnelles stockées sur notre plateforme.
                    </p>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="export_data" value="1">
                        <button type="submit" class="btn btn-outline">
                            <i class="fas fa-download"></i> Exporter mes données
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Zone de danger -->
            <div class="section danger-zone">
                <div class="section-header">
                    <h2 class="section-title">Zone de danger</h2>
                </div>
                
                <div class="form-group">
                    <label>Supprimer le compte</label>
                    <p class="form-text" style="color: var(--error);">
                        Attention : Cette action est irréversible. Toutes vos données seront définitivement supprimées et ne pourront pas être récupérées.
                    </p>
                    
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="delete_account" value="1">
                        
                        <div class="form-group">
                            <label for="confirm_text">
                                Tapez <span class="confirmation-text">SUPPRIMER MON COMPTE</span> pour confirmer
                            </label>
                            <input type="text" id="confirm_text" name="confirm_text" class="form-control" 
                                   placeholder="SUPPRIMER MON COMPTE" required>
                        </div>
                        
                        <div class="danger-actions">
                            <button type="submit" class="btn btn-danger" 
                                    onclick="return confirm('Êtes-vous ABSOLUMENT SÛR de vouloir supprimer votre compte ? Cette action est irréversible.')">
                                <i class="fas fa-trash"></i> Supprimer définitivement mon compte
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Validation pour la suppression de compte
        document.getElementById('confirm_text').addEventListener('input', function() {
            const deleteBtn = document.querySelector('button[type="submit"]');
            if (this.value === 'SUPPRIMER MON COMPTE') {
                deleteBtn.disabled = false;
            } else {
                deleteBtn.disabled = true;
            }
        });
        
        // Navigation fluide vers les ancres
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>
</html>