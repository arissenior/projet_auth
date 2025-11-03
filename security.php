<?php
// security.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$userId = $_SESSION['user_id'];
$csrfToken = Security::generateCSRFToken();

// Récupération des données de sécurité
try {
    $db = Database::getConnection();
    
    // Paramètres de sécurité
    $stmt = $db->prepare("SELECT * FROM security_settings WHERE user_id = ?");
    $stmt->execute([$userId]);
    $securitySettings = $stmt->fetch() ?: [];
    
    // Logs de sécurité récents
    $stmt = $db->prepare("
        SELECT event_type, severity, description, ip_address, created_at 
        FROM security_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    ");
    $stmt->execute([$userId]);
    $securityLogs = $stmt->fetchAll();
    
    // Sessions actives
    $stmt = $db->prepare("
        SELECT id, ip_address, user_agent, device_info, created_at 
        FROM user_sessions 
        WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC
    ");
    $stmt->execute([$userId]);
    $activeSessions = $stmt->fetchAll();
    
    // Tentatives de connexion échouées
    $stmt = $db->prepare("
        SELECT created_at, ip_address, user_agent 
        FROM user_activities 
        WHERE user_id = ? AND activity_type = 'login_failed' 
        ORDER BY created_at DESC 
        LIMIT 10
    ");
    $stmt->execute([$userId]);
    $failedLogins = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Security data error: " . $e->getMessage());
    $securitySettings = [];
    $securityLogs = [];
    $activeSessions = [];
    $failedLogins = [];
}

// Traitement des formulaires
if ($_POST) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        if (isset($_POST['update_security_settings'])) {
            $twoFactorEnabled = isset($_POST['two_factor_enabled']) ? 1 : 0;
            $loginNotifications = isset($_POST['login_notifications']) ? 1 : 0;
            $suspiciousActivityAlerts = isset($_POST['suspicious_activity_alerts']) ? 1 : 0;
            
            if (empty($securitySettings)) {
                $stmt = $db->prepare("
                    INSERT INTO security_settings (user_id, two_factor_enabled, login_notifications, suspicious_activity_alerts) 
                    VALUES (?, ?, ?, ?)
                ");
                $stmt->execute([$userId, $twoFactorEnabled, $loginNotifications, $suspiciousActivityAlerts]);
            } else {
                $stmt = $db->prepare("
                    UPDATE security_settings 
                    SET two_factor_enabled = ?, login_notifications = ?, suspicious_activity_alerts = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE user_id = ?
                ");
                $stmt->execute([$twoFactorEnabled, $loginNotifications, $suspiciousActivityAlerts, $userId]);
            }
            
            Auth::logActivity($userId, 'security_update', 'Security settings updated');
            $success = "Paramètres de sécurité mis à jour avec succès!";
            $stmt = $db->prepare("SELECT * FROM security_settings WHERE user_id = ?");
            $stmt->execute([$userId]);
            $securitySettings = $stmt->fetch();
        }
        
        if (isset($_POST['change_password'])) {
            $currentPassword = $_POST['current_password'];
            $newPassword = $_POST['new_password'];
            $confirmPassword = $_POST['confirm_password'];
            
            // Vérifier le mot de passe actuel
            if (!Security::passwordVerify($currentPassword, $user['password'])) {
                throw new Exception("Le mot de passe actuel est incorrect.");
            }
            
            // Valider le nouveau mot de passe
            $passwordErrors = Security::validatePasswordStrength($newPassword);
            if (!empty($passwordErrors)) {
                throw new Exception(implode(" ", $passwordErrors));
            }
            
            if ($newPassword !== $confirmPassword) {
                throw new Exception("Les nouveaux mots de passe ne correspondent pas.");
            }
            
            // Mettre à jour le mot de passe
            $newPasswordHash = Security::passwordHash($newPassword);
            $stmt = $db->prepare("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$newPasswordHash, $userId]);
            
            Auth::logActivity($userId, 'password_change', 'Password changed successfully');
            $success = "Mot de passe modifié avec succès!";
        }
        
        if (isset($_POST['terminate_session'])) {
            $sessionId = Security::sanitizeInput($_POST['session_id']);
            $stmt = $db->prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?");
            Auth::logActivity($userId, 'session_terminated', 'Session terminated manually');
            $success = "Session terminée avec succès!";
            $stmt = $db->prepare("SELECT * FROM user_sessions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP");
            $stmt->execute([$userId]);
            $activeSessions = $stmt->fetchAll();
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Log de l'accès à la sécurité
Auth::logActivity($userId, 'security_access', 'Viewed security page');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sécurité | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="css/security.css">
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
                <a href="security.php" class="nav-item active">
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
                <a href="settings.php" class="nav-item">
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
                <h1>Sécurité du compte</h1>
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
            
            <!-- Statut de sécurité -->
            <div class="security-status">
                <div class="status-card">
                    <div class="status-icon <?= $securitySettings['two_factor_enabled'] ? 'enabled' : 'disabled' ?>">
                        <i class="fas fa-mobile-alt"></i>
                    </div>
                    <div class="status-title">
                        <?= $securitySettings['two_factor_enabled'] ? 'Activée' : 'Désactivée' ?>
                    </div>
                    <div class="status-description">Authentification à deux facteurs</div>
                </div>
                
                <div class="status-card">
                    <div class="status-icon enabled">
                        <i class="fas fa-shield-check"></i>
                    </div>
                    <div class="status-title">Sécurisé</div>
                    <div class="status-description">Mot de passe fort</div>
                </div>
                
                <div class="status-card">
                    <div class="status-icon enabled">
                        <i class="fas fa-bell"></i>
                    </div>
                    <div class="status-title">Actives</div>
                    <div class="status-description">Notifications de sécurité</div>
                </div>
                
                <div class="status-card">
                    <div class="status-card">
                        <div class="status-icon <?= count($activeSessions) > 0 ? 'enabled' : 'disabled' ?>">
                            <i class="fas fa-laptop"></i>
                        </div>
                        <div class="status-title"><?= count($activeSessions) ?></div>
                        <div class="status-description">Sessions actives</div>
                    </div>
                </div>
            </div>
            
            <!-- Paramètres de sécurité -->
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Paramètres de sécurité</h2>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="update_security_settings" value="1">
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="two_factor_enabled" name="two_factor_enabled" value="1" 
                               <?= $securitySettings['two_factor_enabled'] ? 'checked' : '' ?>>
                        <label for="two_factor_enabled">Authentification à deux facteurs (2FA)</label>
                    </div>
                    <p style="color: var(--gray); font-size: 0.9rem; margin-left: 28px; margin-bottom: 15px;">
                        Ajoutez une couche de sécurité supplémentaire à votre compte en exigeant un code de vérification lors de la connexion.
                    </p>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="login_notifications" name="login_notifications" value="1" 
                               <?= $securitySettings['login_notifications'] ?? true ? 'checked' : '' ?>>
                        <label for="login_notifications">Notifications de connexion</label>
                    </div>
                    <p style="color: var(--gray); font-size: 0.9rem; margin-left: 28px; margin-bottom: 15px;">
                        Recevez une notification par email lors d'une nouvelle connexion à votre compte.
                    </p>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="suspicious_activity_alerts" name="suspicious_activity_alerts" value="1" 
                               <?= $securitySettings['suspicious_activity_alerts'] ?? true ? 'checked' : '' ?>>
                        <label for="suspicious_activity_alerts">Alertes d'activité suspecte</label>
                    </div>
                    <p style="color: var(--gray); font-size: 0.9rem; margin-left: 28px; margin-bottom: 20px;">
                        Soyez alerté en cas d'activité inhabituelle sur votre compte.
                    </p>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Enregistrer les paramètres
                    </button>
                </form>
            </div>
            
            <!-- Changer le mot de passe -->
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Changer le mot de passe</h2>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="change_password" value="1">
                    
                    <div class="form-group">
                        <label for="current_password">Mot de passe actuel</label>
                        <input type="password" id="current_password" name="current_password" class="form-control" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="new_password">Nouveau mot de passe</label>
                        <input type="password" id="new_password" name="new_password" class="form-control" required 
                               oninput="checkPasswordStrength(this.value)">
                        <div class="password-strength">
                            <div class="password-strength-bar" id="password-strength-bar"></div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password">Confirmer le nouveau mot de passe</label>
                        <input type="password" id="confirm_password" name="confirm_password" class="form-control" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-key"></i> Changer le mot de passe
                    </button>
                </form>
            </div>
            
            <!-- Sessions actives -->
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Sessions actives</h2>
                </div>
                <?php if (empty($activeSessions)): ?>
                    <p style="color: var(--gray); text-align: center; padding: 40px;">
                        <i class="fas fa-laptop" style="font-size: 3rem; margin-bottom: 15px; display: block; opacity: 0.5;"></i>
                        Aucune session active
                    </p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="security-table">
                            <thead>
                                <tr>
                                    <th>Appareil</th>
                                    <th>Adresse IP</th>
                                    <th>Début de session</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($activeSessions as $session): ?>
                                    <tr>
                                        <td>
                                            <div class="device-info">
                                                <i class="fas fa-laptop"></i>
                                                <?= htmlspecialchars(getDeviceInfo($session['user_agent'])) ?>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="ip-address"><?= htmlspecialchars($session['ip_address']) ?></span>
                                        </td>
                                        <td><?= date('d/m/Y H:i', strtotime($session['created_at'])) ?></td>
                                        <td>
                                            <form method="POST" style="display: inline;">
                                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                                <input type="hidden" name="session_id" value="<?= $session['id'] ?>">
                                                <input type="hidden" name="terminate_session" value="1">
                                                <button type="submit" class="btn btn-danger" style="padding: 8px 16px;">
                                                    <i class="fas fa-times"></i> Terminer
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Tentatives de connexion échouées -->
            <?php if (!empty($failedLogins)): ?>
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Tentatives de connexion échouées</h2>
                </div>
                <div class="table-responsive">
                    <table class="security-table">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Adresse IP</th>
                                <th>Appareil</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($failedLogins as $attempt): ?>
                                <tr>
                                    <td><?= date('d/m/Y H:i', strtotime($attempt['created_at'])) ?></td>
                                    <td>
                                        <span class="ip-address"><?= htmlspecialchars($attempt['ip_address']) ?></span>
                                    </td>
                                    <td>
                                        <div class="device-info">
                                            <?= htmlspecialchars(getDeviceInfo($attempt['user_agent'])) ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <script src="js/security.js"></script>
</body>
</html>

<?php
// Helper functions
function getDeviceInfo($userAgent) {
    if (strpos($userAgent, 'Mobile') !== false) {
        return 'Appareil mobile';
    } elseif (strpos($userAgent, 'Tablet') !== false) {
        return 'Tablette';
    } elseif (strpos($userAgent, 'Windows') !== false) {
        return 'Windows';
    } elseif (strpos($userAgent, 'Mac') !== false) {
        return 'Mac';
    } elseif (strpos($userAgent, 'Linux') !== false) {
        return 'Linux';
    } else {
        return 'Appareil inconnu';
    }
}
?>