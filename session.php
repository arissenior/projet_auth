<?php
// sessions.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$userId = $_SESSION['user_id'];
$csrfToken = Security::generateCSRFToken();

// Récupération des sessions
try {
    $db = Database::getConnection();
    
    // Sessions actives
    $stmt = $db->prepare("
        SELECT id, session_token, ip_address, user_agent, device_info, created_at, expires_at 
        FROM user_sessions 
        WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC
    ");
    $stmt->execute([$userId]);
    $activeSessions = $stmt->fetchAll();
    
    // Sessions récentes (30 derniers jours)
    $stmt = $db->prepare("
        SELECT id, session_token, ip_address, user_agent, device_info, created_at, expires_at 
        FROM user_sessions 
        WHERE user_id = ? AND created_at >= CURRENT_DATE - INTERVAL '30 days'
        ORDER BY created_at DESC
    ");
    $stmt->execute([$userId]);
    $recentSessions = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Sessions data error: " . $e->getMessage());
    $activeSessions = [];
    $recentSessions = [];
}

// Traitement des actions
if ($_POST) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        if (isset($_POST['terminate_session'])) {
            $sessionId = Security::sanitizeInput($_POST['session_id']);
            $stmt = $db->prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?");
            $stmt->execute([$sessionId, $userId]);
            
            Auth::logActivity($userId, 'session_terminated', 'Session terminated manually');
            $success = "Session terminée avec succès!";
            
            // Recharger les sessions
            $stmt = $db->prepare("
                SELECT id, session_token, ip_address, user_agent, device_info, created_at, expires_at 
                FROM user_sessions 
                WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
                ORDER BY created_at DESC
            ");
            $stmt->execute([$userId]);
            $activeSessions = $stmt->fetchAll();
        }
        
        if (isset($_POST['terminate_all_sessions'])) {
            $stmt = $db->prepare("DELETE FROM user_sessions WHERE user_id = ? AND id != ?");
            $currentSessionId = $_SESSION['session_id'] ?? '';
            $stmt->execute([$userId, $currentSessionId]);
            
            Auth::logActivity($userId, 'all_sessions_terminated', 'All other sessions terminated');
            $success = "Toutes les autres sessions ont été terminées!";
            
            // Recharger les sessions
            $stmt = $db->prepare("
                SELECT id, session_token, ip_address, user_agent, device_info, created_at, expires_at 
                FROM user_sessions 
                WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
                ORDER BY created_at DESC
            ");
            $stmt->execute([$userId]);
            $activeSessions = $stmt->fetchAll();
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Log de l'accès aux sessions
Auth::logActivity($userId, 'sessions_access', 'Viewed sessions page');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sessions actives | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="">
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
                <a href="sessions.php" class="nav-item active">
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
                <h1>Sessions actives</h1>
                <div class="header-actions">
                    <a href="dashboard.php" class="btn btn-outline">
                        <i class="fas fa-arrow-left"></i>
                        Retour
                    </a>
                    <?php if (count($activeSessions) > 1): ?>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <input type="hidden" name="terminate_all_sessions" value="1">
                        <button type="submit" class="btn btn-danger" 
                                onclick="return confirm('Êtes-vous sûr de vouloir terminer toutes les autres sessions ?')">
                            <i class="fas fa-sign-out-alt"></i>
                            Terminer toutes les autres sessions
                        </button>
                    </form>
                    <?php endif; ?>
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
            
            <!-- Statistiques -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value"><?= count($activeSessions) ?></div>
                    <div class="stat-label">Sessions actives</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?= count($recentSessions) ?></div>
                    <div class="stat-label">Sessions (30 jours)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?= count(array_unique(array_column($activeSessions, 'ip_address'))) ?></div>
                    <div class="stat-label">Appareils uniques</div>
                </div>
            </div>
            
            <!-- Sessions actives -->
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Sessions actuellement actives</h2>
                </div>
                
                <?php if (empty($activeSessions)): ?>
                    <div class="empty-state">
                        <i class="fas fa-laptop"></i>
                        <h3>Aucune session active</h3>
                        <p>Vous n'avez actuellement aucune session active.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($activeSessions as $session): ?>
                        <div class="session-card <?= $session['id'] === ($_SESSION['session_id'] ?? '') ? 'current' : '' ?>">
                            <div class="session-header">
                                <div class="session-info">
                                    <div class="session-icon">
                                        <i class="fas fa-<?= getDeviceIcon($session['user_agent']) ?>"></i>
                                    </div>
                                    <div class="session-details">
                                        <h3><?= htmlspecialchars(getDeviceInfo($session['user_agent'])) ?></h3>
                                        <div class="session-meta">
                                            Connecté le <?= date('d/m/Y à H:i', strtotime($session['created_at'])) ?>
                                        </div>
                                    </div>
                                </div>
                                <div class="session-actions">
                                    <span class="session-status status-active">
                                        <i class="fas fa-circle"></i>
                                        Active
                                    </span>
                                    <?php if ($session['id'] !== ($_SESSION['session_id'] ?? '')): ?>
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                        <input type="hidden" name="session_id" value="<?= $session['id'] ?>">
                                        <input type="hidden" name="terminate_session" value="1">
                                        <button type="submit" class="btn btn-danger" 
                                                onclick="return confirm('Êtes-vous sûr de vouloir terminer cette session ?')">
                                            <i class="fas fa-times"></i>
                                            Terminer
                                        </button>
                                    </form>
                                    <?php else: ?>
                                    <span class="session-status" style="background: rgba(99, 102, 241, 0.2); color: var(--primary);">
                                        <i class="fas fa-check"></i>
                                        Session actuelle
                                    </span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="session-body">
                                <div class="session-detail">
                                    <span class="detail-label">Adresse IP</span>
                                    <span class="detail-value ip-address"><?= htmlspecialchars($session['ip_address']) ?></span>
                                </div>
                                <div class="session-detail">
                                    <span class="detail-label">Début de session</span>
                                    <span class="detail-value"><?= date('d/m/Y H:i', strtotime($session['created_at'])) ?></span>
                                </div>
                                <div class="session-detail">
                                    <span class="detail-label">Expire le</span>
                                    <span class="detail-value"><?= date('d/m/Y H:i', strtotime($session['expires_at'])) ?></span>
                                </div>
                                <div class="session-detail">
                                    <span class="detail-label">User Agent</span>
                                    <span class="detail-value" style="font-size: 0.8rem;"><?= htmlspecialchars(substr($session['user_agent'], 0, 50)) ?>...</span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <!-- Sessions récentes -->
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Sessions récentes (30 derniers jours)</h2>
                </div>
                
                <?php if (empty($recentSessions)): ?>
                    <div class="empty-state">
                        <i class="fas fa-history"></i>
                        <h3>Aucune session récente</h3>
                        <p>Aucune session n'a été enregistrée au cours des 30 derniers jours.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($recentSessions as $session): ?>
                        <?php $isExpired = strtotime($session['expires_at']) < time(); ?>
                        <div class="session-card">
                            <div class="session-header">
                                <div class="session-info">
                                    <div class="session-icon">
                                        <i class="fas fa-<?= getDeviceIcon($session['user_agent']) ?>"></i>
                                    </div>
                                    <div class="session-details">
                                        <h3><?= htmlspecialchars(getDeviceInfo($session['user_agent'])) ?></h3>
                                        <div class="session-meta">
                                            Connecté le <?= date('d/m/Y à H:i', strtotime($session['created_at'])) ?>
                                        </div>
                                    </div>
                                </div>
                                <div class="session-actions">
                                    <span class="session-status <?= $isExpired ? 'status-expired' : 'status-active' ?>">
                                        <i class="fas fa-circle"></i>
                                        <?= $isExpired ? 'Expirée' : 'Active' ?>
                                    </span>
                                </div>
                            </div>
                            <div class="session-body">
                                <div class="session-detail">
                                    <span class="detail-label">Adresse IP</span>
                                    <span class="detail-value ip-address"><?= htmlspecialchars($session['ip_address']) ?></span>
                                </div>
                                <div class="session-detail">
                                    <span class="detail-label">Début de session</span>
                                    <span class="detail-value"><?= date('d/m/Y H:i', strtotime($session['created_at'])) ?></span>
                                </div>
                                <div class="session-detail">
                                    <span class="detail-label">Statut</span>
                                    <span class="detail-value"><?= $isExpired ? 'Expirée' : 'Active' ?></span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <!-- Informations de sécurité -->
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Conseil de sécurité</strong>
                    <p>Vérifiez régulièrement vos sessions actives. Si vous remarquez une session suspecte, terminez-la immédiatement et changez votre mot de passe.</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>

<?php
// Helper functions
function getDeviceIcon($userAgent) {
    if (strpos($userAgent, 'Mobile') !== false) {
        return 'mobile-alt';
    } elseif (strpos($userAgent, 'Tablet') !== false) {
        return 'tablet-alt';
    } else {
        return 'laptop';
    }
}

function getDeviceInfo($userAgent) {
    $device = 'Appareil inconnu';
    $browser = 'Navigateur inconnu';
    
    // Détection du navigateur
    if (strpos($userAgent, 'Chrome') !== false) {
        $browser = 'Chrome';
    } elseif (strpos($userAgent, 'Firefox') !== false) {
        $browser = 'Firefox';
    } elseif (strpos($userAgent, 'Safari') !== false) {
        $browser = 'Safari';
    } elseif (strpos($userAgent, 'Edge') !== false) {
        $browser = 'Edge';
    }
    
    // Détection de l'appareil
    if (strpos($userAgent, 'Windows') !== false) {
        $device = 'Windows';
    } elseif (strpos($userAgent, 'Mac') !== false) {
        $device = 'Mac';
    } elseif (strpos($userAgent, 'Linux') !== false) {
        $device = 'Linux';
    } elseif (strpos($userAgent, 'Android') !== false) {
        $device = 'Android';
    } elseif (strpos($userAgent, 'iPhone') !== false || strpos($userAgent, 'iPad') !== false) {
        $device = 'iOS';
    }
    
    return "$device - $browser";
}
?>