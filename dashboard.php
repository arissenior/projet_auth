<?php
// dashboard.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$userId = $_SESSION['user_id'];

// Log the dashboard access
Auth::logActivity($userId, 'dashboard_access', 'Accessed dashboard');

// Get user statistics
try {
    $db = Database::getConnection();
    
    // Get recent activities
    $stmt = $db->prepare("
        SELECT activity_type, description, created_at 
        FROM user_activities 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ");
    $stmt->execute([$userId]);
    $recentActivities = $stmt->fetchAll();
    
    // Get security logs
    $stmt = $db->prepare("
        SELECT event_type, severity, description, created_at 
        FROM security_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ");
    $stmt->execute([$userId]);
    $securityLogs = $stmt->fetchAll();
    
    // Get login statistics
    $stmt = $db->prepare("
        SELECT login_date, login_count 
        FROM login_stats 
        WHERE user_id = ? 
        ORDER BY login_date DESC 
        LIMIT 7
    ");
    $stmt->execute([$userId]);
    $loginStats = $stmt->fetchAll();
    
    // Get active sessions
    $stmt = $db->prepare("
        SELECT id, ip_address, user_agent, created_at 
        FROM user_sessions 
        WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC
    ");
    $stmt->execute([$userId]);
    $activeSessions = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Dashboard data error: " . $e->getMessage());
    $recentActivities = [];
    $securityLogs = [];
    $loginStats = [];
    $activeSessions = [];
}

// Calculate some stats
$totalLogins = array_sum(array_column($loginStats, 'login_count'));
$uniqueDevices = count($activeSessions);
$securityScore = calculateSecurityScore($user);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de Bord | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="css/dashboard.css">
</head>
<body>
    <div class="dashboard-container">
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
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
                <a href="dashboard.php" class="nav-item active">
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
                <h1>Tableau de Bord</h1>
                <div class="header-actions">
                    <button class="btn btn-primary" onclick="refreshData()">
                        <i class="fas fa-sync-alt"></i>
                        Actualiser
                    </button>
                    <button class="btn btn-primary" onclick="exportData()">
                        <i class="fas fa-download"></i>
                        Exporter
                    </button>
                </div>
            </div>
            
            <!-- Statistics Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon security">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                    </div>
                    <div class="stat-value"><?= $securityScore ?>%</div>
                    <div class="stat-label">Score de sécurité</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon sessions">
                            <i class="fas fa-sign-in-alt"></i>
                        </div>
                    </div>
                    <div class="stat-value"><?= $totalLogins ?></div>
                    <div class="stat-label">Connexions totales</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon activities">
                            <i class="fas fa-chart-line"></i>
                        </div>
                    </div>
                    <div class="stat-value"><?= count($recentActivities) ?></div>
                    <div class="stat-label">Activités récentes</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon devices">
                            <i class="fas fa-laptop"></i>
                        </div>
                    </div>
                    <div class="stat-value"><?= $uniqueDevices ?></div>
                    <div class="stat-label">Appareils actifs</div>
                </div>
            </div>
            
            <!-- Main Content Grid -->
            <div class="content-grid">
                <!-- Left Column -->
                <div class="left-column">
                    <!-- Login Statistics Chart -->
                    <div class="chart-container">
                        <div class="section-header">
                            <h2 class="section-title">Statistiques de connexion</h2>
                        </div>
                        <canvas id="loginChart" height="250"></canvas>
                    </div>
                    
                    <!-- Recent Activities -->
                    <div class="list-container">
                        <div class="section-header">
                            <h2 class="section-title">Activités récentes</h2>
                            <a href="activities.php" class="btn btn-primary">Voir tout</a>
                        </div>
                        <div class="activity-list">
                            <?php foreach (array_slice($recentActivities, 0, 5) as $activity): ?>
                                <div class="activity-item">
                                    <div class="activity-icon">
                                        <i class="fas fa-<?= getActivityIcon($activity['activity_type']) ?>"></i>
                                    </div>
                                    <div class="activity-content">
                                        <div class="activity-title"><?= htmlspecialchars($activity['description']) ?></div>
                                        <div class="activity-time"><?= formatDate($activity['created_at']) ?></div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Right Column -->
                <div class="right-column">
                    <!-- Security Score -->
                    <div class="chart-container security-score">
                        <h3>Score de sécurité</h3>
                        <div class="score-circle">
                            <div class="score-value"><?= $securityScore ?>%</div>
                        </div>
                        <p>Votre niveau de sécurité est <?= getSecurityLevel($securityScore) ?></p>
                    </div>
                    
                    <!-- Security Logs -->
                    <div class="list-container">
                        <div class="section-header">
                            <h2 class="section-title">Alertes de sécurité</h2>
                        </div>
                        <div class="security-list">
                            <?php foreach (array_slice($securityLogs, 0, 5) as $log): ?>
                                <div class="security-item <?= $log['severity'] ?>">
                                    <div class="security-icon">
                                        <i class="fas fa-<?= getSeverityIcon($log['severity']) ?>"></i>
                                    </div>
                                    <div class="security-content">
                                        <div class="security-title"><?= htmlspecialchars($log['description']) ?></div>
                                        <div class="security-time"><?= formatDate($log['created_at']) ?></div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Login Statistics Chart
        const loginCtx = document.getElementById('loginChart').getContext('2d');
        const loginChart = new Chart(loginCtx, {
            type: 'line',
            data: {
                labels: <?= json_encode(array_column($loginStats, 'login_date')) ?>,
                datasets: [{
                    label: 'Connexions',
                    data: <?= json_encode(array_column($loginStats, 'login_count')) ?>,
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        function refreshData() {
            location.reload();
        }

        function exportData() {
            alert('Fonctionnalité d\'exportation à implémenter');
        }

        // Mobile menu toggle
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('active');
        }
    </script>
</body>
</html>

<?php
// Helper functions
function calculateSecurityScore($user) {
    $score = 50; // Base score
    
    // Add points for security features
    if ($user['two_factor_enabled']) $score += 20;
    if ($user['biometric_enabled']) $score += 15;
    if ($user['is_verified']) $score += 10;
    if ($user['login_attempts'] === 0) $score += 5;
    
    return min($score, 100);
}

function getActivityIcon($activityType) {
    $icons = [
        'login' => 'sign-in-alt',
        'logout' => 'sign-out-alt',
        'password_change' => 'key',
        'profile_update' => 'user-edit',
        'dashboard_access' => 'home',
        'security_update' => 'shield-alt'
    ];
    
    return $icons[$activityType] ?? 'circle';
}

function getSeverityIcon($severity) {
    $icons = [
        'high' => 'exclamation-triangle',
        'medium' => 'exclamation-circle',
        'low' => 'info-circle',
        'info' => 'info-circle'
    ];
    
    return $icons[$severity] ?? 'circle';
}

function formatDate($dateString) {
    $date = new DateTime($dateString);
    $now = new DateTime();
    $diff = $now->diff($date);
    
    if ($diff->days === 0) {
        if ($diff->h === 0) {
            return 'Il y a ' . $diff->i . ' min';
        }
        return 'Il y a ' . $diff->h . ' h';
    }
    
    if ($diff->days === 1) {
        return 'Hier';
    }
    
    if ($diff->days < 7) {
        return 'Il y a ' . $diff->days . ' jours';
    }
    
    return $date->format('d/m/Y');
}

function getSecurityLevel($score) {
    if ($score >= 80) return 'excellent';
    if ($score >= 60) return 'bon';
    if ($score >= 40) return 'moyen';
    return 'faible';
}
?>