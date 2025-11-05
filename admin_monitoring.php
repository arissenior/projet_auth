<?php
// admin_monitoring.php
require_once 'config.php';

// Vérifier les privilèges administrateur
function isAdmin() {
    if (!Auth::isLoggedIn()) {
        return false;
    }
    
    $user = Auth::getUser();
    // Vérifier si l'utilisateur est admin (vous pouvez adapter cette logique)
    return $user['username'] === 'admin' || $user['email'] === 'admin@secureauth.com';
}

if (!isAdmin()) {
    header('HTTP/1.0 403 Forbidden');
    die('
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Accès Refusé - SecureAuth</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
                    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
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
                    color: #ef4444; 
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
                    <i class="fas fa-ban"></i>
                </div>
                <h1>Accès Refusé</h1>
                <p>Vous n\'avez pas les privilèges administrateur nécessaires pour accéder à cette page.</p>
                <a href="dashboard.php" class="btn">
                    <i class="fas fa-arrow-left"></i>
                    Retour au tableau de bord
                </a>
            </div>
        </body>
        </html>
    ');
}

// Récupération des données de monitoring
try {
    $db = Database::getConnection();
    
    // Statistiques générales
    $stats = [
        'total_users' => $db->query("SELECT COUNT(*) FROM users")->fetchColumn(),
        'active_users' => $db->query("SELECT COUNT(*) FROM users WHERE is_active = TRUE")->fetchColumn(),
        'verified_users' => $db->query("SELECT COUNT(*) FROM users WHERE is_verified = TRUE")->fetchColumn(),
        'total_sessions' => $db->query("SELECT COUNT(*) FROM user_sessions")->fetchColumn(),
        'active_sessions' => $db->query("SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW()")->fetchColumn(),
        'total_activities' => $db->query("SELECT COUNT(*) FROM user_activities")->fetchColumn(),
        'security_events' => $db->query("SELECT COUNT(*) FROM security_logs")->fetchColumn(),
        'failed_logins' => $db->query("SELECT COUNT(*) FROM user_activities WHERE activity_type = 'login_failed'")->fetchColumn(),
    ];
    
    // Activités récentes (24h)
    $recentActivities = $db->query("
        SELECT ua.*, u.username, u.email 
        FROM user_activities ua 
        LEFT JOIN users u ON ua.user_id = u.id 
        WHERE ua.created_at >= NOW() - INTERVAL '24 hours' 
        ORDER BY ua.created_at DESC 
        LIMIT 100
    ")->fetchAll();
    
    // Logs de sécurité récents
    $securityLogs = $db->query("
        SELECT sl.*, u.username 
        FROM security_logs sl 
        LEFT JOIN users u ON sl.user_id = u.id 
        ORDER BY sl.created_at DESC 
        LIMIT 50
    ")->fetchAll();
    
    // Utilisateurs récents (7 derniers jours)
    $recentUsers = $db->query("
        SELECT username, email, created_at, last_login, is_verified 
        FROM users 
        WHERE created_at >= NOW() - INTERVAL '7 days' 
        ORDER BY created_at DESC
    ")->fetchAll();
    
    // Statistiques de connexion par jour (30 derniers jours)
    $loginStats = $db->query("
        SELECT 
            DATE(created_at) as login_date,
            COUNT(*) as login_count,
            COUNT(DISTINCT user_id) as unique_users
        FROM user_activities 
        WHERE activity_type = 'login' 
        AND created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at) 
        ORDER BY login_date DESC
    ")->fetchAll();
    
    // Performances du système
    $systemStats = [
        'php_version' => PHP_VERSION,
        'database_size' => getDatabaseSize($db),
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
        'server_load' => function_exists('sys_getloadavg') ? sys_getloadavg()[0] : 'N/A',
        'memory_usage' => memory_get_usage(true),
        'memory_peak' => memory_get_peak_usage(true),
        'disk_free' => disk_free_space(__DIR__),
        'disk_total' => disk_total_space(__DIR__),
    ];
    
    // Alertes critiques
    $criticalAlerts = $db->query("
        SELECT COUNT(*) 
        FROM security_logs 
        WHERE severity = 'high' 
        AND created_at >= NOW() - INTERVAL '1 hour'
    ")->fetchColumn();
    
} catch (PDOException $e) {
    error_log("Monitoring data error: " . $e->getMessage());
    $stats = [];
    $recentActivities = [];
    $securityLogs = [];
    $recentUsers = [];
    $loginStats = [];
    $systemStats = [];
    $criticalAlerts = 0;
}

// Fonction pour obtenir la taille de la base de données
function getDatabaseSize($pdo) {
    try {
        $stmt = $pdo->query("
            SELECT pg_size_pretty(pg_database_size(current_database())) as size
        ");
        return $stmt->fetchColumn();
    } catch (PDOException $e) {
        return 'N/A';
    }
}

// Fonction pour formatter les tailles
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

// Traitement des actions administrateur
if ($_POST) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        if (isset($_POST['clear_old_logs'])) {
            $days = (int)$_POST['days'] ?? 30;
            $stmt = $db->prepare("
                DELETE FROM user_activities 
                WHERE created_at < NOW() - INTERVAL ? DAY
            ");
            $stmt->execute([$days]);
            
            $stmt = $db->prepare("
                DELETE FROM security_logs 
                WHERE created_at < NOW() - INTERVAL ? DAY
            ");
            $stmt->execute([$days]);
            
            $success = "Logs anciens supprimés avec succès (plus de $days jours)";
        }
        
        if (isset($_POST['export_data'])) {
            $type = $_POST['export_type'] ?? 'activities';
            exportMonitoringData($db, $type);
            exit;
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Fonction d'export des données
function exportMonitoringData($pdo, $type) {
    $filename = "secureauth_monitoring_{$type}_" . date('Y-m-d_H-i-s') . ".csv";
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    switch ($type) {
        case 'users':
            $stmt = $pdo->query("
                SELECT username, email, first_name, last_name, is_active, is_verified, 
                       last_login, created_at, login_attempts
                FROM users 
                ORDER BY created_at DESC
            ");
            fputcsv($output, ['Username', 'Email', 'Prénom', 'Nom', 'Actif', 'Vérifié', 'Dernière connexion', 'Date création', 'Tentatives échouées']);
            break;
            
        case 'activities':
            $stmt = $pdo->query("
                SELECT u.username, ua.activity_type, ua.description, ua.ip_address, ua.user_agent, ua.created_at
                FROM user_activities ua 
                LEFT JOIN users u ON ua.user_id = u.id 
                ORDER BY ua.created_at DESC 
                LIMIT 10000
            ");
            fputcsv($output, ['Utilisateur', 'Type', 'Description', 'IP', 'User Agent', 'Date']);
            break;
            
        case 'security':
            $stmt = $pdo->query("
                SELECT u.username, sl.event_type, sl.severity, sl.description, sl.ip_address, sl.created_at
                FROM security_logs sl 
                LEFT JOIN users u ON sl.user_id = u.id 
                ORDER BY sl.created_at DESC 
                LIMIT 10000
            ");
            fputcsv($output, ['Utilisateur', 'Type d\'événement', 'Sévérité', 'Description', 'IP', 'Date']);
            break;
    }
    
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        fputcsv($output, $row);
    }
    
    fclose($output);
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monitoring Admin - SecureAuth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
   <link rel="stylesheet" href="css/admin_monitoring.css">
</head>
<body>
    <div class="admin-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <span>SecureAuth</span>
                <span class="admin-badge">
                    <i class="fas fa-crown"></i>
                    Admin
                </span>
            </div>
            
            <nav class="nav-menu">
                <a href="dashboard.php" class="nav-item">
                    <i class="fas fa-arrow-left"></i>
                    <span>Retour à l'app</span>
                </a>
                <a href="#overview" class="nav-item active">
                    <i class="fas fa-chart-bar"></i>
                    <span>Vue d'ensemble</span>
                </a>
                <a href="#users" class="nav-item">
                    <i class="fas fa-users"></i>
                    <span>Gestion utilisateurs</span>
                </a>
                <a href="#security" class="nav-item">
                    <i class="fas fa-shield-alt"></i>
                    <span>Logs de sécurité</span>
                </a>
                <a href="#system" class="nav-item">
                    <i class="fas fa-server"></i>
                    <span>Système</span>
                </a>
                <a href="#settings" class="nav-item">
                    <i class="fas fa-cog"></i>
                    <span>Paramètres</span>
                </a>
            </nav>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="header">
                <h1>Monitoring Administrateur</h1>
                <div class="header-actions">
                    <button class="btn btn-outline" onclick="refreshData()">
                        <i class="fas fa-sync-alt"></i>
                        Actualiser
                    </button>
                    <div class="refresh-indicator">
                        <i class="fas fa-clock"></i>
                        <span id="last-updated"><?= date('H:i:s') ?></span>
                    </div>
                </div>
            </div>
            
            <!-- Alertes -->
            <?php if ($criticalAlerts > 0): ?>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong><?= $criticalAlerts ?> alerte(s) critique(s)</strong> détectée(s) dans la dernière heure.
                        <a href="#security" style="color: inherit; text-decoration: underline; margin-left: 10px;">Voir les détails</a>
                    </div>
                </div>
            <?php endif; ?>
            
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
            
            <!-- Statistiques principales -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon users">
                            <i class="fas fa-users"></i>
                        </div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            12%
                        </div>
                    </div>
                    <div class="stat-value"><?= $stats['total_users'] ?? 0 ?></div>
                    <div class="stat-label">Utilisateurs total</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon sessions">
                            <i class="fas fa-laptop"></i>
                        </div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            8%
                        </div>
                    </div>
                    <div class="stat-value"><?= $stats['active_sessions'] ?? 0 ?></div>
                    <div class="stat-label">Sessions actives</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon activities">
                            <i class="fas fa-history"></i>
                        </div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            15%
                        </div>
                    </div>
                    <div class="stat-value"><?= $stats['total_activities'] ?? 0 ?></div>
                    <div class="stat-label">Activités totales</div>
                </div>
                
                <div class="stat-card <?= $criticalAlerts > 0 ? 'critical' : '' ?>">
                    <div class="stat-header">
                        <div class="stat-icon security">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="stat-trend trend-up">
                            <i class="fas fa-arrow-up"></i>
                            5%
                        </div>
                    </div>
                    <div class="stat-value"><?= $stats['security_events'] ?? 0 ?></div>
                    <div class="stat-label">Événements de sécurité</div>
                </div>
            </div>
            
            <!-- Graphiques -->
            <div class="charts-grid">
                <div class="chart-container">
                    <div class="section-header">
                        <h2 class="section-title">Activités des utilisateurs (30 jours)</h2>
                    </div>
                    <div id="activities-chart" class="chart"></div>
                </div>
                
                <div class="chart-container">
                    <div class="section-header">
                        <h2 class="section-title">Répartition des utilisateurs</h2>
                    </div>
                    <div id="users-chart" class="chart"></div>
                </div>
            </div>
            
            <!-- Actions administrateur -->
            <div class="admin-actions">
                <div class="section-header">
                    <h2 class="section-title">Actions administrateur</h2>
                </div>
                <form method="POST" class="action-form">
                    <input type="hidden" name="csrf_token" value="<?= Security::generateCSRFToken() ?>">
                    
                    <div class="form-group">
                        <label for="export_type">Exporter les données</label>
                        <select id="export_type" name="export_type" class="form-control">
                            <option value="activities">Activités utilisateur</option>
                            <option value="users">Liste des utilisateurs</option>
                            <option value="security">Logs de sécurité</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" name="export_data" class="btn btn-primary">
                            <i class="fas fa-download"></i>
                            Exporter CSV
                        </button>
                    </div>
                    
                    <div class="form-group">
                        <label for="days">Nettoyer les logs anciens</label>
                        <select id="days" name="days" class="form-control">
                            <option value="30">Plus de 30 jours</option>
                            <option value="90">Plus de 90 jours</option>
                            <option value="180">Plus de 180 jours</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" name="clear_old_logs" class="btn btn-danger" 
                                onclick="return confirm('Êtes-vous sûr de vouloir supprimer les logs anciens ?')">
                            <i class="fas fa-trash"></i>
                            Nettoyer les logs
                        </button>
                    </div>
                </form>
            </div>
            
            <!-- Informations système -->
            <div class="table-container">
                <div class="section-header">
                    <h2 class="section-title">Informations système</h2>
                </div>
                <div class="system-info">
                    <div class="info-card">
                        <div class="info-label">Version PHP</div>
                        <div class="info-value"><?= $systemStats['php_version'] ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Taille base de données</div>
                        <div class="info-value"><?= $systemStats['database_size'] ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Serveur web</div>
                        <div class="info-value"><?= substr($systemStats['server_software'], 0, 30) ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Charge système</div>
                        <div class="info-value"><?= $systemStats['server_load'] ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Mémoire utilisée</div>
                        <div class="info-value"><?= formatBytes($systemStats['memory_usage']) ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Pic mémoire</div>
                        <div class="info-value"><?= formatBytes($systemStats['memory_peak']) ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Espace disque libre</div>
                        <div class="info-value"><?= formatBytes($systemStats['disk_free']) ?></div>
                    </div>
                    
                    <div class="info-card">
                        <div class="info-label">Espace disque total</div>
                        <div class="info-value"><?= formatBytes($systemStats['disk_total']) ?></div>
                    </div>
                </div>
            </div>
            
            <!-- Activités récentes -->
            <div class="table-container">
                <div class="section-header">
                    <h2 class="section-title">Activités récentes (24h)</h2>
                    <a href="#activities" class="btn btn-outline">Voir tout</a>
                </div>
                <div class="table-responsive">
                    <table class="monitoring-table">
                        <thead>
                            <tr>
                                <th>Utilisateur</th>
                                <th>Type</th>
                                <th>Description</th>
                                <th>IP</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($recentActivities, 0, 10) as $activity): ?>
                                <tr>
                                    <td>
                                        <?php if ($activity['username']): ?>
                                            <img src="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=32&h=32&fit=crop&crop=face" 
                                                 alt="Avatar" class="user-avatar">
                                            <?= htmlspecialchars($activity['username']) ?>
                                        <?php else: ?>
                                            <span class="badge badge-info">Système</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="badge badge-<?= getActivityBadgeClass($activity['activity_type']) ?>">
                                            <?= htmlspecialchars(ucfirst(str_replace('_', ' ', $activity['activity_type']))) ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($activity['description']) ?></td>
                                    <td>
                                        <span class="ip-address"><?= htmlspecialchars($activity['ip_address']) ?></span>
                                    </td>
                                    <td><?= date('d/m/Y H:i', strtotime($activity['created_at'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Logs de sécurité -->
            <div class="table-container">
                <div class="section-header">
                    <h2 class="section-title">Logs de sécurité récents</h2>
                    <a href="#security-logs" class="btn btn-outline">Voir tout</a>
                </div>
                <div class="table-responsive">
                    <table class="monitoring-table">
                        <thead>
                            <tr>
                                <th>Utilisateur</th>
                                <th>Événement</th>
                                <th>Sévérité</th>
                                <th>Description</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($securityLogs, 0, 10) as $log): ?>
                                <tr>
                                    <td>
                                        <?php if ($log['username']): ?>
                                            <img src="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=32&h=32&fit=crop&crop=face" 
                                                 alt="Avatar" class="user-avatar">
                                            <?= htmlspecialchars($log['username']) ?>
                                        <?php else: ?>
                                            <span class="badge badge-info">Système</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= htmlspecialchars(ucfirst($log['event_type'])) ?></td>
                                    <td>
                                        <span class="badge badge-<?= getSeverityBadgeClass($log['severity']) ?>">
                                            <i class="fas fa-<?= getSeverityIcon($log['severity']) ?>"></i>
                                            <?= htmlspecialchars(ucfirst($log['severity'])) ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($log['description']) ?></td>
                                    <td><?= date('d/m/Y H:i', strtotime($log['created_at'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Données pour les graphiques
        const loginStats = <?= json_encode($loginStats) ?>;
        const userStats = {
            total: <?= $stats['total_users'] ?? 0 ?>,
            active: <?= $stats['active_users'] ?? 0 ?>,
            verified: <?= $stats['verified_users'] ?? 0 ?>
        };

        // Graphique des activités
        const activitiesChart = new ApexCharts(document.querySelector("#activities-chart"), {
            series: [{
                name: 'Connexions',
                data: loginStats.map(stat => stat.login_count).reverse()
            }],
            chart: {
                height: 300,
                type: 'area',
                toolbar: {
                    show: false
                },
                zoom: {
                    enabled: false
                }
            },
            colors: ['#6366f1'],
            dataLabels: {
                enabled: false
            },
            stroke: {
                curve: 'smooth',
                width: 3
            },
            fill: {
                type: 'gradient',
                gradient: {
                    shadeIntensity: 1,
                    opacityFrom: 0.7,
                    opacityTo: 0.1,
                    stops: [0, 90, 100]
                }
            },
            xaxis: {
                categories: loginStats.map(stat => new Date(stat.login_date).toLocaleDateString()).reverse(),
                labels: {
                    style: {
                        colors: '#64748b'
                    }
                }
            },
            yaxis: {
                labels: {
                    style: {
                        colors: '#64748b'
                    }
                }
            },
            grid: {
                borderColor: 'rgba(255, 255, 255, 0.1)',
                strokeDashArray: 4
            },
            tooltip: {
                theme: 'dark'
            }
        });

        // Graphique des utilisateurs
        const usersChart = new ApexCharts(document.querySelector("#users-chart"), {
            series: [userStats.active, userStats.total - userStats.active],
            chart: {
                height: 300,
                type: 'donut',
                toolbar: {
                    show: false
                }
            },
            colors: ['#10b981', '#64748b'],
            labels: ['Utilisateurs actifs', 'Utilisateurs inactifs'],
            dataLabels: {
                enabled: false
            },
            legend: {
                position: 'bottom',
                labels: {
                    colors: '#cbd5e1'
                }
            },
            plotOptions: {
                pie: {
                    donut: {
                        size: '65%',
                        labels: {
                            show: true,
                            total: {
                                show: true,
                                label: 'Total utilisateurs',
                                color: '#cbd5e1',
                                formatter: function (w) {
                                    return w.globals.seriesTotals.reduce((a, b) => a + b, 0)
                                }
                            }
                        }
                    }
                }
            },
            responsive: [{
                breakpoint: 480,
                options: {
                    chart: {
                        width: 200
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }]
        });

        // Initialisation des graphiques
        activitiesChart.render();
        usersChart.render();

        // Actualisation des données
        function refreshData() {
            const lastUpdated = document.getElementById('last-updated');
            lastUpdated.innerHTML = '<span class="loading"><span></span><span></span><span></span></span>';
            
            setTimeout(() => {
                location.reload();
            }, 1000);
        }

        // Auto-refresh toutes les 5 minutes
        setInterval(refreshData, 300000);

        // Navigation fluide
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

        // Gestion du menu mobile
        function toggleSidebar() {
            document.querySelector('.sidebar').classList.toggle('active');
        }
    </script>
</body>
</html>

<?php
// Helper functions
function getActivityBadgeClass($activityType) {
    $classes = [
        'login' => 'success',
        'logout' => 'info',
        'login_failed' => 'error',
        'password_change' => 'warning',
        'registration' => 'success'
    ];
    
    return $classes[$activityType] ?? 'info';
}

function getSeverityBadgeClass($severity) {
    $classes = [
        'high' => 'error',
        'medium' => 'warning',
        'low' => 'info',
        'info' => 'info'
    ];
    
    return $classes[$severity] ?? 'info';
}

function getSeverityIcon($severity) {
    $icons = [
        'high' => 'exclamation-triangle',
        'medium' => 'exclamation-circle',
        'low' => 'info-circle',
        'info' => 'info-circle'
    ];
    
    return $icons[$severity] ?? 'info-circle';
}
?>