<?php
// activities.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$userId = $_SESSION['user_id'];

// Pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// Filtres
$activityType = isset($_GET['type']) ? Security::sanitizeInput($_GET['type']) : '';
$dateFrom = isset($_GET['date_from']) ? Security::sanitizeInput($_GET['date_from']) : '';
$dateTo = isset($_GET['date_to']) ? Security::sanitizeInput($_GET['date_to']) : '';

// Construction de la requête
$whereConditions = ["user_id = ?"];
$params = [$userId];

if (!empty($activityType)) {
    $whereConditions[] = "activity_type = ?";
    $params[] = $activityType;
}

if (!empty($dateFrom)) {
    $whereConditions[] = "created_at >= ?";
    $params[] = $dateFrom . ' 00:00:00';
}

if (!empty($dateTo)) {
    $whereConditions[] = "created_at <= ?";
    $params[] = $dateTo . ' 23:59:59';
}

$whereClause = implode(' AND ', $whereConditions);

// Récupération des activités
try {
    $db = Database::getConnection();
    
    // Compter le total
    $countStmt = $db->prepare("SELECT COUNT(*) FROM user_activities WHERE $whereClause");
    $countStmt->execute($params);
    $totalActivities = $countStmt->fetchColumn();
    $totalPages = ceil($totalActivities / $limit);
    
    // Récupérer les activités
    $stmt = $db->prepare("
        SELECT activity_type, description, ip_address, user_agent, created_at 
        FROM user_activities 
        WHERE $whereClause 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    ");
    $paramsWithLimit = array_merge($params, [$limit, $offset]);
    $stmt->execute($paramsWithLimit);
    $activities = $stmt->fetchAll();
    
    // Types d'activités pour le filtre
    $typeStmt = $db->prepare("SELECT DISTINCT activity_type FROM user_activities WHERE user_id = ? ORDER BY activity_type");
    $typeStmt->execute([$userId]);
    $activityTypes = $typeStmt->fetchAll(PDO::FETCH_COLUMN);
    
} catch (PDOException $e) {
    error_log("Activities data error: " . $e->getMessage());
    $activities = [];
    $activityTypes = [];
    $totalActivities = 0;
    $totalPages = 1;
}

// Log de l'accès aux activités
Auth::logActivity($userId, 'activities_access', 'Viewed activities page');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activités | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --dark: #1f2937;
            --darker: #111827;
            --light: #f9fafb;
            --gray: #6b7280;
            --glass: rgba(255, 255, 255, 0.1);
            --glass-border: rgba(255, 255, 255, 0.2);
            --shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 50%, var(--primary-dark) 100%);
            min-height: 100vh;
            color: var(--light);
        }

        .dashboard-container {
            display: grid;
            grid-template-columns: 280px 1fr;
            min-height: 100vh;
        }

        .sidebar {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border-right: 1px solid var(--glass-border);
            padding: 30px 20px;
            position: fixed;
            width: 280px;
            height: 100vh;
            overflow-y: auto;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 40px;
            color: white;
        }

        .logo i {
            font-size: 2rem;
            color: var(--primary);
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 30px;
            padding: 15px;
            background: var(--glass);
            border-radius: 12px;
            border: 1px solid var(--glass-border);
        }

        .user-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid var(--primary);
        }

        .user-info h3 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .user-info p {
            font-size: 0.9rem;
            color: var(--gray);
        }

        .nav-menu {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 15px;
            border-radius: 12px;
            color: var(--light);
            text-decoration: none;
            transition: var(--transition);
            font-weight: 500;
        }

        .nav-item:hover, .nav-item.active {
            background: var(--primary);
            color: white;
        }

        .nav-item i {
            width: 20px;
            text-align: center;
        }

        .main-content {
            grid-column: 2;
            padding: 30px;
            margin-left: 280px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            color: white;
        }

        .header-actions {
            display: flex;
            gap: 15px;
        }

        .btn {
            padding: 12px 24px;
            border-radius: 12px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
        }

        .btn-outline {
            background: transparent;
            color: var(--light);
            border: 1px solid var(--glass-border);
        }

        .btn-outline:hover {
            background: var(--glass);
            border-color: var(--primary);
        }

        /* Filtres */
        .filters-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
        }

        .filters-form {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            align-items: end;
        }

        .form-group {
            margin-bottom: 0;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--light);
            font-size: 0.9rem;
        }

        .form-control {
            width: 100%;
            padding: 12px 16px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--glass-border);
            border-radius: 8px;
            color: var(--light);
            font-size: 0.9rem;
            transition: var(--transition);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        /* Tableau des activités */
        .activities-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
        }

        .activities-table {
            width: 100%;
            border-collapse: collapse;
        }

        .activities-table th,
        .activities-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid var(--glass-border);
        }

        .activities-table th {
            font-weight: 600;
            color: var(--gray);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .activities-table tbody tr {
            transition: var(--transition);
        }

        .activities-table tbody tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .activity-type {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: var(--glass);
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .activity-icon {
            width: 16px;
            height: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .ip-address {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--gray);
        }

        .time-ago {
            font-size: 0.85rem;
            color: var(--gray);
        }

        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 30px;
        }

        .pagination-btn {
            padding: 10px 16px;
            background: var(--glass);
            border: 1px solid var(--glass-border);
            border-radius: 8px;
            color: var(--light);
            text-decoration: none;
            transition: var(--transition);
            font-size: 0.9rem;
        }

        .pagination-btn:hover {
            background: var(--primary);
            border-color: var(--primary);
        }

        .pagination-btn.active {
            background: var(--primary);
            border-color: var(--primary);
        }

        .pagination-btn.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .pagination-info {
            color: var(--gray);
            font-size: 0.9rem;
            margin: 0 20px;
        }

        /* Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            transition: var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--gray);
            font-size: 0.9rem;
        }

        /* Responsive */
        @media (max-width: 1200px) {
            .sidebar {
                transform: translateX(-100%);
                transition: var(--transition);
                z-index: 1000;
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
        }

        @media (max-width: 768px) {
            .main-content {
                padding: 20px;
            }
            
            .filters-form {
                grid-template-columns: 1fr;
            }
            
            .activities-table {
                display: block;
                overflow-x: auto;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
            
            .header-actions {
                width: 100%;
                justify-content: space-between;
            }
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        .empty-state h3 {
            font-size: 1.3rem;
            margin-bottom: 10px;
            color: var(--light);
        }
    </style>
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
                <a href="activities.php" class="nav-item active">
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
                <h1>Historique des activités</h1>
                <div class="header-actions">
                    <a href="dashboard.php" class="btn btn-outline">
                        <i class="fas fa-arrow-left"></i>
                        Retour
                    </a>
                    <button class="btn btn-primary" onclick="exportActivities()">
                        <i class="fas fa-download"></i>
                        Exporter
                    </button>
                </div>
            </div>
            
            <!-- Statistiques -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value"><?= $totalActivities ?></div>
                    <div class="stat-label">Activités totales</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?= count($activityTypes) ?></div>
                    <div class="stat-label">Types d'activités</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?= count(array_unique(array_column($activities, 'ip_address'))) ?></div>
                    <div class="stat-label">Adresses IP uniques</div>
                </div>
            </div>
            
            <!-- Filtres -->
            <div class="filters-container">
                <form method="GET" class="filters-form">
                    <div class="form-group">
                        <label for="type">Type d'activité</label>
                        <select id="type" name="type" class="form-control">
                            <option value="">Tous les types</option>
                            <?php foreach ($activityTypes as $type): ?>
                                <option value="<?= htmlspecialchars($type) ?>" <?= $activityType === $type ? 'selected' : '' ?>>
                                    <?= htmlspecialchars(ucfirst(str_replace('_', ' ', $type))) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="date_from">Date de début</label>
                        <input type="date" id="date_from" name="date_from" class="form-control" value="<?= htmlspecialchars($dateFrom) ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="date_to">Date de fin</label>
                        <input type="date" id="date_to" name="date_to" class="form-control" value="<?= htmlspecialchars($dateTo) ?>">
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary" style="width: 100%">
                            <i class="fas fa-filter"></i>
                            Filtrer
                        </button>
                    </div>
                </form>
            </div>
            
            <!-- Tableau des activités -->
            <div class="activities-container">
                <?php if (empty($activities)): ?>
                    <div class="empty-state">
                        <i class="fas fa-history"></i>
                        <h3>Aucune activité trouvée</h3>
                        <p>Aucune activité ne correspond à vos critères de recherche.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="activities-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Description</th>
                                    <th>Adresse IP</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($activities as $activity): ?>
                                    <tr>
                                        <td>
                                            <span class="activity-type">
                                                <i class="fas fa-<?= getActivityIcon($activity['activity_type']) ?> activity-icon"></i>
                                                <?= htmlspecialchars(ucfirst(str_replace('_', ' ', $activity['activity_type']))) ?>
                                            </span>
                                        </td>
                                        <td><?= htmlspecialchars($activity['description']) ?></td>
                                        <td>
                                            <span class="ip-address"><?= htmlspecialchars($activity['ip_address']) ?></span>
                                        </td>
                                        <td>
                                            <div><?= date('d/m/Y H:i', strtotime($activity['created_at'])) ?></div>
                                            <div class="time-ago"><?= getTimeAgo($activity['created_at']) ?></div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($totalPages > 1): ?>
                        <div class="pagination">
                            <a href="?<?= buildQueryString(['page' => max(1, $page - 1)]) ?>" 
                               class="pagination-btn <?= $page <= 1 ? 'disabled' : '' ?>">
                                <i class="fas fa-chevron-left"></i>
                                Précédent
                            </a>
                            
                            <span class="pagination-info">
                                Page <?= $page ?> sur <?= $totalPages ?>
                            </span>
                            
                            <a href="?<?= buildQueryString(['page' => min($totalPages, $page + 1)]) ?>" 
                               class="pagination-btn <?= $page >= $totalPages ? 'disabled' : '' ?>">
                                Suivant
                                <i class="fas fa-chevron-right"></i>
                            </a>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        function exportActivities() {
            const params = new URLSearchParams(window.location.search);
            params.set('export', 'csv');
            window.location.href = 'activities.php?' + params.toString();
        }
        
        // Validation des dates
        document.getElementById('date_from').addEventListener('change', function() {
            const dateTo = document.getElementById('date_to');
            if (this.value && dateTo.value && this.value > dateTo.value) {
                dateTo.value = this.value;
            }
        });
        
        document.getElementById('date_to').addEventListener('change', function() {
            const dateFrom = document.getElementById('date_from');
            if (this.value && dateFrom.value && this.value < dateFrom.value) {
                dateFrom.value = this.value;
            }
        });
    </script>
</body>
</html>

<?php
// Helper functions
function getActivityIcon($activityType) {
    $icons = [
        'login' => 'sign-in-alt',
        'logout' => 'sign-out-alt',
        'password_change' => 'key',
        'profile_update' => 'user-edit',
        'dashboard_access' => 'home',
        'security_update' => 'shield-alt',
        'activities_access' => 'history',
        'security_access' => 'shield-check',
        'sessions_access' => 'laptop',
        'settings_access' => 'cog'
    ];
    
    return $icons[$activityType] ?? 'circle';
}

function getTimeAgo($dateString) {
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
    
    if ($diff->days < 30) {
        $weeks = floor($diff->days / 7);
        return 'Il y a ' . $weeks . ' semaine' . ($weeks > 1 ? 's' : '');
    }
    
    return $date->format('d/m/Y');
}

function buildQueryString($newParams = []) {
    $params = $_GET;
    foreach ($newParams as $key => $value) {
        $params[$key] = $value;
    }
    return http_build_query($params);
}
?>