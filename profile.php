<?php
// profile.php
require_once 'config.php';
Auth::requireLogin();

$user = Auth::getUser();
$csrfToken = Security::generateCSRFToken();

if ($_POST && isset($_POST['update_profile'])) {
    try {
        Security::validateCSRFToken($_POST['csrf_token']);
        
        $firstName = Security::sanitizeInput($_POST['first_name']);
        $lastName = Security::sanitizeInput($_POST['last_name']);
        $avatarUrl = Security::sanitizeInput($_POST['avatar_url']);
        
        $db = Database::getConnection();
        $stmt = $db->prepare("
            UPDATE users 
            SET first_name = ?, last_name = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ");
        $stmt->execute([$firstName, $lastName, $avatarUrl, $user['id']]);
        
        Auth::logActivity($user['id'], 'profile_update', 'Profile information updated');
        
        $success = "Profil mis à jour avec succès!";
        $user = Auth::getUser(); // Refresh user data
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
    <title>Mon Profil | <?= Config::APP_NAME ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/profile.css">
</head>
<body>
    <div class="dashboard-container">
        <!-- Sidebar (identique au dashboard) -->
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
                <a href="profile.php" class="nav-item active">
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
                <h1>Mon Profil</h1>
            </div>
            
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
            
            <div class="form-container">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <input type="hidden" name="update_profile" value="1">
                    
                    <div class="form-group">
                        <label for="username">Nom d'utilisateur</label>
                        <input type="text" id="username" class="form-control" value="<?= htmlspecialchars($user['username']) ?>" readonly>
                        <small style="color: var(--gray); font-size: 0.8rem;">Le nom d'utilisateur ne peut pas être modifié</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Adresse email</label>
                        <input type="email" id="email" class="form-control" value="<?= htmlspecialchars($user['email']) ?>" readonly>
                        <small style="color: var(--gray); font-size: 0.8rem;">L'email ne peut pas être modifié</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="first_name">Prénom</label>
                        <input type="text" id="first_name" name="first_name" class="form-control" value="<?= htmlspecialchars($user['first_name'] ?? '') ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="last_name">Nom</label>
                        <input type="text" id="last_name" name="last_name" class="form-control" value="<?= htmlspecialchars($user['last_name'] ?? '') ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="avatar_url">URL de l'avatar</label>
                        <input type="url" id="avatar_url" name="avatar_url" class="form-control" value="<?= htmlspecialchars($user['avatar_url'] ?? '') ?>">
                        <small style="color: var(--gray); font-size: 0.8rem;">Entrez l'URL d'une image pour votre avatar</small>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Mettre à jour le profil
                    </button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>