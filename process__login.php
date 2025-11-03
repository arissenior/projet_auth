<?php
include 'config.php';

// Simple input sanitization function
function sanitize_input($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identifier = sanitize_input($_POST['email']);
    $password = $_POST['password'];
    
    try {
        // Vérifier si l'utilisateur existe par email ou username
        $sql = "SELECT * FROM users WHERE email = ? OR username = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$identifier, $identifier]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            // Connexion réussie
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['last_login'] = date('Y-m-d H:i:s');
            
            // Mettre à jour la dernière connexion
            $update_sql = "UPDATE users SET last_login = ? WHERE id = ?";
            $update_stmt = $pdo->prepare($update_sql);
            $update_stmt->execute([date('Y-m-d H:i:s'), $user['id']]);
            
            echo json_encode(['success' => true, 'message' => 'Connexion réussie !']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Identifiants incorrects.']);
        }
    } catch(PDOException $e) {
        error_log("Erreur de connexion : " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Une erreur est survenue.']);
    }
}
?>