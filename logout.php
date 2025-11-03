<?php
// logout.php
require_once 'config.php';

if (Auth::isLoggedIn()) {
    $userId = $_SESSION['user_id'];
    
    // Log the logout activity
    Auth::logActivity($userId, 'logout', 'User logged out');
    
    // Clear all session data
    $_SESSION = [];
    
    // Destroy session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    session_destroy();
}

header('Location: login.php');
exit;
?>