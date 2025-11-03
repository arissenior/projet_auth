<?php
error_reporting(E_ALL);
ini_set('display_error',1);
// index.php
require_once 'config.php';

// Si l'utilisateur est déjà connecté, redirection vers le dashboard
if (Auth::isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

// Traitement du formulaire de newsletter
$newsletterSuccess = false;
if ($_POST && isset($_POST['newsletter_subscribe'])) {
    $email = Security::sanitizeInput($_POST['newsletter_email']);
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Enregistrer l'email (simulation)
        $newsletterSuccess = true;
    }
}

// Récupération des statistiques pour la page d'accueil
try {
    $db = Database::getConnection();
    $userCount = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $activeSessions = $db->query("SELECT COUNT(*) FROM user_sessions WHERE expires_at > CURRENT_TIMESTAMP")->fetchColumn();
} catch (PDOException $e) {
    $userCount = 1250;
    $activeSessions = 890;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureAuth - Sécurité Intelligente & Authentification Avancée</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/aos/2.3.4/aos.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/aos/2.3.4/aos.js"></script>
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar" id="navbar">
        <div class="nav-container">
            <a href="#" class="logo">
                <i class="fas fa-shield-alt"></i>
                <span>SecureAuth</span>
            </a>
            
            <div class="nav-links">
                <a href="#features" class="nav-link">Fonctionnalités</a>
                <a href="#security" class="nav-link">Sécurité</a>
                <a href="#testimonials" class="nav-link">Témoignages</a>
                <a href="#pricing" class="nav-link">Tarifs</a>
            </div>
            
            <div class="nav-actions">
                <a href="login.php" class="btn btn-outline">Connexion</a>
                <a href="register.php" class="btn btn-primary">Essai Gratuit</a>
            </div>
            
            <button class="mobile-menu-btn" id="mobileMenuBtn">
                <i class="fas fa-bars"></i>
            </button>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-container">
            <div class="hero-content" data-aos="fade-right">
                <div class="hero-badge">
                    <i class="fas fa-star"></i>
                    <span>Plateforme de sécurité n°1 en 2024</span>
                </div>
                
                <h1 class="hero-title">
                    Sécurité Intelligente 
                    <span style="display: block; background: var(--gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
                        Authentification Avancée
                    </span>
                </h1>
                
                <p class="hero-subtitle">
                    Protégez votre identité numérique avec notre système d'authentification innovant. 
                    Biométrie, 2FA, et protection avancée contre les cybermenaces en temps réel.
                </p>
                
                <div class="hero-actions">
                    <a href="register.php" class="btn btn-primary btn-lg">
                        <i class="fas fa-rocket"></i>
                        Commencer gratuitement
                    </a>
                    <a href="#features" class="btn btn-outline btn-lg">
                        <i class="fas fa-play-circle"></i>
                        Voir la démo
                    </a>
                </div>
                
                <div class="hero-stats">
                    <div class="stat">
                        <span class="stat-value">+<?= $userCount ?></span>
                        <span class="stat-label">Utilisateurs protégés</span>
                    </div>
                    <div class="stat">
                        <span class="stat-value">99.9%</span>
                        <span class="stat-label">Temps de service</span>
                    </div>
                    <div class="stat">
                        <span class="stat-value"><?= $activeSessions ?></span>
                        <span class="stat-label">Sessions actives</span>
                    </div>
                </div>
            </div>
            
            <div class="hero-visual" data-aos="fade-left">
                <div class="floating-card card-1">
                    <div class="card-icon">
                        <i class="fas fa-fingerprint"></i>
                    </div>
                    <h3 class="card-title">Biométrie</h3>
                    <p class="card-text">Authentification par empreinte et reconnaissance faciale</p>
                </div>
                
                <div class="floating-card card-2">
                    <div class="card-icon">
                        <i class="fas fa-shield-check"></i>
                    </div>
                    <h3 class="card-title">Protection</h3>
                    <p class="card-text">Détection d'intrusion en temps réel</p>
                </div>
                
                <div class="floating-card card-3">
                    <div class="card-icon">
                        <i class="fas fa-bolt"></i>
                    </div>
                    <h3 class="card-title">Rapidité</h3>
                    <p class="card-text">Connexion sécurisée en moins de 2 secondes</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="section" id="features">
        <div class="section-header" data-aos="fade-up">
            <span class="section-badge">Fonctionnalités</span>
            <h2 class="section-title">Une sécurité complète pour votre paix d'esprit</h2>
            <p class="section-subtitle">
                Découvrez notre suite complète d'outils de sécurité conçus pour protéger 
                votre identité numérique à chaque étape.
            </p>
        </div>
        
        <div class="features-grid">
            <div class="feature-card" data-aos="fade-up" data-aos-delay="100">
                <div class="feature-icon">
                    <i class="fas fa-fingerprint"></i>
                </div>
                <h3 class="feature-title">Authentification Biométrique</h3>
                <p class="feature-description">
                    Utilisez votre empreinte digitale, votre visage ou votre iris pour une authentification 
                    sécurisée et sans mot de passe.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> Reconnaissance faciale avancée</li>
                    <li><i class="fas fa-check"></i> Empreintes digitales cryptées</li>
                    <li><i class="fas fa-check"></i> Scanner rétinien optionnel</li>
                </ul>
            </div>
            
            <div class="feature-card" data-aos="fade-up" data-aos-delay="200">
                <div class="feature-icon">
                    <i class="fas fa-mobile-alt"></i>
                </div>
                <h3 class="feature-title">2FA Intelligent</h3>
                <p class="feature-description">
                    Authentification à deux facteurs intelligente qui s'adapte à votre niveau de risque 
                    et à votre comportement.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> Codes temporaires sécurisés</li>
                    <li><i class="fas fa-check"></i> Notifications push instantanées</li>
                    <li><i class="fas fa-check"></i> Adaptation contextuelle</li>
                </ul>
            </div>
            
            <div class="feature-card" data-aos="fade-up" data-aos-delay="300">
                <div class="feature-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h3 class="feature-title">Protection Avancée</h3>
                <p class="feature-description">
                    Système de détection d'intrusion et prévention des attaques en temps réel 
                    avec apprentissage automatique.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> Détection d'anomalies IA</li>
                    <li><i class="fas fa-check"></i> Protection contre le phishing</li>
                    <li><i class="fas fa-check"></i> Surveillance 24/7</li>
                </ul>
            </div>
            
            <div class="feature-card" data-aos="fade-up" data-aos-delay="400">
                <div class="feature-icon">
                    <i class="fas fa-tachometer-alt"></i>
                </div>
                <h3 class="feature-title">Tableau de Bord Intelligent</h3>
                <p class="feature-description">
                    Surveillez votre sécurité en temps réel avec des analyses détaillées 
                    et des alertes personnalisées.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> Analytics en temps réel</li>
                    <li><i class="fas fa-check"></i> Rapports de sécurité détaillés</li>
                    <li><i class="fas fa-check"></i> Recommandations personnalisées</li>
                </ul>
            </div>
            
            <div class="feature-card" data-aos="fade-up" data-aos-delay="500">
                <div class="feature-icon">
                    <i class="fas fa-sync-alt"></i>
                </div>
                <h3 class="feature-title">Synchronisation Multi-Appareils</h3>
                <p class="feature-description">
                    Accédez à vos données de sécurité en toute transparence sur tous vos appareils 
                    avec synchronisation cryptée.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> Synchronisation E2E</li>
                    <li><i class="fas fa-check"></i> Gestion multi-appareils</li>
                    <li><i class="fas fa-check"></i> Sauvegarde automatique</li>
                </ul>
            </div>
            
            <div class="feature-card" data-aos="fade-up" data-aos-delay="600">
                <div class="feature-icon">
                    <i class="fas fa-user-lock"></i>
                </div>
                <h3 class="feature-title">Contrôle d'Accès Granulaire</h3>
                <p class="feature-description">
                    Définissez des permissions détaillées et des politiques d'accès 
                    adaptées à vos besoins spécifiques.
                </p>
                <ul class="feature-list">
                    <li><i class="fas fa-check"></i> RBAC avancé</li>
                    <li><i class="fas fa-check"></i> Politiques personnalisables</li>
                    <li><i class="fas fa-check"></i> Audit détaillé</li>
                </ul>
            </div>
        </div>
    </section>

    <!-- Security Showcase -->
    <section class="section security-showcase" id="security">
        <div class="showcase-container">
            <div class="showcase-visual" data-aos="fade-right">
                <div class="security-animation">
                    <div class="shield">
                        <div class="shield-inner">
                            <i class="fas fa-lock"></i>
                        </div>
                    </div>
                    <div class="orbiting-element">
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="orbiting-element">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="orbiting-element">
                        <i class="fas fa-fingerprint"></i>
                    </div>
                    <div class="orbiting-element">
                        <i class="fas fa-mobile-alt"></i>
                    </div>
                </div>
            </div>
            
            <div class="showcase-content" data-aos="fade-left">
                <span class="section-badge">Sécurité</span>
                <h2 class="section-title">Protection de niveau militaire pour vos données</h2>
                <p class="section-subtitle" style="text-align: left; margin: 0 0 2rem 0;">
                    Notre système utilise un chiffrement de bout en bout et des protocoles de sécurité 
                    avancés pour garantir la confidentialité de vos informations.
                </p>
                
                <div class="features-grid" style="grid-template-columns: 1fr; gap: 1.5rem;">
                    <div class="feature-card" style="padding: 1.5rem;">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div class="feature-icon" style="width: 50px; height: 50px; margin: 0;">
                                <i class="fas fa-lock"></i>
                            </div>
                            <div>
                                <h3 style="margin: 0 0 0.5rem 0;">Chiffrement AES-256</h3>
                                <p style="margin: 0; color: var(--gray-light); font-size: 0.9rem;">
                                    Toutes vos données sont chiffrées avec l'algorithme AES-256, le standard de l'industrie.
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="feature-card" style="padding: 1.5rem;">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div class="feature-icon" style="width: 50px; height: 50px; margin: 0; background: rgba(16, 185, 129, 0.1); color: var(--success);">
                                <i class="fas fa-shield-check"></i>
                            </div>
                            <div>
                                <h3 style="margin: 0 0 0.5rem 0;">Certifications de sécurité</h3>
                                <p style="margin: 0; color: var(--gray-light); font-size: 0.9rem;">
                                    Certifié ISO 27001, SOC 2 et conforme au RGPD pour une protection maximale.
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="feature-card" style="padding: 1.5rem;">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div class="feature-icon" style="width: 50px; height: 50px; margin: 0; background: rgba(245, 158, 11, 0.1); color: var(--warning);">
                                <i class="fas fa-eye"></i>
                            </div>
                            <div>
                                <h3 style="margin: 0 0 0.5rem 0;">Surveillance 24/7</h3>
                                <p style="margin: 0; color: var(--gray-light); font-size: 0.9rem;">
                                    Notre équipe de sécurité surveille votre compte en permanence contre les menaces.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Testimonials -->
    <section class="section testimonials" id="testimonials">
        <div class="section-header" data-aos="fade-up">
            <span class="section-badge">Témoignages</span>
            <h2 class="section-title">Ils nous font confiance</h2>
            <p class="section-subtitle">
                Découvrez pourquoi des milliers d'utilisateurs et d'entreprises choisissent SecureAuth.
            </p>
        </div>
        
        <div class="testimonials-grid">
            <div class="testimonial-card" data-aos="fade-up" data-aos-delay="100">
                <div class="testimonial-content">
                    "SecureAuth a révolutionné notre approche de la sécurité. L'authentification biométrique 
                    a considérablement réduit les risques tout en améliorant l'expérience utilisateur."
                </div>
                <div class="testimonial-author">
                    <img src="https://images.unsplash.com/photo-1560250097-0b93528c311a?w=100&h=100&fit=crop&crop=face" alt="Pierre Martin" class="author-avatar">
                    <div class="author-info">
                        <h4>Pierre Martin</h4>
                        <p>DSI, TechInnov</p>
                    </div>
                </div>
            </div>
            
            <div class="testimonial-card" data-aos="fade-up" data-aos-delay="200">
                <div class="testimonial-content">
                    "La mise en place a été incroyablement simple et le support client exceptionnel. 
                    Nous avons déployé SecureAuth sur 500 postes en moins d'une semaine."
                </div>
                <div class="testimonial-author">
                    <img src="https://images.unsplash.com/photo-1580489944761-15a19d654956?w=100&h=100&fit=crop&crop=face" alt="Sophie Laurent" class="author-avatar">
                    <div class="author-info">
                        <h4>Sophie Laurent</h4>
                        <p>Responsable Sécurité, FinSecure</p>
                    </div>
                </div>
            </div>
            
            <div class="testimonial-card" data-aos="fade-up" data-aos-delay="300">
                <div class="testimonial-content">
                    "Les analytics de sécurité nous donnent une visibilité totale sur les activités suspectes. 
                    Nous avons détecté et bloqué plusieurs tentatives d'intrusion grâce à SecureAuth."
                </div>
                <div class="testimonial-author">
                    <img src="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&h=100&fit=crop&crop=face" alt="Thomas Bernard" class="author-avatar">
                    <div class="author-info">
                        <h4>Thomas Bernard</h4>
                        <p>CEO, DataProtect</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="section cta" id="cta">
        <div class="cta-container" data-aos="fade-up">
            <h2 class="cta-title">Prêt à sécuriser votre avenir numérique ?</h2>
            <p class="cta-subtitle">
                Rejoignez des milliers d'utilisateurs qui protègent déjà leur identité avec SecureAuth. 
                Essai gratuit de 30 jours, sans carte de crédit.
            </p>
            <div class="cta-actions">
                <a href="register.php" class="btn btn-light btn-lg">
                    <i class="fas fa-rocket"></i>
                    Commencer gratuitement
                </a>
                <a href="#features" class="btn btn-outline btn-lg" style="background: rgba(255,255,255,0.1);">
                    <i class="fas fa-play-circle"></i>
                    Voir la démo
                </a>
            </div>
        </div>
    </section>

    <!-- Newsletter -->
    <section class="section newsletter">
        <div class="newsletter-container" data-aos="fade-up">
            <h2 class="section-title">Restez informé</h2>
            <p class="section-subtitle">
                Recevez les dernières actualités sur la sécurité numérique et les nouvelles fonctionnalités de SecureAuth.
            </p>
            
            <?php if ($newsletterSuccess): ?>
                <div class="newsletter-success">
                    <i class="fas fa-check-circle"></i>
                    Merci ! Vous recevrez bientôt nos actualités.
                </div>
            <?php else: ?>
                <form method="POST" class="newsletter-form">
                    <input type="email" name="newsletter_email" class="newsletter-input" placeholder="Votre adresse email" required>
                    <button type="submit" name="newsletter_subscribe" class="btn btn-primary">
                        <i class="fas fa-paper-plane"></i>
                        S'abonner
                    </button>
                </form>
            <?php endif; ?>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-container">
            <div class="footer-brand">
                <a href="#" class="logo">
                    <i class="fas fa-shield-alt"></i>
                    <span>SecureAuth</span>
                </a>
                <p class="footer-description">
                    La plateforme de sécurité intelligente qui protège votre identité numérique 
                    avec des technologies d'authentification avancées.
                </p>
                <div class="social-links">
                    <a href="#" class="social-link">
                        <i class="fab fa-twitter"></i>
                    </a>
                    <a href="#" class="social-link">
                        <i class="fab fa-linkedin"></i>
                    </a>
                    <a href="#" class="social-link">
                        <i class="fab fa-github"></i>
                    </a>
                    <a href="#" class="social-link">
                        <i class="fab fa-discord"></i>
                    </a>
                </div>
            </div>
            
            <div class="footer-column">
                <h3 class="footer-heading">Produit</h3>
                <ul class="footer-links">
                    <li><a href="#features">Fonctionnalités</a></li>
                    <li><a href="#security">Sécurité</a></li>
                    <li><a href="#pricing">Tarifs</a></li>
                    <li><a href="#">Documentation</a></li>
                    <li><a href="#">API</a></li>
                </ul>
            </div>
            
            <div class="footer-column">
                <h3 class="footer-heading">Entreprise</h3>
                <ul class="footer-links">
                    <li><a href="#">À propos</a></li>
                    <li><a href="#">Carrières</a></li>
                    <li><a href="#">Presse</a></li>
                    <li><a href="#">Blog</a></li>
                    <li><a href="#">Contact</a></li>
                </ul>
            </div>
            
            <div class="footer-column">
                <h3 class="footer-heading">Légal</h3>
                <ul class="footer-links">
                    <li><a href="#">Mentions légales</a></li>
                    <li><a href="#">Politique de confidentialité</a></li>
                    <li><a href="#">Conditions d'utilisation</a></li>
                    <li><a href="#">RGPD</a></li>
                    <li><a href="#">Cookies</a></li>
                </ul>
            </div>
        </div>
        
        <div class="footer-bottom">
            <p>&copy; 2024 SecureAuth. Tous droits réservés.</p>
        </div>
    </footer>

    <!-- Scroll to Top -->
    <button class="scroll-top" id="scrollTop">
        <i class="fas fa-chevron-up"></i>
    </button>

    <script src="js/index.js"></script>
</body>
</html>