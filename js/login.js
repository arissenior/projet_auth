
        // Éléments DOM
        const loginForm = document.getElementById('login-form');
        const loginBtn = document.getElementById('login-btn');
        const passwordToggle = document.getElementById('password-toggle');
        const passwordInput = document.getElementById('password');
        const biometricLogin = document.getElementById('biometric-login');
        const forgotPasswordLink = document.getElementById('forgot-password-link');
        const resetModal = document.getElementById('reset-modal');
        const modalClose = document.getElementById('modal-close');
        const resetForm = document.getElementById('reset-form');
        const resetBtn = document.getElementById('reset-btn');
        const backgroundAnimation = document.getElementById('background-animation');

        // Créer l'animation de fond
        function createParticles() {
            for (let i = 0; i < 12; i++) {
                const particle = document.createElement('div');
                particle.classList.add('particle');
                
                // Taille aléatoire
                const size = Math.random() * 15 + 5;
                particle.style.width = `${size}px`;
                particle.style.height = `${size}px`;
                
                // Position aléatoire
                particle.style.left = `${Math.random() * 100}%`;
                particle.style.top = `${Math.random() * 100}%`;
                
                // Animation delay aléatoire
                particle.style.animationDelay = `${Math.random() * 5}s`;
                
                // Couleur aléatoire
                const colors = ['#6366f1', '#8b5cf6', '#10b981', '#f59e0b'];
                const color = colors[Math.floor(Math.random() * colors.length)];
                particle.style.background = color;
                
                backgroundAnimation.appendChild(particle);
            }
        }

        // Basculer la visibilité du mot de passe
        passwordToggle.addEventListener('click', function() {
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                passwordToggle.classList.remove('fa-eye');
                passwordToggle.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                passwordToggle.classList.remove('fa-eye-slash');
                passwordToggle.classList.add('fa-eye');
            }
        });

        // Authentification biométrique simulée
        biometricLogin.addEventListener('click', function() {
            const originalText = biometricLogin.innerHTML;
            biometricLogin.innerHTML = '<i class="fas fa-fingerprint"></i><span>Authentification en cours <span class="loading-dots"><span></span><span></span><span></span></span></span>';
            biometricLogin.style.pointerEvents = 'none';
            
            setTimeout(() => {
                biometricLogin.innerHTML = '<i class="fas fa-check"></i><span>Authentification réussie ! Redirection...</span>';
                biometricLogin.style.color = '#10b981';
                biometricLogin.style.borderColor = '#10b981';
                
                setTimeout(() => {
                    // Simuler une redirection
                    window.location.href = 'dashboard.php';
                }, 1500);
            }, 2000);
        });

        // Gestion du formulaire de connexion
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const btnText = loginBtn.querySelector('.btn-text');
            const originalText = btnText.textContent;
            
            // Simulation de chargement
            loginBtn.classList.add('btn-loading');
            btnText.textContent = 'Connexion en cours...';
            
            // Désactiver les champs pendant le chargement
            const inputs = loginForm.querySelectorAll('input');
            inputs.forEach(input => input.disabled = true);
            
            // Simuler un délai de traitement
            setTimeout(() => {
                // Réactiver les champs
                inputs.forEach(input => input.disabled = false);
                loginBtn.classList.remove('btn-loading');
                btnText.textContent = originalText;
                
                // Soumettre le formulaire
                loginForm.submit();
            }, 1500);
        });

        // Gestion de la modal de réinitialisation
        forgotPasswordLink.addEventListener('click', function(e) {
            e.preventDefault();
            resetModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        });

        modalClose.addEventListener('click', function() {
            resetModal.style.display = 'none';
            document.body.style.overflow = 'auto';
        });

        resetModal.addEventListener('click', function(e) {
            if (e.target === resetModal) {
                resetModal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        });

        // Gestion du formulaire de réinitialisation
        resetForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const btnText = resetBtn.querySelector('.btn-text');
            const originalText = btnText.textContent;
            
            // Simulation de chargement
            resetBtn.classList.add('btn-loading');
            btnText.textContent = 'Envoi en cours...';
            
            setTimeout(() => {
                resetBtn.classList.remove('btn-loading');
                btnText.textContent = 'Lien envoyé !';
                resetBtn.style.background = '#10b981';
                
                setTimeout(() => {
                    resetForm.submit();
                }, 1000);
            }, 2000);
        });

        // Animation d'entrée des éléments
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            
            const elements = document.querySelectorAll('.form-group, .form-options, .btn, .divider, .social-login, .form-footer, .biometric-option, .security-indicator');
            
            elements.forEach((element, index) => {
                element.style.opacity = '0';
                element.style.transform = 'translateY(20px)';
                
                setTimeout(() => {
                    element.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    element.style.opacity = '1';
                    element.style.transform = 'translateY(0)';
                }, 100 + index * 100);
            });
            
            // Focus sur le premier champ
            document.getElementById('identifier').focus();
        });

        // Effet de focus amélioré
        document.querySelectorAll('.input-with-icon input').forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'translateY(-2px)';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'translateY(0)';
            });
        });

        // Validation en temps réel
        document.getElementById('identifier').addEventListener('input', function() {
            if (this.value.length > 0) {
                this.parentElement.style.borderColor = '#10b981';
            } else {
                this.parentElement.style.borderColor = '#e2e8f0';
            }
        });

        // Navigation au clavier
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                resetModal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        });
   