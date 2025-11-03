
        // Éléments DOM
        const loginTab = document.getElementById('login-tab');
        const registerTab = document.getElementById('register-tab');
        const tabIndicator = document.getElementById('tab-indicator');
        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        const switchToRegister = document.getElementById('switch-to-register');
        const switchToLogin = document.getElementById('switch-to-login');
        const loginPasswordToggle = document.getElementById('login-password-toggle');
        const registerPasswordToggle = document.getElementById('register-password-toggle');
        const loginPassword = document.getElementById('login-password');
        const registerPassword = document.getElementById('register-password');
        const passwordStrengthBar = document.getElementById('password-strength-bar');
        const successAlert = document.getElementById('success-alert');
        const errorAlert = document.getElementById('error-alert');
        const successMessage = document.getElementById('success-message');
        const errorMessage = document.getElementById('error-message');
        const backgroundAnimation = document.getElementById('background-animation');
        const biometricLogin = document.getElementById('biometric-login');
        const loginBtn = document.getElementById('login-btn');
        const registerBtn = document.getElementById('register-btn');
        
        // Éléments pour les étapes d'inscription
        const formSteps = [
            document.getElementById('form-step-1'),
            document.getElementById('form-step-2'),
            document.getElementById('form-step-3')
        ];
        const progressSteps = [
            document.getElementById('step-1'),
            document.getElementById('step-2'),
            document.getElementById('step-3')
        ];
        const nextStep1 = document.getElementById('next-step-1');
        const nextStep2 = document.getElementById('next-step-2');
        const prevStep2 = document.getElementById('prev-step-2');
        const prevStep3 = document.getElementById('prev-step-3');
        
        let currentStep = 0;

        // Créer l'animation de fond
        function createParticles() {
            for (let i = 0; i < 15; i++) {
                const particle = document.createElement('div');
                particle.classList.add('particle');
                
                // Taille aléatoire
                const size = Math.random() * 20 + 5;
                particle.style.width = `${size}px`;
                particle.style.height = `${size}px`;
                
                // Position aléatoire
                particle.style.left = `${Math.random() * 100}%`;
                particle.style.top = `${Math.random() * 100}%`;
                
                // Animation delay aléatoire
                particle.style.animationDelay = `${Math.random() * 5}s`;
                
                // Couleur aléatoire
                const colors = ['#6366f1', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444'];
                const color = colors[Math.floor(Math.random() * colors.length)];
                particle.style.background = color;
                
                backgroundAnimation.appendChild(particle);
            }
        }

        // Basculer entre les formulaires
        loginTab.addEventListener('click', () => {
            loginTab.classList.add('active');
            registerTab.classList.remove('active');
            tabIndicator.classList.remove('register');
            loginForm.classList.add('active');
            registerForm.classList.remove('active');
            resetFormSteps();
            hideAlerts();
        });

        registerTab.addEventListener('click', () => {
            registerTab.classList.add('active');
            loginTab.classList.remove('active');
            tabIndicator.classList.add('register');
            registerForm.classList.add('active');
            loginForm.classList.remove('active');
            hideAlerts();
        });

        switchToRegister.addEventListener('click', (e) => {
            e.preventDefault();
            registerTab.click();
        });

        switchToLogin.addEventListener('click', (e) => {
            e.preventDefault();
            loginTab.click();
        });

        // Basculer la visibilité du mot de passe
        loginPasswordToggle.addEventListener('click', () => {
            togglePasswordVisibility(loginPassword, loginPasswordToggle);
        });

        registerPasswordToggle.addEventListener('click', () => {
            togglePasswordVisibility(registerPassword, registerPasswordToggle);
        });

        function togglePasswordVisibility(passwordField, toggleIcon) {
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
            } else {
                passwordField.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
            }
        }

        // Vérification de la force du mot de passe
        registerPassword.addEventListener('input', () => {
            const password = registerPassword.value;
            const strength = checkPasswordStrength(password);
            
            passwordStrengthBar.className = 'password-strength-bar';
            
            if (password.length > 0) {
                passwordStrengthBar.classList.add(`strength-${strength}`);
            }
        });

        function checkPasswordStrength(password) {
            let strength = 0;
            
            // Longueur minimale
            if (password.length >= 8) strength++;
            
            // Contient des lettres minuscules et majuscules
            if (password.match(/([a-z].*[A-Z])|([A-Z].*[a-z])/)) strength++;
            
            // Contient des chiffres
            if (password.match(/([0-9])/)) strength++;
            
            // Contient des caractères spéciaux
            if (password.match(/([!,%,&,@,#,$,^,*,?,_,~])/)) strength++;
            
            // Déterminer le niveau de force
            if (strength < 2) return 'weak';
            if (strength < 3) return 'fair';
            if (strength < 4) return 'good';
            return 'strong';
        }

        // Gestion des étapes d'inscription
        function showStep(stepIndex) {
            formSteps.forEach((step, index) => {
                step.style.display = index === stepIndex ? 'block' : 'none';
            });
            
            progressSteps.forEach((step, index) => {
                if (index < stepIndex) {
                    step.classList.add('completed');
                    step.classList.remove('active');
                } else if (index === stepIndex) {
                    step.classList.add('active');
                    step.classList.remove('completed');
                } else {
                    step.classList.remove('active', 'completed');
                }
            });
            
            currentStep = stepIndex;
        }

        function resetFormSteps() {
            showStep(0);
        }

        nextStep1.addEventListener('click', () => {
            const username = document.getElementById('register-username').value;
            const email = document.getElementById('register-email').value;
            
            if (username && email) {
                showStep(1);
            } else {
                showError('Veuillez remplir tous les champs.');
            }
        });

        nextStep2.addEventListener('click', () => {
            const password = document.getElementById('register-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            if (password && confirmPassword) {
                if (password === confirmPassword) {
                    showStep(2);
                } else {
                    showError('Les mots de passe ne correspondent pas.');
                }
            } else {
                showError('Veuillez remplir tous les champs.');
            }
        });

        prevStep2.addEventListener('click', () => {
            showStep(0);
        });

        prevStep3.addEventListener('click', () => {
            showStep(1);
        });

        // Authentification biométrique simulée
        biometricLogin.addEventListener('click', () => {
            showSuccess('Authentification biométrique détectée...');
            loginBtn.classList.add('btn-loading');
            
            setTimeout(() => {
                loginBtn.classList.remove('btn-loading');
                showSuccess('Authentification réussie ! Redirection...');
                setTimeout(() => {
                    window.location.href = 'dashboard.php';
                }, 1500);
            }, 2000);
        });

        // Gestion des formulaires
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            
            // Simulation de connexion
            if (email && password) {
                loginBtn.classList.add('btn-loading');
                
                setTimeout(() => {
                    loginBtn.classList.remove('btn-loading');
                    showSuccess('Connexion réussie ! Redirection en cours...');
                    // Ici, vous enverriez les données au serveur
                    setTimeout(() => {
                        window.location.href = 'dashboard.php';
                    }, 1500);
                }, 2000);
            } else {
                showError('Veuillez remplir tous les champs.');
            }
        });

        registerForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const terms = document.getElementById('terms').checked;
            
            // Validation
            if (!username || !email || !password || !confirmPassword) {
                showError('Veuillez remplir tous les champs.');
                return;
            }
            
            if (password !== confirmPassword) {
                showError('Les mots de passe ne correspondent pas.');
                return;
            }
            
            if (!terms) {
                showError('Veuillez accepter les conditions d\'utilisation.');
                return;
            }
            
            registerBtn.classList.add('btn-loading');
            
            // Simulation d'inscription
            setTimeout(() => {
                registerBtn.classList.remove('btn-loading');
                showSuccess('Inscription réussie ! Vérification de sécurité en cours...');
                
                setTimeout(() => {
                    showSuccess('Compte créé avec succès ! Vous pouvez maintenant vous connecter.');
                    setTimeout(() => {
                        loginTab.click();
                        registerForm.reset();
                        passwordStrengthBar.className = 'password-strength-bar';
                        resetFormSteps();
                    }, 2000);
                }, 1500);
            }, 2000);
        });

        // Fonctions d'affichage des alertes
        function showSuccess(message) {
            successMessage.textContent = message;
            successAlert.style.display = 'flex';
            errorAlert.style.display = 'none';
        }

        function showError(message) {
            errorMessage.textContent = message;
            errorAlert.style.display = 'flex';
            successAlert.style.display = 'none';
        }

        function hideAlerts() {
            successAlert.style.display = 'none';
            errorAlert.style.display = 'none';
        }

        // Animation d'entrée des éléments
        document.addEventListener('DOMContentLoaded', () => {
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
        });
   