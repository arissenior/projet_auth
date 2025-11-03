
        // Éléments DOM
        const registerForm = document.getElementById('register-form');
        const steps = [1, 2, 3];
        const progressSteps = steps.map(step => document.getElementById(`step-${step}`));
        const formSteps = steps.map(step => document.getElementById(`form-step-${step}`));
        const nextStep1 = document.getElementById('next-step-1');
        const nextStep2 = document.getElementById('next-step-2');
        const prevStep2 = document.getElementById('prev-step-2');
        const prevStep3 = document.getElementById('prev-step-3');
        const registerBtn = document.getElementById('register-btn');
        const passwordToggle = document.getElementById('password-toggle');
        const confirmPasswordToggle = document.getElementById('confirm-password-toggle');
        const passwordInput = document.getElementById('password');
        const confirmPasswordInput = document.getElementById('confirm-password');
        const passwordStrengthBar = document.getElementById('password-strength-bar');
        const passwordMatch = document.getElementById('password-match');
        const backgroundAnimation = document.getElementById('background-animation');
        
        let currentStep = 1;

        // Créer l'animation de fond
        function createParticles() {
            for (let i = 0; i < 12; i++) {
                const particle = document.createElement('div');
                particle.classList.add('particle');
                
                const size = Math.random() * 15 + 5;
                particle.style.width = `${size}px`;
                particle.style.height = `${size}px`;
                
                particle.style.left = `${Math.random() * 100}%`;
                particle.style.top = `${Math.random() * 100}%`;
                
                particle.style.animationDelay = `${Math.random() * 5}s`;
                
                const colors = ['#6366f1', '#8b5cf6', '#10b981', '#f59e0b'];
                const color = colors[Math.floor(Math.random() * colors.length)];
                particle.style.background = color;
                
                backgroundAnimation.appendChild(particle);
            }
        }

        // Afficher une étape spécifique
        function showStep(stepIndex) {
            formSteps.forEach((step, index) => {
                step.classList.toggle('active', index + 1 === stepIndex);
            });
            
            progressSteps.forEach((step, index) => {
                if (index + 1 < stepIndex) {
                    step.classList.add('completed');
                    step.classList.remove('active');
                } else if (index + 1 === stepIndex) {
                    step.classList.add('active');
                    step.classList.remove('completed');
                } else {
                    step.classList.remove('active', 'completed');
                }
            });
            
            currentStep = stepIndex;
        }

        // Validation de l'étape 1
        function validateStep1() {
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            
            if (!username || !email) {
                alert('Veuillez remplir tous les champs obligatoires.');
                return false;
            }
            
            if (!isValidEmail(email)) {
                alert('Veuillez entrer une adresse email valide.');
                return false;
            }
            
            return true;
        }

        // Validation de l'étape 2
        function validateStep2() {
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;
            
            if (!password || !confirmPassword) {
                alert('Veuillez remplir tous les champs de mot de passe.');
                return false;
            }
            
            if (password !== confirmPassword) {
                alert('Les mots de passe ne correspondent pas.');
                return false;
            }
            
            const strength = checkPasswordStrength(password);
            if (strength === 'weak' || strength === 'fair') {
                alert('Veuillez choisir un mot de passe plus fort.');
                return false;
            }
            
            return true;
        }

        // Validation email
        function isValidEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        // Vérification de la force du mot de passe
        function checkPasswordStrength(password) {
            let strength = 0;
            const requirements = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[!@#$%^&*()\-_=+{};:,<.>]/.test(password)
            };
            
            // Mettre à jour les indicateurs visuels
            Object.keys(requirements).forEach(key => {
                const element = document.getElementById(`req-${key}`);
                if (requirements[key]) {
                    element.classList.remove('unmet');
                    element.classList.add('met');
                    element.innerHTML = '<i class="fas fa-check"></i><span>' + element.textContent + '</span>';
                    strength++;
                } else {
                    element.classList.remove('met');
                    element.classList.add('unmet');
                    element.innerHTML = '<i class="fas fa-circle"></i><span>' + element.textContent + '</span>';
                }
            });
            
            // Mettre à jour la barre de force
            passwordStrengthBar.className = 'password-strength-bar';
            
            if (password.length > 0) {
                if (strength < 3) {
                    passwordStrengthBar.classList.add('strength-weak');
                    return 'weak';
                } else if (strength < 4) {
                    passwordStrengthBar.classList.add('strength-fair');
                    return 'fair';
                } else if (strength < 5) {
                    passwordStrengthBar.classList.add('strength-good');
                    return 'good';
                } else {
                    passwordStrengthBar.classList.add('strength-strong');
                    return 'strong';
                }
            }
            
            return 'none';
        }

        // Vérification de la correspondance des mots de passe
        function checkPasswordMatch() {
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;
            
            if (confirmPassword.length === 0) {
                passwordMatch.textContent = '';
                passwordMatch.style.color = '';
            } else if (password === confirmPassword) {
                passwordMatch.textContent = '✓ Les mots de passe correspondent';
                passwordMatch.style.color = '#10b981';
            } else {
                passwordMatch.textContent = '✗ Les mots de passe ne correspondent pas';
                passwordMatch.style.color = '#ef4444';
            }
        }

        // Événements
        nextStep1.addEventListener('click', function() {
            if (validateStep1()) {
                showStep(2);
            }
        });

        nextStep2.addEventListener('click', function() {
            if (validateStep2()) {
                showStep(3);
            }
        });

        prevStep2.addEventListener('click', function() {
            showStep(1);
        });

        prevStep3.addEventListener('click', function() {
            showStep(2);
        });

        // Basculer la visibilité des mots de passe
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

        confirmPasswordToggle.addEventListener('click', function() {
            if (confirmPasswordInput.type === 'password') {
                confirmPasswordInput.type = 'text';
                confirmPasswordToggle.classList.remove('fa-eye');
                confirmPasswordToggle.classList.add('fa-eye-slash');
            } else {
                confirmPasswordInput.type = 'password';
                confirmPasswordToggle.classList.remove('fa-eye-slash');
                confirmPasswordToggle.classList.add('fa-eye');
            }
        });

        // Écouteurs pour la validation en temps réel
        passwordInput.addEventListener('input', function() {
            checkPasswordStrength(this.value);
            checkPasswordMatch();
        });

        confirmPasswordInput.addEventListener('input', checkPasswordMatch);

        // Validation du formulaire final
        registerForm.addEventListener('submit', function(e) {
            const terms = document.getElementById('terms');
            
            if (!terms.checked) {
                e.preventDefault();
                alert('Vous devez accepter les conditions d\'utilisation pour créer un compte.');
                return;
            }
            
            const btnText = registerBtn.querySelector('.btn-text');
            btnText.textContent = 'Création du compte...';
            registerBtn.classList.add('btn-loading');
        });

        // Animation d'entrée
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            showStep(1);
            
            // Focus sur le premier champ
            document.getElementById('username').focus();
            
            // Animation des éléments du formulaire
            const elements = document.querySelectorAll('.form-group, .form-actions, .form-footer');
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

        // Navigation au clavier
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                if (currentStep === 1) {
                    nextStep1.click();
                } else if (currentStep === 2) {
                    nextStep2.click();
                } else if (currentStep === 3) {
                    registerForm.dispatchEvent(new Event('submit'));
                }
            }
            
            if (e.key === 'Escape' && currentStep > 1) {
                showStep(currentStep - 1);
            }
        });
    