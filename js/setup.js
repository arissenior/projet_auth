
        // Créer l'animation de fond
        function createParticles() {
            const backgroundAnimation = document.getElementById('background-animation');
            for (let i = 0; i < 15; i++) {
                const particle = document.createElement('div');
                particle.classList.add('particle');
                
                const size = Math.random() * 20 + 5;
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

        // Validation des formulaires
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            
            // Validation de l'étape 1
            const step1Form = document.getElementById('step-1');
            if (step1Form) {
                step1Form.addEventListener('submit', function(e) {
                    const dbUser = document.getElementById('db_user').value;
                    if (!dbUser) {
                        e.preventDefault();
                        alert('Veuillez remplir tous les champs obligatoires.');
                        return;
                    }
                });
            }
            
            // Validation de l'étape 2
            const step2Form = document.getElementById('step-2');
            if (step2Form) {
                step2Form.addEventListener('submit', function(e) {
                    const adminEmail = document.getElementById('admin_email').value;
                    const adminPassword = document.getElementById('admin_password').value;
                    const adminConfirmPassword = document.getElementById('admin_confirm_password').value;
                    
                    if (!adminEmail || !adminPassword || !adminConfirmPassword) {
                        e.preventDefault();
                        alert('Veuillez remplir tous les champs obligatoires.');
                        return;
                    }
                    
                    if (adminPassword !== adminConfirmPassword) {
                        e.preventDefault();
                        alert('Les mots de passe ne correspondent pas.');
                        return;
                    }
                    
                    if (adminPassword.length < 8) {
                        e.preventDefault();
                        alert('Le mot de passe doit contenir au moins 8 caractères.');
                        return;
                    }
                });
            }
            
            // Indicateur de force du mot de passe
            const adminPassword = document.getElementById('admin_password');
            if (adminPassword) {
                adminPassword.addEventListener('input', function() {
                    const password = this.value;
                    const requirements = {
                        length: password.length >= 8,
                        uppercase: /[A-Z]/.test(password),
                        lowercase: /[a-z]/.test(password),
                        number: /[0-9]/.test(password),
                        special: /[!@#$%^&*()\-_=+{};:,<.>]/.test(password)
                    };
                    
                    // Mettre à jour l'interface utilisateur si nécessaire
                    console.log('Force du mot de passe:', requirements);
                });
            }
            
            // Vérification de la correspondance des mots de passe
            const confirmPassword = document.getElementById('admin_confirm_password');
            if (confirmPassword && adminPassword) {
                confirmPassword.addEventListener('input', function() {
                    if (this.value !== adminPassword.value) {
                        this.style.borderColor = '#ef4444';
                    } else {
                        this.style.borderColor = '#10b981';
                    }
                });
            }
        });

        // Animation des étapes
        document.querySelectorAll('.form-step').forEach((step, index) => {
            step.style.opacity = '0';
            step.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                step.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                if (step.classList.contains('active')) {
                    step.style.opacity = '1';
                    step.style.transform = 'translateY(0)';
                }
            }, 100 + index * 100);
        });
