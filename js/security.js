
        function checkPasswordStrength(password) {
            const strengthBar = document.getElementById('password-strength-bar');
            let strength = 0;
            
            // Longueur minimale
            if (password.length >= 8) strength++;
            
            // Lettres minuscules et majuscules
            if (password.match(/([a-z].*[A-Z])|([A-Z].*[a-z])/)) strength++;
            
            // Chiffres
            if (password.match(/([0-9])/)) strength++;
            
            // Caractères spéciaux
            if (password.match(/([!,%,&,@,#,$,^,*,?,_,~])/)) strength++;
            
            // Mettre à jour la barre
            strengthBar.className = 'password-strength-bar';
            
            if (password.length > 0) {
                if (strength < 2) {
                    strengthBar.classList.add('strength-weak');
                } else if (strength < 3) {
                    strengthBar.classList.add('strength-fair');
                } else if (strength < 4) {
                    strengthBar.classList.add('strength-good');
                } else {
                    strengthBar.classList.add('strength-strong');
                }
            }
        }
   