
        // Validation pour la suppression de compte
        document.getElementById('confirm_text').addEventListener('input', function() {
            const deleteBtn = document.querySelector('button[type="submit"]');
            if (this.value === 'SUPPRIMER MON COMPTE') {
                deleteBtn.disabled = false;
            } else {
                deleteBtn.disabled = true;
            }
        });
        
        // Navigation fluide vers les ancres
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
   