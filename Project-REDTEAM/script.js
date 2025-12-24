document.addEventListener('DOMContentLoaded', () => {

    function animateIcon(icon, animClass) {
        icon.classList.remove("pop", "shaking"); 
        void icon.offsetWidth; 
        icon.classList.add(animClass); 
        setTimeout(() => { icon.classList.remove(animClass); }, 300);
    }

    window.manualToggle = function(inputId, icon) {
        const input = document.getElementById(inputId);
        if (input.type === "password") {
            input.type = "text";
            icon.textContent = "🐵";
            animateIcon(icon, "pop");
        } else {
            input.type = "password";
            if(input.value.length > 0) {
                icon.textContent = "🙈";
            } else {
                icon.textContent = "🐵";
            }
            animateIcon(icon, "pop");
        }
    }

    function attachMonkeyLogic(inputId, iconId) {
        const input = document.getElementById(inputId);
        const icon = document.getElementById(iconId);
        let isCovering = false; 

        if(input && icon) {
            input.addEventListener('input', function() {
                if (input.type === "password") {
                    if (this.value.length > 0) {
                        if (!isCovering) {
                            icon.textContent = "🙈";
                            animateIcon(icon, "pop");
                            isCovering = true;
                        } else {
                            if(Math.random() > 0.5) animateIcon(icon, "shaking");
                        }
                    } else {
                        if (isCovering) {
                            icon.textContent = "🐵";
                            animateIcon(icon, "pop");
                            isCovering = false;
                        }
                    }
                }
            });
        }
    }

    attachMonkeyLogic('regPass', 'regIcon');
    attachMonkeyLogic('loginPass', 'loginIcon');

    const signUpBtn = document.getElementById('signUp');
    const signInBtn = document.getElementById('signIn');
    const container = document.getElementById('container');
    const toggleBtn = document.getElementById('toggleMode');
    const volSlider = document.getElementById('volSlider');
    const body = document.body;
    const music = document.getElementById('bgMusic');
    
    if(music) music.volume = 0.3;

    if(signUpBtn) signUpBtn.addEventListener('click', () => { container.classList.add("right-panel-active"); });
    if(signInBtn) signInBtn.addEventListener('click', () => { container.classList.remove("right-panel-active"); });
    
    document.body.addEventListener('click', () => {
        if (music && music.paused) {
            music.play().catch(e => console.log("Audio play blocked."));
        }
    }, { once: true });

    if(volSlider) volSlider.addEventListener('input', (e) => { if(music) music.volume = e.target.value; });

    if(toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const isDark = body.getAttribute('data-theme') === 'dark';
            const newTheme = isDark ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            toggleBtn.textContent = newTheme === 'dark' ? 'DAY MODE ☀️' : 'NIGHT MODE 🌙';
            const formData = new FormData();
            formData.append('ajax_theme', '1');
            formData.append('theme_val', newTheme);
            fetch('index.php', { method: 'POST', body: formData });
        });
    }
});