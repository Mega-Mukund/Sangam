document.addEventListener('DOMContentLoaded', () => {
    // Theme toggling logic
    const themeToggleBtn = document.getElementById('theme-toggle');
    const htmlEl = document.documentElement;
    const themeIcon = document.getElementById('theme-icon');
  
    // Check local storage for theme
    const currentTheme = localStorage.getItem('theme');
    
    if (currentTheme === 'dark') {
      htmlEl.classList.add('dark');
      if (themeIcon) themeIcon.className = 'fas fa-sun';
    } else {
      if (themeIcon) themeIcon.className = 'fas fa-moon';
    }
  
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
        htmlEl.classList.toggle('dark');
        let theme = 'light';
        if (htmlEl.classList.contains('dark')) {
            theme = 'dark';
            themeIcon.className = 'fas fa-sun';
        } else {
            themeIcon.className = 'fas fa-moon';
        }
        localStorage.setItem('theme', theme);
        });
    }

    // Auto-hid alerts after a few seconds
    const alerts = document.querySelectorAll('.alert-error, .alert-success');
    if (alerts.length > 0) {
        setTimeout(() => {
            alerts.forEach(alert => {
                alert.style.opacity = '0';
                alert.style.transition = 'opacity 0.5s ease';
                setTimeout(() => alert.remove(), 500);
            });
        }, 5000);
    }
  });
