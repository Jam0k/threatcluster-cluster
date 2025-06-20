// Theme Management for ThreatCluster

// Initialize theme from localStorage or default to dark
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    // Update dark class for Tailwind
    if (savedTheme === 'dark') {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
    
    updateThemeIcon(savedTheme);
}

// Toggle between light and dark themes
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // Update dark class for Tailwind
    if (newTheme === 'dark') {
        html.classList.add('dark');
    } else {
        html.classList.remove('dark');
    }
    
    updateThemeIcon(newTheme);
}

// Update theme icon visibility
function updateThemeIcon(theme) {
    const lightIcon = document.querySelector('.theme-icon-light');
    const darkIcon = document.querySelector('.theme-icon-dark');
    
    if (lightIcon && darkIcon) {
        lightIcon.style.display = theme === 'light' ? 'block' : 'none';
        darkIcon.style.display = theme === 'dark' ? 'block' : 'none';
    }
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', initTheme);

// Export for global use
window.toggleTheme = toggleTheme;