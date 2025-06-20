// Unified theme color system for ThreatCluster
// This ensures consistent colors across all pages in both light and dark modes

window.getEntityColorClass = function(entityType) {
    // Define color mappings for entity types
    const threatEntities = ['apt_group', 'ransomware_group', 'threat_actor', 'malware', 'malware_family'];
    const warningEntities = ['cve', 'vulnerability'];
    const infoEntities = ['mitre_attack', 'mitre_technique'];
    
    // Check entity type and return appropriate color class
    if (threatEntities.includes(entityType)) {
        return 'bg-red-900 text-red-200 border-red-800';
    } else if (warningEntities.includes(entityType)) {
        return 'bg-orange-900 text-orange-200 border-orange-800';
    } else if (infoEntities.includes(entityType)) {
        return 'bg-purple-900 text-purple-200 border-purple-800';
    } else {
        // Default gray for all other entities (company, industry, platform, attack_type, etc.)
        return 'bg-gray-700 text-gray-200 border-gray-600';
    }
};

// Ensure all background colors respect the theme
window.applyThemeColors = function() {
    const isDark = document.documentElement.classList.contains('dark');
    
    // Remove any blue classes that might have been added
    const blueClasses = ['bg-blue-', 'text-blue-', 'border-blue-', 'bg-indigo-', 'text-indigo-', 'border-indigo-'];
    const allElements = document.querySelectorAll('*');
    
    allElements.forEach(element => {
        const classList = Array.from(element.classList);
        classList.forEach(className => {
            if (blueClasses.some(blueClass => className.includes(blueClass))) {
                element.classList.remove(className);
                // Replace with gray equivalent
                if (className.includes('bg-blue-900') || className.includes('bg-indigo-900')) {
                    element.classList.add('bg-gray-700');
                } else if (className.includes('text-blue-') || className.includes('text-indigo-')) {
                    element.classList.add('text-gray-200');
                } else if (className.includes('border-blue-') || className.includes('border-indigo-')) {
                    element.classList.add('border-gray-600');
                }
            }
        });
    });
};

// Apply theme colors on page load and theme change
document.addEventListener('DOMContentLoaded', applyThemeColors);

// Watch for theme changes
const themeObserver = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
        if (mutation.attributeName === 'class' || mutation.attributeName === 'data-theme') {
            applyThemeColors();
        }
    });
});

themeObserver.observe(document.documentElement, { attributes: true });