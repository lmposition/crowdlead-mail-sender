// Gestionnaire d'authentification
const AuthManager = {
    init() {
        // Vérifier l'authentification au chargement
        this.checkAuth();

        // Gestionnaire de déconnexion
        document.getElementById('logout-btn').addEventListener('click', async () => {
            try {
                await API.logout();
                Utils.showNotification('Déconnexion réussie');
                window.location.href = '/admin/login';
            } catch (error) {
                console.error('Erreur lors de la déconnexion:', error);
                Utils.showNotification('Erreur lors de la déconnexion', 'error');
            }
        });
    },

    async checkAuth() {
        try {
            const response = await API.checkAuth();
            if (response.success && response.data.authenticated) {
                // Afficher un message de bienvenue
                const expiresAt = new Date(response.data.expiresAt);
                const welcomeMsg = document.getElementById('welcome-message');
                welcomeMsg.textContent = `Session expire le ${Utils.formatDate(expiresAt)}`;
                return true;
            }
        } catch (error) {
            console.error('Erreur d\'authentification:', error);
        }
        
        // Rediriger vers la page de connexion si non authentifié
        window.location.href = '/admin/login';
        return false;
    }
};

// Gestion des interactions globales
const GlobalEventManager = {
    init() {
        // Gérer les raccourcis clavier
        document.addEventListener('keydown', (e) => {
            // Échapper pour fermer les modals
            if (e.key === 'Escape') {
                const modals = document.querySelectorAll('.modal-overlay:not(.hidden)');
                modals.forEach(modal => {
                    if (modal.id === 'template-modal') {
                        TemplateManager.closeTemplateModal();
                    } else if (modal.id === 'test-modal') {
                        TemplateManager.closeTestModal();
                    }
                });
            }

            // Ctrl/Cmd + N pour nouveau template
            if ((e.ctrlKey || e.metaKey) && e.key === 'n' && AppState.currentTab === 'templates') {
                e.preventDefault();
                TemplateManager.openTemplateModal();
            }

            // Ctrl/Cmd + S pour sauvegarder dans le modal
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                const templateModal = document.getElementById('template-modal');
                if (!templateModal.classList.contains('hidden')) {
                    e.preventDefault();
                    TemplateManager.saveTemplate();
                }
            }
        });

        // Auto-refresh des données toutes les 30 secondes pour le dashboard
        setInterval(() => {
            if (AppState.currentTab === 'dashboard') {
                DashboardManager.loadData();
            }
        }, 30000);

        // Gérer la visibilité de la page pour suspendre/reprendre l'auto-refresh
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // Page masquée - on peut arrêter les requêtes
                console.log('Page cachée - pause des mises à jour');
            } else {
                // Page visible - recharger les données
                console.log('Page visible - reprise des mises à jour');
                TabManager.loadTabData(AppState.currentTab);
            }
        });
    }
};

// Gestionnaire de thème (pour futures améliorations)
const ThemeManager = {
    init() {
        // Pour l'instant, on reste en dark mode
        // Mais on peut ajouter un toggle plus tard
        document.documentElement.classList.add('dark');
    }
};

// Helpers pour améliorer l'UX
const UXHelpers = {
    init() {
        // Ajouter des tooltips aux éléments avec title
        this.initTooltips();
        
        // Ajouter la validation en temps réel aux formulaires
        this.initFormValidation();
        
        // Ajouter l'auto-resize aux textareas
        this.initAutoResize();
    },

    initTooltips() {
        // Simple implémentation de tooltips natifs
        document.querySelectorAll('[title]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                // Les tooltips natifs sont suffisants pour maintenant
            });
        });
    },

    initFormValidation() {
        // Validation en temps réel pour les emails
        document.querySelectorAll('input[type="email"]').forEach(input => {
            input.addEventListener('blur', (e) => {
                const email = e.target.value;
                if (email && !this.isValidEmail(email)) {
                    e.target.classList.add('error');
                    this.showFieldError(e.target, 'Email invalide');
                } else {
                    e.target.classList.remove('error');
                    this.hideFieldError(e.target);
                }
            });
        });

        // Validation pour les champs requis
        document.querySelectorAll('input[required], textarea[required]').forEach(input => {
            input.addEventListener('blur', (e) => {
                if (!e.target.value.trim()) {
                    e.target.classList.add('error');
                    this.showFieldError(e.target, 'Ce champ est requis');
                } else {
                    e.target.classList.remove('error');
                    this.hideFieldError(e.target);
                }
            });
        });
    },

    initAutoResize() {
        document.querySelectorAll('textarea').forEach(textarea => {
            textarea.addEventListener('input', (e) => {
                e.target.style.height = 'auto';
                e.target.style.height = e.target.scrollHeight + 'px';
            });
        });
    },

    isValidEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    showFieldError(field, message) {
        // Supprimer l'erreur existante
        this.hideFieldError(field);
        
        // Créer l'élément d'erreur
        const errorElement = document.createElement('div');
        errorElement.className = 'form-error';
        errorElement.textContent = message;
        errorElement.setAttribute('data-field-error', '');
        
        // Insérer après le champ
        field.parentNode.insertBefore(errorElement, field.nextSibling);
    },

    hideFieldError(field) {
        const errorElement = field.parentNode.querySelector('[data-field-error]');
        if (errorElement) {
            errorElement.remove();
        }
    }
};

// Gestionnaire d'état pour la persistance locale
const StateManager = {
    init() {
        // Sauvegarder l'onglet actuel
        this.loadPersistedState();
        
        // Sauvegarder l'état quand on change d'onglet
        window.addEventListener('beforeunload', () => {
            this.savePersistedState();
        });
    },

    savePersistedState() {
        const state = {
            currentTab: AppState.currentTab,
            timestamp: Date.now()
        };
        
        try {
            localStorage.setItem('emailManagerState', JSON.stringify(state));
        } catch (error) {
            console.log('Impossible de sauvegarder l\'état local');
        }
    },

    loadPersistedState() {
        try {
            const saved = localStorage.getItem('emailManagerState');
            if (saved) {
                const state = JSON.parse(saved);
                // Ne restaurer que si la sauvegarde a moins de 24h
                if (Date.now() - state.timestamp < 24 * 60 * 60 * 1000) {
                    if (state.currentTab && state.currentTab !== 'dashboard') {
                        // Délai pour laisser le temps à la page de se charger
                        setTimeout(() => {
                            TabManager.switchTab(state.currentTab);
                        }, 100);
                    }
                }
            }
        } catch (error) {
            console.log('Impossible de charger l\'état local');
        }
    }
};

// Animation helpers
const AnimationHelpers = {
    // Fade in pour les éléments qui apparaissent
    fadeIn(element, duration = 300) {
        element.style.opacity = '0';
        element.style.transition = `opacity ${duration}ms ease-in-out`;
        
        requestAnimationFrame(() => {
            element.style.opacity = '1';
        });
        
        return new Promise(resolve => {
            setTimeout(resolve, duration);
        });
    },

    // Slide in pour les notifications
    slideIn(element, direction = 'right', duration = 300) {
        const transform = direction === 'right' ? 'translateX(100%)' : 'translateX(-100%)';
        element.style.transform = transform;
        element.style.transition = `transform ${duration}ms ease-out`;
        
        requestAnimationFrame(() => {
            element.style.transform = 'translateX(0)';
        });
        
        return new Promise(resolve => {
            setTimeout(resolve, duration);
        });
    }
};

// Initialization - Point d'entrée principal
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 Initialisation de l\'Email Manager Admin');

    // Vérifier l'authentification en premier
    const isAuthenticated = await AuthManager.checkAuth();
    if (!isAuthenticated) {
        return; // Arrêter l'initialisation si non authentifié
    }

    // Initialiser tous les gestionnaires
    TabManager.init();
    TemplateManager.init();
    AuthManager.init();
    GlobalEventManager.init();
    ThemeManager.init();
    UXHelpers.init();
    StateManager.init();

    // Charger les données initiales (dashboard par défaut)
    await DashboardManager.loadData();

    // Ajouter les styles d'animation CSS
    const animationStyles = document.createElement('style');
    animationStyles.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        
        .form-input.error {
            border-color: hsl(var(--destructive));
            box-shadow: 0 0 0 2px hsl(var(--destructive) / 0.2);
        }
        
        .font-semibold {
            font-weight: 600;
        }
        
        .flex {
            display: flex;
        }
        
        .flex-wrap {
            flex-wrap: wrap;
        }
        
        .items-center {
            align-items: center;
        }
        
        .gap-1 {
            gap: 0.25rem;
        }
        
        .gap-2 {
            gap: 0.5rem;
        }
        
        .w-24 {
            width: 6rem;
        }
        
        .h-2 {
            height: 0.5rem;
        }
        
        .bg-muted {
            background-color: hsl(var(--muted));
        }
        
        .bg-success {
            background-color: hsl(142.1 76.2% 36.3%);
        }
        
        .bg-warning {
            background-color: hsl(45.4 93.4% 47.5%);
        }
        
        .bg-destructive {
            background-color: hsl(var(--destructive));
        }
        
        .rounded-full {
            border-radius: 9999px;
        }
        
        .overflow-hidden {
            overflow: hidden;
        }
        
        .text-destructive {
            color: hsl(var(--destructive));
        }
        
        /* Responsive helpers */
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .flex {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .btn-sm {
                padding: 0.25rem 0.5rem;
                font-size: 0.75rem;
            }
        }
        
        /* Loading state improvements */
        .table tbody tr:has(.loading) {
            pointer-events: none;
            opacity: 0.7;
        }
        
        /* Smooth transitions */
        .tab-content {
            transition: opacity 0.2s ease-in-out;
        }
        
        .tab-content.hidden {
            opacity: 0;
        }
        
        /* Focus management */
        .modal input:first-of-type {
            background-color: hsl(var(--background));
        }
        
        /* Better text selection */
        .code {
            user-select: all;
        }
        
        /* Print styles */
        @media print {
            .header, .nav, .modal-overlay, .btn {
                display: none !important;
            }
            
            .container {
                max-width: none;
                padding: 0;
            }
            
            .card {
                box-shadow: none;
                border: 1px solid #ccc;
                break-inside: avoid;
            }
        }
    `;
    document.head.appendChild(animationStyles);

    console.log('✅ Email Manager Admin initialisé avec succès');
});

// Gestion des erreurs globales
window.addEventListener('unhandledrejection', (event) => {
    console.error('Erreur non gérée:', event.reason);
    Utils.showNotification('Une erreur inattendue s\'est produite', 'error');
});

window.addEventListener('error', (event) => {
    console.error('Erreur JavaScript:', event.error);
    Utils.showNotification('Erreur JavaScript détectée', 'error');
});

// Export des gestionnaires pour débogage en développement
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.EmailManagerDebug = {
        AppState,
        Utils,
        API,
        TabManager,
        DashboardManager,
        TemplateManager,
        LogManager,
        StatsManager,
        AuthManager
    };
}