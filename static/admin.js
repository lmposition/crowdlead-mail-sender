// Gestion des statistiques
const stats = {
    // Charger les stats pour tous les templates
    loadAll: async () => {
        utils.toggleLoading('statsLoading', true);
        
        const container = document.getElementById('statsContainer');
        if (!container) return;

        if (currentTemplates.length === 0) {
            container.innerHTML = `
                <div class="alert" style="background-color: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-secondary);">
                    📊 Aucune statistique disponible. Créez d'abord des templates et envoyez des emails.
                </div>
            `;
            utils.toggleLoading('statsLoading', false);
            return;
        }

        try {
            const statsPromises = currentTemplates.map(template => 
                stats.loadForTemplate(template.id, true)
            );

            const allStats = await Promise.all(statsPromises);
            
            container.innerHTML = currentTemplates.map((template, index) => {
                const templateStats = allStats[index];
                const successRate = templateStats.total_sent > 0 
                    ? Math.round((templateStats.total_success / templateStats.total_sent) * 100)
                    : 0;

                const lastSentText = templateStats.last_sent_at 
                    ? new Date(templateStats.last_sent_at).toLocaleString('fr-FR')
                    : 'Jamais';

                return `
                    <div class="template-item" data-stats-id="${template.id}">
                        <h3>📧 ${utils.escapeHtml(template.name)} <code>(${template.id})</code></h3>
                        
                        <div class="stats-grid">
                            <div class="stats-card">
                                <div class="stats-number">${templateStats.total_sent}</div>
                                <div class="stats-label">Total envoyés</div>
                            </div>
                            <div class="stats-card">
                                <div class="stats-number" style="color: var(--accent-green);">${templateStats.total_success}</div>
                                <div class="stats-label">Succès</div>
                            </div>
                            <div class="stats-card">
                                <div class="stats-number" style="color: var(--accent-red);">${templateStats.total_failed}</div>
                                <div class="stats-label">Échecs</div>
                            </div>
                            <div class="stats-card">
                                <div class="stats-number" style="color: ${successRate >= 80 ? 'var(--accent-green)' : successRate >= 50 ? 'var(--accent-orange)' : 'var(--accent-red)'};">
                                    ${successRate}%
                                </div>
                                <div class="stats-label">Taux de succès</div>
                            </div>
                        </div>

                        <p style="color: var(--text-secondary); margin-top: 16px;">
                            <strong>Dernier envoi:</strong> ${lastSentText}
                        </p>
                    </div>
                `;
            }).join('');

        } catch (error) {
            console.error('Erreur chargement stats:', error);
            container.innerHTML = `
                <div class="alert alert-error">
                    ❌ Erreur lors du chargement des statistiques: ${error.message}
                </div>
            `;
        } finally {
            utils.toggleLoading('statsLoading', false);
        }
    },

    // Charger les stats pour un template spécifique
    loadForTemplate: async (templateId, returnData = false) => {
        try {
            const data = await utils.apiRequest(`${ENDPOINTS.stats}/${encodeURIComponent(templateId)}`);
            
            if (returnData) {
                return data;
            }

            // Mettre à jour l'affichage dans la liste des templates
            const statsElement = document.getElementById(`stats-${templateId}`);
            if (statsElement) {
                statsElement.innerHTML = `${data.total_sent} envoyés (${data.total_success} ✅)`;
            }

            return data;
        } catch (error) {
            console.error(`Erreur stats pour template ${templateId}:`, error);
            
            if (returnData) {
                return { total_sent: 0, total_success: 0, total_failed: 0, last_sent_at: null };
            }

            const statsElement = document.getElementById(`stats-${templateId}`);
            if (statsElement) {
                statsElement.innerHTML = 'Erreur';
            }
        }
    }
};

// Gestion des tests d'emails
const emailTesting = {
    // Mettre à jour les champs de paramètres selon le template sélectionné
    updateParamInputs: () => {
        const templateId = document.getElementById('testTemplateId').value;
        const paramInputsDiv = document.getElementById('paramInputs');
        
        if (!paramInputsDiv) return;

        if (!templateId) {
            paramInputsDiv.innerHTML = '';
            return;
        }

        const template = currentTemplates.find(t => t.id === templateId);
        if (!template || !template.params) {
            paramInputsDiv.innerHTML = '';
            return;
        }

        paramInputsDiv.innerHTML = template.params.map(param => `
            <div class="param-input">
                <label for="param_${param}">Paramètre: ${param} *</label>
                <input type="text" id="param_${param}" data-param="${param}" placeholder="Valeur pour ${param}" required>
            </div>
        `).join('');
    },

    // Envoyer un email de test
    send: async (formData) => {
        try {
            const emailData = { to: formData.email.trim() };

            // Ajouter tous les paramètres
            const paramInputs = document.querySelectorAll('#paramInputs input[data-param]');
            paramInputs.forEach(input => {
                const paramName = input.getAttribute('data-param');
                const paramValue = input.value.trim();
                if (!paramValue) {
                    throw new Error(`Le paramètre "${paramName}" est requis`);
                }
                emailData[paramName] = paramValue;
            });

            console.log('Envoi email de test:', emailData);

            await utils.apiRequest(`${ENDPOINTS.email}/${encodeURIComponent(formData.templateId)}`, {
                method: 'POST',
                headers: {
                    'X-API-Key': document.getElementById('apiKey').textContent.trim()
                },
                body: JSON.stringify(emailData)
            });

            utils.showMessage('testEmailMessage', `Email envoyé avec succès à ${formData.email} !`);
            
            // Vider le formulaire
            document.getElementById('testEmailForm').reset();
            emailTesting.updateParamInputs();
            
            // Recharger les templates pour mettre à jour les stats
            setTimeout(() => templates.load(), 1000);

        } catch (error) {
            console.error('Erreur envoi email:', error);
            utils.showMessage('testEmailMessage', error.message, true);
        }
    }
};

// Fonctions utilitaires globales
function showTab(tabName) {
    tabs.show(tabName);
}

function copyApiKey() {
    const apiKey = document.getElementById('apiKey').textContent.trim();
    
    // Méthode moderne
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(apiKey)
            .then(() => {
                // Animation de succès
                const button = event.target.closest('.btn');
                const originalContent = button.innerHTML;
                button.innerHTML = '<span>✅</span> Copié !';
                button.style.backgroundColor = 'var(--accent-green)';
                
                setTimeout(() => {
                    button.innerHTML = originalContent;
                    button.style.backgroundColor = '';
                }, 2000);
            })
            .catch(err => {
                console.error('Erreur copie clipboard:', err);
                fallbackCopy(apiKey);
            });
    } else {
        fallbackCopy(apiKey);
    }
}

function fallbackCopy(text) {
    // Méthode de fallback
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-9999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            alert('✅ Clé API copiée dans le presse-papiers !');
        } else {
            throw new Error('Copie échouée');
        }
    } catch (err) {
        console.error('Erreur de copie:', err);
        prompt('Copiez manuellement cette clé API:', text);
    } finally {
        document.body.removeChild(textArea);
    }
}

function logout() {
    if (confirm('Êtes-vous sûr de vouloir vous déconnecter ?')) {
        fetch('/admin/logout', { method: 'POST' })
            .then(() => {
                window.location.href = '/admin/login';
            })
            .catch(error => {
                console.error('Erreur logout:', error);
                window.location.href = '/admin/login';
            });
    }
}

// Gestionnaires d'événements
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initialisation de l\'interface admin...');
    
    // Charger les templates au démarrage
    templates.load();
    
    // Gestionnaire pour le formulaire d'ajout de template
    const addForm = document.getElementById('addTemplateForm');
    if (addForm) {
        addForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const button = this.querySelector('button[type="submit"]');
            const buttonText = document.getElementById('addButtonText');
            const formData = new FormData(this);
            
            // État de chargement
            button.disabled = true;
            buttonText.textContent = 'Ajout en cours...';
            
            try {
                await templates.add({
                    id: formData.get('templateId') || document.getElementById('templateId').value,
                    name: formData.get('templateName') || document.getElementById('templateName').value,
                    subject: formData.get('templateSubject') || document.getElementById('templateSubject').value,
                    html: formData.get('templateHTML') || document.getElementById('templateHTML').value,
                    params: formData.get('templateParams') || document.getElementById('templateParams').value,
                    fromEmail: formData.get('templateFromEmail') || document.getElementById('templateFromEmail').value
                });
            } finally {
                button.disabled = false;
                buttonText.textContent = 'Ajouter Template';
            }
        });
    }
    
    // Gestionnaire pour le formulaire de test d'email
    const testForm = document.getElementById('testEmailForm');
    if (testForm) {
        testForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const button = this.querySelector('button[type="submit"]');
            const buttonText = document.getElementById('testButtonText');
            const formData = new FormData(this);
            
            // État de chargement
            button.disabled = true;
            buttonText.textContent = 'Envoi en cours...';
            
            try {
                await emailTesting.send({
                    templateId: formData.get('testTemplateId') || document.getElementById('testTemplateId').value,
                    email: formData.get('testEmail') || document.getElementById('testEmail').value
                });
            } finally {
                button.disabled = false;
                buttonText.textContent = 'Envoyer Test';
            }
        });
    }
    
    // Gestionnaire pour le changement de template dans les tests
    const templateSelect = document.getElementById('testTemplateId');
    if (templateSelect) {
        templateSelect.addEventListener('change', emailTesting.updateParamInputs);
    }
    
    // Gestionnaires pour les onglets
    document.querySelectorAll('.tab').forEach((tab, index) => {
        tab.addEventListener('click', function() {
            const tabName = index === 0 ? 'templates' : 'stats';
            tabs.show(tabName);
        });
    });
    
    console.log('✅ Interface admin initialisée');
});