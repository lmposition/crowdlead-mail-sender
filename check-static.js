#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔍 Vérification des fichiers statiques pour Email Manager\n');

// Vérifier le dossier public
const publicDir = path.join(process.cwd(), 'public');
console.log(`Dossier public: ${publicDir}`);
console.log(`Existe: ${fs.existsSync(publicDir) ? '✅' : '❌'}`);

if (fs.existsSync(publicDir)) {
  const files = fs.readdirSync(publicDir);
  console.log(`\nFichiers dans le dossier public (${files.length}):`);
  
  files.forEach(file => {
    const filePath = path.join(publicDir, file);
    const stats = fs.statSync(filePath);
    const size = stats.size / 1024; // en Ko
    console.log(`- ${file} (${size.toFixed(2)} Ko)`);
    
    if (file === 'style.css') {
      console.log(`  📄 Contenu CSS (premiers 200 caractères):`);
      const cssContent = fs.readFileSync(filePath, 'utf8');
      console.log(`  "${cssContent.substring(0, 200)}..."`);
    }
  });
}

// Vérifier les chemins dans les fichiers HTML
console.log('\n🔍 Analyse des liens dans les fichiers HTML:');

const loginHtml = path.join(publicDir, 'login.html');
if (fs.existsSync(loginHtml)) {
  const content = fs.readFileSync(loginHtml, 'utf8');
  
  // Rechercher les liens CSS
  const cssLinks = content.match(/<link[^>]*rel="stylesheet"[^>]*>/g) || [];
  console.log(`\nCSS dans login.html (${cssLinks.length}):`);
  cssLinks.forEach(link => {
    console.log(`- ${link}`);
  });
}

const adminHtml = path.join(publicDir, 'admin.html');
if (fs.existsSync(adminHtml)) {
  const content = fs.readFileSync(adminHtml, 'utf8');
  
  // Rechercher les liens CSS
  const cssLinks = content.match(/<link[^>]*rel="stylesheet"[^>]*>/g) || [];
  console.log(`\nCSS dans admin.html (${cssLinks.length}):`);
  cssLinks.forEach(link => {
    console.log(`- ${link}`);
  });
  
  // Rechercher les liens JS
  const jsLinks = content.match(/<script[^>]*src="[^"]*"[^>]*>/g) || [];
  console.log(`\nJS dans admin.html (${jsLinks.length}):`);
  jsLinks.forEach(link => {
    console.log(`- ${link}`);
  });
}

console.log('\n🚀 Suggestions de correction:');
console.log('1. Assurez-vous que style.css est bien dans le dossier public');
console.log('2. Assurez-vous que les chemins dans les balises <link> sont corrects (href="style.css" et non href="/style.css")');
console.log('3. Vérifiez que le middleware express.static est correctement configuré');
console.log('4. Redémarrez le serveur après avoir effectué les corrections');

console.log('\n✅ Diagnostic terminé!');

// Tenter de créer un fichier CSS de base si absent
if (!fs.existsSync(path.join(publicDir, 'style.css'))) {
  console.log('\n⚠️ style.css manquant, création d\'un fichier CSS de base...');
  
  const basicCss = `
/* Style CSS de base pour Email Manager */
:root {
  --background: 224 71.4% 4.1%;
  --foreground: 210 20% 98%;
}

body {
  font-family: sans-serif;
  background-color: #1a1b1e;
  color: #e6e6e6;
  margin: 0;
  padding: 20px;
}

.card {
  background-color: #2a2b2e;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
}

.btn {
  background-color: #3a3b3e;
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
}

.btn-primary {
  background-color: #7c3aed;
}
`;
  
  try {
    fs.writeFileSync(path.join(publicDir, 'style.css'), basicCss);
    console.log('✅ Fichier CSS de base créé avec succès!');
  } catch (error) {
    console.error('❌ Erreur lors de la création du fichier CSS:', error);
  }
}