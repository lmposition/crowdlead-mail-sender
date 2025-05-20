#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Dossiers requis
const requiredDirs = [
  'src',
  'src/@types',
  'src/middleware',
  'src/routes',
  'public',
  'dist'
];

console.log('🔧 Vérification de la structure du projet...');

let allDirsExist = true;

requiredDirs.forEach(dir => {
  const dirPath = path.join(process.cwd(), dir);
  if (!fs.existsSync(dirPath)) {
    console.log(`📁 Création du dossier: ${dir}`);
    fs.mkdirSync(dirPath, { recursive: true });
    allDirsExist = false;
  }
});

if (allDirsExist) {
  console.log('✅ Tous les dossiers requis existent déjà.');
} else {
  console.log('✅ Structure du projet créée avec succès.');
}

// Vérifier les fichiers .env
if (!fs.existsSync('.env')) {
  if (fs.existsSync('.env.example')) {
    console.log('📄 Fichier .env manquant. Copiez .env.example vers .env et configurez-le.');
  } else {
    console.log('⚠️  Fichier .env.example manquant.');
  }
} else {
  console.log('✅ Fichier .env trouvé.');
}

console.log('\n🚀 Prêt à démarrer le projet !');
console.log('Prochaines étapes:');
console.log('1. npm install');
console.log('2. Configurez votre fichier .env');
console.log('3. npm run build');
console.log('4. npm start ou npm run dev');