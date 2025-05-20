#!/usr/bin/env node

console.log('🔍 Diagnostic TypeScript du projet Email Manager\n');

// Vérifier la structure des fichiers
const fs = require('fs');
const path = require('path');

const files = [
  'src/types.ts',
  'src/database.ts',
  'src/server.ts',
  'src/middleware/auth.ts',
  'src/middleware/apiKey.ts',
  'src/routes/auth.ts',
  'src/routes/admin.ts',
  'src/routes/emails.ts',
  'src/routes/templates.ts',
  'src/@types/express.d.ts',
  'src/utils/db.ts',
  'src/utils/index.ts',
  'tsconfig.json',
  'package.json'
];

console.log('📁 Vérification des fichiers:');
files.forEach(file => {
  const exists = fs.existsSync(file);
  console.log(`${exists ? '✅' : '❌'} ${file}`);
});

console.log('\n📦 Vérification des dossiers:');
const dirs = [
  'src',
  'src/@types',
  'src/middleware',
  'src/routes',
  'src/utils',
  'public',
  'dist'
];

dirs.forEach(dir => {
  const exists = fs.existsSync(dir);
  console.log(`${exists ? '✅' : '❌'} ${dir}/`);
});

console.log('\n🔧 Vérification de la configuration TypeScript:');
try {
  const tsconfig = JSON.parse(fs.readFileSync('tsconfig.json', 'utf8'));
  console.log('✅ tsconfig.json valide');
  console.log(`✅ Target: ${tsconfig.compilerOptions.target}`);
  console.log(`✅ Module: ${tsconfig.compilerOptions.module}`);
  console.log(`✅ Strict: ${tsconfig.compilerOptions.strict}`);
} catch (error) {
  console.log('❌ Erreur dans tsconfig.json:', error.message);
}

console.log('\n🏃 Commandes suggérées:');
console.log('npm run type-check  # Vérifier les types sans compiler');
console.log('npm run build       # Compiler le projet');
console.log('npm run dev         # Démarrer en mode développement');