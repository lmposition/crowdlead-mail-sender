import express from 'express';
import session from 'express-session';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { Database } from './database';
import { DatabaseConfig } from './types';
import { authenticateAdmin } from './middleware/auth';
import { validateApiKey } from './middleware/apiKey';

// Routes
import authRoutes from './routes/auth';
import templateRoutes from './routes/templates';
import emailRoutes from './routes/emails';
import adminRoutes from './routes/admin';

// Charger les variables d'environnement
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration de la base de données
const dbConfig: DatabaseConfig = {
  type: process.env.DATABASE_URL?.startsWith('postgres') ? 'postgres' : 'sqlite',
  url: process.env.DATABASE_URL || 'sqlite:./database.db'
};

// Initialisation de la base de données
const database = new Database(dbConfig);

// Middleware pour injecter la DB dans les requêtes
app.use((req, res, next) => {
  req.db = database;
  next();
});

// Middleware global
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.FRONTEND_URL, /\.railway\.app$/].filter(Boolean)
    : true,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configuration des sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 heures
  }
}));

// Servir les fichiers statiques
app.use(express.static(path.join(process.cwd(), 'public')));

// Routes publiques pour l'envoi d'emails (avec clé API)
app.use('/email', validateApiKey, emailRoutes);

// Routes d'authentification admin
app.use('/admin', authRoutes);

// Routes admin protégées
app.use('/admin', authenticateAdmin, adminRoutes);

// Routes API admin protégées
app.use('/api/templates', authenticateAdmin, templateRoutes);

// Route de health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Redirection de la racine vers l'admin
app.get('/', (req, res) => {
  res.redirect('/admin');
});

// Gestion des erreurs 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route non trouvée'
  });
});

// Gestion globale des erreurs
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Erreur serveur:', err);
  
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' 
      ? 'Erreur interne du serveur'
      : err.message
  });
});

// Initialisation du serveur
async function startServer() {
  try {
    // Initialiser les tables de la base de données
    await database.initTables();
    console.log('✅ Base de données initialisée');

    // Nettoyer les sessions expirées au démarrage
    await database.cleanupExpiredSessions();
    console.log('✅ Sessions expirées nettoyées');

    // Démarrer le serveur
    app.listen(PORT, () => {
      console.log('🚀 Serveur Email Manager démarré');
      console.log(`📧 API disponible sur http://localhost:${PORT}`);
      console.log(`🔧 Interface admin sur http://localhost:${PORT}/admin`);
      console.log(`💾 Base de données: ${dbConfig.type} (${dbConfig.url})`);
      console.log(`🌍 Environnement: ${process.env.NODE_ENV || 'development'}`);
    });

    // Nettoyer les sessions expirées toutes les heures
    setInterval(async () => {
      try {
        await database.cleanupExpiredSessions();
        console.log('✅ Sessions expirées nettoyées automatiquement');
      } catch (error) {
        console.error('❌ Erreur lors du nettoyage des sessions:', error);
      }
    }, 60 * 60 * 1000); // 1 heure

  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error);
    process.exit(1);
  }
}

// Gestion propre de l'arrêt du serveur
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur...');
  
  try {
    await database.close();
    console.log('✅ Connexion base de données fermée');
    process.exit(0);
  } catch (error) {
    console.error('❌ Erreur lors de la fermeture:', error);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Signal SIGTERM reçu, arrêt du serveur...');
  
  try {
    await database.close();
    console.log('✅ Connexion base de données fermée');
    process.exit(0);
  } catch (error) {
    console.error('❌ Erreur lors de la fermeture:', error);
    process.exit(1);
  }
});

// Démarrer le serveur
startServer();