import { Request, Response, NextFunction } from 'express';

export const authenticateAdmin = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    console.log('🔍 Vérification d\'authentification admin');
    const authHeader = req.headers.authorization;
    const token = req.session?.adminToken;

    console.log('- Token dans session:', token ? token.substring(0, 8) + '...' : 'aucun');
    console.log('- Token dans header:', authHeader ? authHeader.substring(0, 15) + '...' : 'aucun');

    if (!authHeader && !token) {
      console.log('❌ Authentification échouée: Aucun token');
      res.status(401).json({ 
        success: false, 
        error: 'Token d\'authentification requis' 
      });
      return;
    }

    // Vérifier le token dans l'en-tête Authorization
    let sessionToken = token;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      sessionToken = authHeader.substring(7);
      console.log('- Utilisation du token du header');
    }

    if (!sessionToken) {
      console.log('❌ Authentification échouée: Token invalide');
      res.status(401).json({ 
        success: false, 
        error: 'Token invalide' 
      });
      return;
    }

    // Vérifier la session dans la base de données
    console.log('- Recherche du token dans la BDD:', sessionToken.substring(0, 8) + '...');
    const session = await req.db.getSession(sessionToken);
    if (!session) {
      // Nettoyer la session expirée
      console.log('❌ Authentification échouée: Session non trouvée');
      if (req.session?.adminToken) {
        req.session.destroy((err) => {
          if (err) console.error('Erreur lors de la destruction de la session:', err);
        });
      }
      
      res.status(401).json({ 
        success: false, 
        error: 'Session expirée ou invalide' 
      });
      return;
    }

    // Vérifier si la session n'est pas expirée
    if (session.expiresAt < new Date()) {
      console.log('❌ Authentification échouée: Session expirée');
      await req.db.deleteSession(sessionToken);
      
      if (req.session?.adminToken) {
        req.session.destroy((err) => {
          if (err) console.error('Erreur lors de la destruction de la session:', err);
        });
      }
      
      res.status(401).json({ 
        success: false, 
        error: 'Session expirée' 
      });
      return;
    }

    // Mettre à jour le token de session si nécessaire
    if (!req.session?.adminToken && sessionToken) {
      req.session!.adminToken = sessionToken;
    }

    console.log('✅ Authentification réussie');
    next();
  } catch (error) {
    console.error('❌ Erreur d\'authentification admin:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erreur interne du serveur' 
    });
  }
};