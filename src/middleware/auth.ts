import { Request, Response, NextFunction } from 'express';
import { Database } from '../database';

declare global {
  namespace Express {
    interface Request {
      db: Database;
    }
  }
}

export const authenticateAdmin = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = req.session?.adminToken;

    if (!authHeader && !token) {
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
    }

    if (!sessionToken) {
      res.status(401).json({ 
        success: false, 
        error: 'Token invalide' 
      });
      return;
    }

    // Vérifier la session dans la base de données
    const session = await req.db.getSession(sessionToken);
    if (!session) {
      // Nettoyer la session expirée
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

    next();
  } catch (error) {
    console.error('Erreur d\'authentification admin:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erreur interne du serveur' 
    });
  }
};