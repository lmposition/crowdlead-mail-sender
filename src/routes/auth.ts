import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { LoginRequest, ApiResponse } from '../types';

const router = Router();

// Login admin
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { password }: LoginRequest = req.body;

    if (!password) {
      res.status(400).json({
        success: false,
        error: 'Mot de passe requis'
      } as ApiResponse);
      return;
    }

    // Vérifier le mot de passe admin
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword) {
      res.status(500).json({
        success: false,
        error: 'Configuration serveur invalide'
      } as ApiResponse);
      return;
    }

    // Comparer le mot de passe (en mode développement, comparaison directe)
    let isValidPassword = false;
    
    if (process.env.NODE_ENV === 'development') {
      isValidPassword = password === adminPassword;
    } else {
      // En production, utiliser bcrypt si le mot de passe est déjà hashé
      try {
        isValidPassword = await bcrypt.compare(password, adminPassword);
      } catch {
        // Si la comparaison échoue, essayer une comparaison directe
        isValidPassword = password === adminPassword;
      }
    }

    if (!isValidPassword) {
      res.status(401).json({
        success: false,
        error: 'Mot de passe incorrect'
      } as ApiResponse);
      return;
    }

    // Générer un token de session
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // Expire dans 24h

    // Sauvegarder la session
    await req.db.createSession(token, expiresAt);

    // Stocker le token dans la session Express
    req.session!.adminToken = token;

    res.json({
      success: true,
      data: {
        token,
        expiresAt: expiresAt.toISOString()
      },
      message: 'Connexion réussie'
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur'
    } as ApiResponse);
  }
});

// Logout admin
router.post('/logout', async (req: Request, res: Response) => {
  try {
    const token = req.session?.adminToken;

    if (token) {
      // Supprimer la session de la base de données
      await req.db.deleteSession(token);
    }

    // Détruire la session Express
    req.session!.destroy((err) => {
      if (err) {
        console.error('Erreur lors de la destruction de la session:', err);
        res.status(500).json({
          success: false,
          error: 'Erreur lors de la déconnexion'
        } as ApiResponse);
        return;
      }

      res.json({
        success: true,
        message: 'Déconnexion réussie'
      } as ApiResponse);
    });

  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur'
    } as ApiResponse);
  }
});

// Vérifier l'état de la session
router.get('/check', async (req: Request, res: Response) => {
  try {
    const token = req.session?.adminToken;

    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Aucune session active'
      } as ApiResponse);
      return;
    }

    const session = await req.db.getSession(token);
    
    if (!session || session.expiresAt < new Date()) {
      res.status(401).json({
        success: false,
        error: 'Session expirée'
      } as ApiResponse);
      return;
    }

    res.json({
      success: true,
      data: {
        authenticated: true,
        expiresAt: session.expiresAt.toISOString()
      }
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la vérification de session:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur'
    } as ApiResponse);
  }
});

export default router;