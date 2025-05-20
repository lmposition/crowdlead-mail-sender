import { Router, Request, Response } from 'express';
import path from 'path';
import { ApiResponse } from '../types';

const router = Router();

// Servir la page de connexion
router.get('/login', (req: Request, res: Response) => {
  res.sendFile(path.join(process.cwd(), 'public', 'login.html'));
});

// Servir la page d'administration (protégée)
router.get('/', async (req: Request, res: Response) => {
  try {
    // Vérifier si l'utilisateur est connecté
    const token = req.session?.adminToken;
    
    if (!token) {
      res.redirect('/admin/login');
      return;
    }

    // Vérifier la validité de la session
    const session = await req.db.getSession(token);
    if (!session || session.expiresAt < new Date()) {
      req.session!.destroy((err) => {
        if (err) console.error('Erreur lors de la destruction de la session:', err);
      });
      res.redirect('/admin/login');
      return;
    }

    res.sendFile(path.join(process.cwd(), 'public', 'admin.html'));
  } catch (error) {
    console.error('Erreur lors de l\'accès à l\'admin:', error);
    res.redirect('/admin/login');
  }
});

// API pour obtenir les statistiques du tableau de bord
router.get('/api/dashboard', async (req: Request, res: Response) => {
  try {
    const stats = await req.db.getDashboardStats();
    
    res.json({
      success: true,
      data: stats
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des statistiques'
    } as ApiResponse);
  }
});

// API pour obtenir tous les logs
router.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const logs = await req.db.getEmailLogs(undefined, limit);
    
    res.json({
      success: true,
      data: logs
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la récupération des logs:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des logs'
    } as ApiResponse);
  }
});

// API pour obtenir toutes les statistiques
router.get('/api/stats', async (req: Request, res: Response) => {
  try {
    const stats = await req.db.getAllStats();
    
    res.json({
      success: true,
      data: stats
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des statistiques'
    } as ApiResponse);
  }
});

export default router;