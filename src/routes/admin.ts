import { Router, Request, Response } from 'express';
import path from 'path';
import { ApiResponse } from '../types';
import { authenticateAdmin } from '../middleware/auth';

const router = Router();

// Routes publiques (pas de middleware auth)
// Servir la page de connexion
router.get('/login', (req: Request, res: Response) => {
  res.sendFile(path.join(process.cwd(), 'public', 'login.html'));
});

// Servir la page d'administration (vérification côté client)
router.get('/', (req: Request, res: Response) => {
  // Servir la page admin HTML - l'authentification sera vérifiée côté client
  res.sendFile(path.join(process.cwd(), 'public', 'admin.html'));
});

// Routes API protégées (avec middleware auth)
// API pour obtenir les statistiques du tableau de bord
router.get('/api/dashboard', authenticateAdmin, async (req: Request, res: Response) => {
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
router.get('/api/logs', authenticateAdmin, async (req: Request, res: Response) => {
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
router.get('/api/stats', authenticateAdmin, async (req: Request, res: Response) => {
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