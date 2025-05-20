import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { CreateTemplateRequest, UpdateTemplateRequest, EmailTemplate, ApiResponse } from '../types';

const router = Router();

// Obtenir tous les templates
router.get('/', async (req: Request, res: Response) => {
  try {
    const templates = await req.db.getAllTemplates();
    
    res.json({
      success: true,
      data: templates
    } as ApiResponse<EmailTemplate[]>);

  } catch (error) {
    console.error('Erreur lors de la récupération des templates:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des templates'
    } as ApiResponse);
  }
});

// Obtenir un template par ID
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const template = await req.db.getTemplate(id);

    if (!template) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    res.json({
      success: true,
      data: template
    } as ApiResponse<EmailTemplate>);

  } catch (error) {
    console.error('Erreur lors de la récupération du template:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération du template'
    } as ApiResponse);
  }
});

// Créer un nouveau template
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, subject, html, fromEmail }: CreateTemplateRequest = req.body;

    // Validation des données
    if (!name || !subject || !html) {
      res.status(400).json({
        success: false,
        error: 'Nom, sujet et contenu HTML sont requis'
      } as ApiResponse);
      return;
    }

    // Extraire les paramètres du template HTML
    const paramRegex = /\{\{(\w+)\}\}/g;
    const params: string[] = [];
    let match;
    
    while ((match = paramRegex.exec(html)) !== null) {
      if (!params.includes(match[1])) {
        params.push(match[1]);
      }
    }

    // Créer le template
    const template: Omit<EmailTemplate, 'createdAt' | 'updatedAt'> = {
      id: uuidv4(),
      name,
      subject,
      html,
      fromEmail,
      params
    };

    await req.db.createTemplate(template);

    res.status(201).json({
      success: true,
      data: template,
      message: 'Template créé avec succès'
    } as ApiResponse<Omit<EmailTemplate, 'createdAt' | 'updatedAt'>>);

  } catch (error) {
    console.error('Erreur lors de la création du template:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la création du template'
    } as ApiResponse);
  }
});

// Mettre à jour un template
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { name, subject, html, fromEmail }: UpdateTemplateRequest = req.body;

    // Vérifier que le template existe
    const existingTemplate = await req.db.getTemplate(id);
    if (!existingTemplate) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    // Validation des données
    if (!name || !subject || !html) {
      res.status(400).json({
        success: false,
        error: 'Nom, sujet et contenu HTML sont requis'
      } as ApiResponse);
      return;
    }

    // Extraire les paramètres du nouveau template HTML
    const paramRegex = /\{\{(\w+)\}\}/g;
    const params: string[] = [];
    let match;
    
    while ((match = paramRegex.exec(html)) !== null) {
      if (!params.includes(match[1])) {
        params.push(match[1]);
      }
    }

    // Mettre à jour le template
    const updatedTemplate: EmailTemplate = {
      ...existingTemplate,
      name,
      subject,
      html,
      fromEmail,
      params,
      updatedAt: new Date()
    };

    await req.db.updateTemplate(updatedTemplate);

    res.json({
      success: true,
      data: updatedTemplate,
      message: 'Template mis à jour avec succès'
    } as ApiResponse<EmailTemplate>);

  } catch (error) {
    console.error('Erreur lors de la mise à jour du template:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la mise à jour du template'
    } as ApiResponse);
  }
});

// Supprimer un template
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    // Vérifier que le template existe
    const existingTemplate = await req.db.getTemplate(id);
    if (!existingTemplate) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    await req.db.deleteTemplate(id);

    res.json({
      success: true,
      message: 'Template supprimé avec succès'
    } as ApiResponse);

  } catch (error) {
    console.error('Erreur lors de la suppression du template:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la suppression du template'
    } as ApiResponse);
  }
});

// Obtenir les statistiques d'un template
router.get('/:id/stats', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    // Vérifier que le template existe
    const template = await req.db.getTemplate(id);
    if (!template) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    const stats = await req.db.getTemplateStats(id);
    
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

// Obtenir les logs d'un template
router.get('/:id/logs', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;
    
    // Vérifier que le template existe
    const template = await req.db.getTemplate(id);
    if (!template) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    const logs = await req.db.getEmailLogs(id, limit);
    
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

export default router;