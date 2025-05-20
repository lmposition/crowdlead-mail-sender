import { Router, Request, Response } from 'express';
import { Resend } from 'resend';
import { SendEmailRequest, ApiResponse } from '../types';

const router = Router();
const resend = new Resend(process.env.RESEND_API_KEY);

// Fonction pour remplacer les paramètres dans le template
function replaceTemplateParams(content: string, params: Record<string, any>): string {
  let result = content;
  
  for (const [key, value] of Object.entries(params)) {
    const regex = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    result = result.replace(regex, String(value));
  }
  
  return result;
}

// Envoyer un email via un template
router.post('/:templateId', async (req: Request, res: Response) => {
  try {
    const { templateId } = req.params;
    const { to, cc, bcc, ...templateParams }: SendEmailRequest = req.body;

    // Validation de base
    if (!to) {
      res.status(400).json({
        success: false,
        error: 'Destinataire requis'
      } as ApiResponse);
      return;
    }

    // Récupérer le template
    const template = await req.db.getTemplate(templateId);
    if (!template) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    // Vérifier que tous les paramètres requis sont fournis
    const missingParams = template.params.filter((param: string) => 
      templateParams[param] === undefined || templateParams[param] === null
    );

    if (missingParams.length > 0) {
      res.status(400).json({
        success: false,
        error: `Paramètres manquants: ${missingParams.join(', ')}`
      } as ApiResponse);
      return;
    }

    // Remplacer les paramètres dans le sujet et le contenu
    const subject = replaceTemplateParams(template.subject, templateParams);
    const html = replaceTemplateParams(template.html, templateParams);

    // Préparer l'email
    const emailData: any = {
      from: template.fromEmail || process.env.FROM_EMAIL,
      to: Array.isArray(to) ? to : [to],
      subject,
      html
    };

    // Ajouter CC et BCC si fournis
    if (cc) {
      emailData.cc = Array.isArray(cc) ? cc : [cc];
    }
    if (bcc) {
      emailData.bcc = Array.isArray(bcc) ? bcc : [bcc];
    }

    // Envoyer l'email via Resend
    try {
      const result = await resend.emails.send(emailData);

      // Logger le succès
      await req.db.createEmailLog({
        templateId,
        recipientEmail: Array.isArray(to) ? to.join(', ') : to,
        subject,
        status: 'success'
      });

      res.json({
        success: true,
        data: {
          emailId: result.data?.id,
          templateId,
          recipient: to,
          subject
        },
        message: 'Email envoyé avec succès'
      } as ApiResponse);

    } catch (resendError: any) {
      console.error('Erreur Resend:', resendError);

      // Logger l'échec
      await req.db.createEmailLog({
        templateId,
        recipientEmail: Array.isArray(to) ? to.join(', ') : to,
        subject,
        status: 'failed',
        errorMessage: resendError.message || 'Erreur Resend inconnue'
      });

      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'envoi de l\'email',
        message: process.env.NODE_ENV === 'development' ? resendError.message : undefined
      } as ApiResponse);
    }

  } catch (error) {
    console.error('Erreur lors de l\'envoi de l\'email:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur'
    } as ApiResponse);
  }
});

// Envoyer un email de test (pour l'admin)
router.post('/:templateId/test', async (req: Request, res: Response) => {
  try {
    const { templateId } = req.params;
    const { to, ...templateParams }: SendEmailRequest = req.body;

    // Validation de base
    if (!to) {
      res.status(400).json({
        success: false,
        error: 'Destinataire requis pour le test'
      } as ApiResponse);
      return;
    }

    // Récupérer le template
    const template = await req.db.getTemplate(templateId);
    if (!template) {
      res.status(404).json({
        success: false,
        error: 'Template non trouvé'
      } as ApiResponse);
      return;
    }

    // Utiliser des valeurs par défaut pour les paramètres manquants
    const testParams: Record<string, any> = {};
    for (const param of template.params) {
      testParams[param] = templateParams[param] || `[TEST_${param.toUpperCase()}]`;
    }

    // Remplacer les paramètres dans le sujet et le contenu
    const subject = `[TEST] ${replaceTemplateParams(template.subject, testParams)}`;
    const html = replaceTemplateParams(template.html, testParams);

    // Préparer l'email de test
    const emailData = {
      from: template.fromEmail || process.env.FROM_EMAIL,
      to: Array.isArray(to) ? to : [to],
      subject,
      html
    };

    // Envoyer l'email de test via Resend
    try {
      const result = await resend.emails.send(emailData);

      res.json({
        success: true,
        data: {
          emailId: result.data?.id,
          templateId,
          recipient: to,
          subject,
          testParams
        },
        message: 'Email de test envoyé avec succès'
      } as ApiResponse);

    } catch (resendError: any) {
      console.error('Erreur Resend (test):', resendError);

      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'envoi de l\'email de test',
        message: process.env.NODE_ENV === 'development' ? resendError.message : undefined
      } as ApiResponse);
    }

  } catch (error) {
    console.error('Erreur lors de l\'envoi de l\'email de test:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur interne du serveur'
    } as ApiResponse);
  }
});

export default router;