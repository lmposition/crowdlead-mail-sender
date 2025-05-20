import { Request, Response, NextFunction } from 'express';

export const validateApiKey = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'] as string;
  const validApiKeys = process.env.API_KEYS?.split(',') || [];

  if (!apiKey) {
    res.status(401).json({ 
      success: false, 
      error: 'Clé API requise dans l\'en-tête X-API-Key' 
    });
    return;
  }

  if (!validApiKeys.includes(apiKey)) {
    res.status(403).json({ 
      success: false, 
      error: 'Clé API invalide' 
    });
    return;
  }

  next();
};