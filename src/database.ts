// Types TypeScript pour l'Email Manager

export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  html: string;
  fromEmail?: string;
  params: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface EmailLog {
  id: number;
  templateId: string;
  recipientEmail: string;
  subject: string;
  status: 'success' | 'failed';
  errorMessage?: string;
  sentAt: Date;
}

export interface EmailStats {
  templateId: string;
  templateName: string;
  totalSent: number;
  totalSuccess: number;
  totalFailed: number;
  lastSentAt?: Date;
  successRate: number;
}

export interface AdminSession {
  token: string;
  expiresAt: Date;
}

export interface SendEmailRequest {
  to: string;
  cc?: string;
  bcc?: string;
  [key: string]: any; // Paramètres dynamiques du template
}

export interface DatabaseConfig {
  type: 'postgres' | 'sqlite';
  url: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface CreateTemplateRequest {
  name: string;
  subject: string;
  html: string;
  fromEmail?: string;
}

export interface UpdateTemplateRequest extends Partial<CreateTemplateRequest> {
  id: string;
}

export interface LoginRequest {
  password: string;
}

export interface DashboardStats {
  totalTemplates: number;
  totalEmailsSent: number;
  successRate: number;
  recentLogs: EmailLog[];
  templatesStats: EmailStats[];
}