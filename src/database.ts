import { Pool } from 'pg';
import sqlite3 from 'sqlite3';
import { EmailTemplate, EmailLog, EmailStats, AdminSession, DatabaseConfig, DashboardStats } from './types';
import { parseJsonSafely, formatDate } from './utils/db';

export class Database {
  private pgPool?: Pool;
  private sqliteDb?: sqlite3.Database;
  private config: DatabaseConfig;

  constructor(config: DatabaseConfig) {
    this.config = config;
    this.init();
  }

  private init(): void {
    if (this.config.type === 'postgres') {
      this.pgPool = new Pool({
        connectionString: this.config.url
      });
    } else {
      const dbPath = this.config.url.replace('sqlite:', '');
      this.sqliteDb = new sqlite3.Database(dbPath);
    }
  }

  async query(sql: string, params: any[] = []): Promise<any> {
    if (this.config.type === 'postgres' && this.pgPool) {
      const result = await this.pgPool.query(sql, params);
      return result;
    } else if (this.sqliteDb) {
      return new Promise((resolve, reject) => {
        if (sql.toLowerCase().startsWith('select')) {
          this.sqliteDb!.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve({ rows });
          });
        } else {
          this.sqliteDb!.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ rowCount: this.changes, insertId: this.lastID });
          });
        }
      });
    }
    throw new Error('Database not initialized');
  }

  async initTables(): Promise<void> {
    const isPostgres = this.config.type === 'postgres';
    
    // Table des templates
    await this.query(`
      CREATE TABLE IF NOT EXISTS email_templates (
        id VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        subject TEXT NOT NULL,
        html TEXT NOT NULL,
        from_email VARCHAR(255),
        params TEXT,
        created_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP,
        updated_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table des logs d'emails
    await this.query(`
      CREATE TABLE IF NOT EXISTS email_logs (
        id ${isPostgres ? 'SERIAL' : 'INTEGER'} PRIMARY KEY ${!isPostgres ? 'AUTOINCREMENT' : ''},
        template_id VARCHAR(100) NOT NULL,
        recipient_email VARCHAR(255) NOT NULL,
        subject TEXT NOT NULL,
        status VARCHAR(20) NOT NULL,
        error_message TEXT,
        sent_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
      )
    `);

    // Table des statistiques
    await this.query(`
      CREATE TABLE IF NOT EXISTS email_stats (
        template_id VARCHAR(100) PRIMARY KEY,
        total_sent INTEGER DEFAULT 0,
        total_success INTEGER DEFAULT 0,
        total_failed INTEGER DEFAULT 0,
        last_sent_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'},
        FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
      )
    `);

    // Table des sessions admin
    await this.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        token VARCHAR(255) PRIMARY KEY,
        expires_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'} NOT NULL,
        created_at ${isPostgres ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  // Templates
  async getTemplate(id: string): Promise<EmailTemplate | null> {
    const result = await this.query(
      'SELECT * FROM email_templates WHERE id = $1',
      [id]
    );
    
    if (!result.rows || result.rows.length === 0) return null;
    
    const row = result.rows[0];
    return {
      id: row.id,
      name: row.name,
      subject: row.subject,
      html: row.html,
      fromEmail: row.from_email || undefined,
      params: parseJsonSafely(row.params, []),
      createdAt: formatDate(row.created_at),
      updatedAt: formatDate(row.updated_at)
    };
  }

  async getAllTemplates(): Promise<EmailTemplate[]> {
    const result = await this.query(
      'SELECT * FROM email_templates ORDER BY created_at DESC'
    );
    
    return result.rows.map((row: any) => ({
      id: row.id,
      name: row.name,
      subject: row.subject,
      html: row.html,
      fromEmail: row.from_email || undefined,
      params: parseJsonSafely(row.params, []),
      createdAt: formatDate(row.created_at),
      updatedAt: formatDate(row.updated_at)
    }));
  }

  async createTemplate(template: Omit<EmailTemplate, 'createdAt' | 'updatedAt'>): Promise<void> {
    await this.query(`
      INSERT INTO email_templates (id, name, subject, html, from_email, params)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      template.id,
      template.name,
      template.subject,
      template.html,
      template.fromEmail || null,
      JSON.stringify(template.params)
    ]);

    // Créer les statistiques pour ce template
    await this.query(`
      INSERT INTO email_stats (template_id, total_sent, total_success, total_failed)
      VALUES ($1, 0, 0, 0)
    `, [template.id]);
  }

  async updateTemplate(template: EmailTemplate): Promise<void> {
    await this.query(`
      UPDATE email_templates 
      SET name = $2, subject = $3, html = $4, from_email = $5, params = $6, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `, [
      template.id,
      template.name,
      template.subject,
      template.html,
      template.fromEmail || null,
      JSON.stringify(template.params)
    ]);
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.query('DELETE FROM email_templates WHERE id = $1', [id]);
  }

  // Logs d'emails
  async createEmailLog(log: Omit<EmailLog, 'id' | 'sentAt'>): Promise<void> {
    await this.query(`
      INSERT INTO email_logs (template_id, recipient_email, subject, status, error_message)
      VALUES ($1, $2, $3, $4, $5)
    `, [
      log.templateId,
      log.recipientEmail,
      log.subject,
      log.status,
      log.errorMessage || null
    ]);

    // Mettre à jour les statistiques
    await this.updateStats(log.templateId, log.status);
  }

  async getEmailLogs(templateId?: string, limit = 50): Promise<EmailLog[]> {
    let query = `
      SELECT el.*, et.name as template_name 
      FROM email_logs el
      LEFT JOIN email_templates et ON el.template_id = et.id
    `;
    const params: any[] = [];

    if (templateId) {
      query += ' WHERE el.template_id = $1';
      params.push(templateId);
    }

    query += ` ORDER BY el.sent_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const result = await this.query(query, params);
    
    return result.rows.map((row: any) => ({
      id: row.id,
      templateId: row.template_id,
      recipientEmail: row.recipient_email,
      subject: row.subject,
      status: row.status,
      errorMessage: row.error_message || undefined,
      sentAt: new Date(row.sent_at)
    }));
  }

  // Statistiques
  private async updateStats(templateId: string, status: 'success' | 'failed'): Promise<void> {
    const updateQuery = `
      UPDATE email_stats 
      SET 
        total_sent = total_sent + 1,
        ${status === 'success' ? 'total_success = total_success + 1' : 'total_failed = total_failed + 1'},
        last_sent_at = CURRENT_TIMESTAMP
      WHERE template_id = $1
    `;
    await this.query(updateQuery, [templateId]);
  }

  async getTemplateStats(templateId: string): Promise<EmailStats | null> {
    const result = await this.query(`
      SELECT es.*, et.name as template_name
      FROM email_stats es
      LEFT JOIN email_templates et ON es.template_id = et.id
      WHERE es.template_id = $1
    `, [templateId]);

    if (!result.rows || result.rows.length === 0) return null;

    const row = result.rows[0];
    const successRate = row.total_sent > 0 ? (row.total_success / row.total_sent) * 100 : 0;

    return {
      templateId: row.template_id,
      templateName: row.template_name,
      totalSent: row.total_sent,
      totalSuccess: row.total_success,
      totalFailed: row.total_failed,
      lastSentAt: row.last_sent_at ? new Date(row.last_sent_at) : undefined,
      successRate: Math.round(successRate * 100) / 100
    };
  }

  async getAllStats(): Promise<EmailStats[]> {
    const result = await this.query(`
      SELECT es.*, et.name as template_name
      FROM email_stats es
      LEFT JOIN email_templates et ON es.template_id = et.id
      ORDER BY es.total_sent DESC
    `);

    return result.rows.map((row: any) => {
      const successRate = row.total_sent > 0 ? (row.total_success / row.total_sent) * 100 : 0;
      return {
        templateId: row.template_id,
        templateName: row.template_name,
        totalSent: row.total_sent,
        totalSuccess: row.total_success,
        totalFailed: row.total_failed,
        lastSentAt: row.last_sent_at ? new Date(row.last_sent_at) : undefined,
        successRate: Math.round(successRate * 100) / 100
      };
    });
  }

  async getDashboardStats(): Promise<DashboardStats> {
    // Total des templates
    const templatesResult = await this.query('SELECT COUNT(*) as count FROM email_templates');
    const totalTemplates = templatesResult.rows[0].count;

    // Total des emails envoyés
    const emailsResult = await this.query('SELECT COUNT(*) as count FROM email_logs');
    const totalEmailsSent = emailsResult.rows[0].count;

    // Taux de succès global
    const successResult = await this.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'success' THEN 1 END) as success
      FROM email_logs
    `);
    const successRate = successResult.rows[0].total > 0 
      ? Math.round((successResult.rows[0].success / successResult.rows[0].total) * 100 * 100) / 100
      : 0;

    // Logs récents
    const recentLogs = await this.getEmailLogs(undefined, 10);

    // Statistiques des templates
    const templatesStats = await this.getAllStats();

    return {
      totalTemplates,
      totalEmailsSent,
      successRate,
      recentLogs,
      templatesStats
    };
  }

  // Sessions admin
  async createSession(token: string, expiresAt: Date): Promise<void> {
    await this.query(`
      INSERT INTO admin_sessions (token, expires_at)
      VALUES ($1, $2)
    `, [token, expiresAt]);
  }

  async getSession(token: string): Promise<AdminSession | null> {
    const result = await this.query(
      'SELECT * FROM admin_sessions WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP',
      [token]
    );

    if (!result.rows || result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      token: row.token,
      expiresAt: new Date(row.expires_at)
    };
  }

  async deleteSession(token: string): Promise<void> {
    await this.query('DELETE FROM admin_sessions WHERE token = $1', [token]);
  }

  async cleanupExpiredSessions(): Promise<void> {
    await this.query('DELETE FROM admin_sessions WHERE expires_at <= CURRENT_TIMESTAMP');
  }

  async close(): Promise<void> {
    if (this.pgPool) {
      await this.pgPool.end();
    }
    if (this.sqliteDb) {
      this.sqliteDb.close();
    }
  }
}