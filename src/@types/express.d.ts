// Déclarations TypeScript pour étendre Express
import { Database } from './database';

declare global {
  namespace Express {
    interface Request {
      db: Database;
    }
  }
}

export {};