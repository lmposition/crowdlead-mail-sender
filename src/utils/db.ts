// Utilitaires pour la base de données
export function ensureString(value: string | undefined): string {
  return value || '';
}

export function ensureArray<T>(value: T[] | undefined): T[] {
  return value || [];
}

export function parseJsonSafely<T>(value: string | null | undefined, defaultValue: T): T {
  if (!value) return defaultValue;
  try {
    return JSON.parse(value);
  } catch {
    return defaultValue;
  }
}

export function formatDate(date: string | Date): Date {
  return new Date(date);
}