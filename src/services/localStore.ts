/**
 * Tiny localStorage-backed store used by the prototype.
 * Browser storage is NOT a secure database: it is per-browser, user-editable and unencrypted.
 * Never store secrets, credentials or real evidence here.
 */
export interface LocalStore<T> {
  subscribe: (cb: () => void) => () => void;
  getSnapshot: () => T;
  set: (next: T) => void;
  reset: () => void;
}

export function createLocalStore<T>(key: string, seed: () => T): LocalStore<T> {
  let cache: T | null = null;
  const listeners = new Set<() => void>();

  const read = (): T => {
    if (cache !== null) return cache;
    try {
      const raw = window.localStorage.getItem(key);
      cache = raw ? (JSON.parse(raw) as T) : seed();
    } catch {
      cache = seed();
    }
    return cache as T;
  };

  const write = (next: T) => {
    cache = next;
    try {
      window.localStorage.setItem(key, JSON.stringify(next));
    } catch {
      /* storage unavailable (private mode / quota) — keep in-memory only */
    }
    listeners.forEach((l) => l());
  };

  return {
    subscribe: (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getSnapshot: read,
    set: write,
    reset: () => {
      try {
        window.localStorage.removeItem(key);
      } catch {
        /* ignore */
      }
      cache = seed();
      listeners.forEach((l) => l());
    },
  };
}
