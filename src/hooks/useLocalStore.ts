import { useSyncExternalStore } from 'react';
import type { LocalStore } from '../services/localStore';

export function useLocalStore<T>(store: LocalStore<T>): T {
  return useSyncExternalStore(store.subscribe, store.getSnapshot);
}
