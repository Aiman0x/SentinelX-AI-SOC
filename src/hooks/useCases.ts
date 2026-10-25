import { casesStore } from '../services/casesService';
import { useLocalStore } from './useLocalStore';

export const useCases = () => useLocalStore(casesStore);
