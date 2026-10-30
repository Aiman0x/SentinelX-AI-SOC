import { casesStore, loadCases } from '../services/casesService';
import { isBackendConfigured } from '../services/apiClient';
import { useData } from './useData';
import { useLocalStore } from './useLocalStore';

export const useCases = () => {
  const local = useLocalStore(casesStore);
  const remote = useData(loadCases);
  return isBackendConfigured ? remote.data ?? [] : local;
};
