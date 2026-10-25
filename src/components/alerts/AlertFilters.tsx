import { FilterX } from 'lucide-react';
import { Select } from '../common/Controls';
import { SearchInput } from '../common/SearchInput';

export interface AlertFilterState {
  q: string;
  severity: string;
  status: string;
  source: string;
  date: string;
}

export const emptyAlertFilters: AlertFilterState = { q: '', severity: 'all', status: 'all', source: 'all', date: 'all' };

interface Props {
  value: AlertFilterState;
  onChange: (v: AlertFilterState) => void;
  sources: string[];
}

export function AlertFilters({ value, onChange, sources }: Props) {
  const set = (patch: Partial<AlertFilterState>) => onChange({ ...value, ...patch });
  const dirty = JSON.stringify(value) !== JSON.stringify(emptyAlertFilters);
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-sx-line p-3">
      <SearchInput className="w-full sm:w-72" value={value.q} onChange={(q) => set({ q })} placeholder="Search name, IP, asset, alert or event ID" label="Search alerts" />
      <Select label="Severity" className="w-32" value={value.severity} onChange={(severity) => set({ severity })}
        options={[{ value: 'all', label: 'All severities' }, { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }]} />
      <Select label="Status" className="w-36" value={value.status} onChange={(status) => set({ status })}
        options={[{ value: 'all', label: 'All statuses' }, { value: 'open', label: 'Open' }, { value: 'investigating', label: 'Investigating' }, { value: 'resolved', label: 'Resolved' }, { value: 'false_positive', label: 'False positive' }]} />
      <Select label="Event source" className="w-40" value={value.source} onChange={(source) => set({ source })}
        options={[{ value: 'all', label: 'All sources' }, ...sources.map((s) => ({ value: s, label: s }))]} />
      <Select label="Date range" className="w-36" value={value.date} onChange={(date) => set({ date })}
        options={[{ value: 'all', label: 'Any time' }, { value: '1', label: 'Last 1 hour' }, { value: '6', label: 'Last 6 hours' }, { value: '24', label: 'Last 24 hours' }]} />
      <button className="btn" onClick={() => onChange(emptyAlertFilters)} disabled={!dirty}><FilterX className="h-3.5 w-3.5" /> Clear</button>
    </div>
  );
}
