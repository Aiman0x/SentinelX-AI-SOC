import { cap } from '../../utils/severity';

export type Tone = 'red' | 'gold' | 'green' | 'amber' | 'grey' | 'orange';

const tones: Record<Tone, string> = {
  red: 'bg-sx-red/15 text-[#FF6B66] border-sx-red/40',
  gold: 'bg-sx-gold/15 text-sx-gold border-sx-gold/40',
  green: 'bg-sx-ok/15 text-sx-ok border-sx-ok/40',
  amber: 'bg-sx-warn/15 text-sx-warn border-sx-warn/40',
  orange: 'bg-[#F0742C]/15 text-[#FF9A5C] border-[#F0742C]/40',
  grey: 'bg-[#6E6E6E]/20 text-[#B5B5B5] border-[#6E6E6E]/40',
};

const map: Record<string, Tone> = {
  // alert status
  open: 'red', investigating: 'gold', resolved: 'green', false_positive: 'grey',
  // case status
  contained: 'amber', closed: 'grey',
  // integration state
  connected: 'green', disconnected: 'amber', error: 'red', not_configured: 'grey', demo: 'gold',
  // monitoring
  verified: 'green', registered: 'gold', stale: 'amber', unmonitored: 'grey',
  // rules
  enabled: 'green', disabled: 'grey', draft: 'amber', validated: 'green', in_testing: 'gold', unvalidated: 'grey',
  // playbooks
  designed: 'grey', configured: 'amber', executed: 'green',
  // audit
  success: 'green', failure: 'red', denied: 'orange',
};

const labels: Record<string, string> = { demo: 'Demo data', not_configured: 'Not configured', false_positive: 'False positive' };

export function StatusBadge({ value, tone, label }: { value: string; tone?: Tone; label?: string }) {
  const t = tone ?? map[value] ?? 'grey';
  return (
    <span className={`inline-flex items-center whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-medium ${tones[t]}`}>
      {label ?? labels[value] ?? cap(value)}
    </span>
  );
}

/** Small amber/gold tag used on any block that is showing sample data. */
export function DemoTag({ text = 'DEMO DATA' }: { text?: string }) {
  return (
    <span className="inline-flex items-center whitespace-nowrap rounded border border-sx-gold/40 bg-sx-gold/10 px-1.5 py-0.5 text-[10px] font-semibold tracking-wider text-sx-gold">
      {text}
    </span>
  );
}
