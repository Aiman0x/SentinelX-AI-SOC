import type { Severity } from '../types/alert';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Hex colours used by charts. Matches the SentinelX palette (red / orange / gold / neutral). */
export const severityHex: Record<Severity, string> = {
  critical: '#E53935',
  high: '#F0742C',
  medium: '#D4AF37',
  low: '#6E6E6E',
};

export const severityClasses: Record<Severity, string> = {
  critical: 'bg-sx-red/15 text-[#FF6B66] border-sx-red/40',
  high: 'bg-[#F0742C]/15 text-[#FF9A5C] border-[#F0742C]/40',
  medium: 'bg-sx-gold/15 text-sx-gold border-sx-gold/40',
  low: 'bg-[#6E6E6E]/20 text-[#B5B5B5] border-[#6E6E6E]/40',
};

export const cap = (s: string) => s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
