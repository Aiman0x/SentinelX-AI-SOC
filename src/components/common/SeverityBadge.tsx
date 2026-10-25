import type { Severity } from '../../types/alert';
import { cap, severityClasses } from '../../utils/severity';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${severityClasses[severity]}`}>
      <span className={`h-1.5 w-1.5 rounded-full bg-current ${severity === 'critical' ? 'shadow-[0_0_6px_currentColor]' : ''}`} aria-hidden />
      {cap(severity)}
    </span>
  );
}
