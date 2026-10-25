import { Network, Radar, Shield, Workflow, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getIntegrations } from '../../services/integrationsService';
import { Panel } from '../common/Controls';
import { StatusBadge } from '../common/StatusBadge';
import type { IntegrationState } from '../../types/integration';

const icons: Record<string, LucideIcon> = { activepieces: Workflow, wazuh: Shield, sysmon: Radar, network: Network };

export function IntegrationHealth() {
  const all = getIntegrations();
  const net = all.filter((i) => i.id === 'suricata' || i.id === 'zeek');
  // Network monitoring is "connected" only if every network sensor is; otherwise the worst/least state is shown.
  const netState: IntegrationState = net.every((n) => n.state === 'connected') ? 'connected' : net.some((n) => n.state === 'error') ? 'error' : net.some((n) => n.state === 'disconnected') ? 'disconnected' : net.every((n) => n.state === 'not_configured') ? 'not_configured' : 'demo';

  const cards = [
    { id: 'activepieces', name: 'ActivePieces', state: all.find((i) => i.id === 'activepieces')!.state, note: 'Workflow orchestration' },
    { id: 'wazuh', name: 'Wazuh', state: all.find((i) => i.id === 'wazuh')!.state, note: 'Host detection & logs' },
    { id: 'sysmon', name: 'Windows Sysmon', state: all.find((i) => i.id === 'sysmon')!.state, note: 'Endpoint telemetry' },
    { id: 'network', name: 'Network monitoring', state: netState, note: 'Suricata / Zeek' },
  ];

  return (
    <Panel title="System & Integration Health" right={<Link to="/integrations" className="text-xs text-sx-gold hover:underline">Manage</Link>} bodyClass="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((c) => {
        const Icon = icons[c.id];
        return (
          <Link key={c.id} to="/integrations" className="rounded-lg border border-sx-line bg-sx-elev/50 p-3 transition-colors hover:border-sx-gold/40">
            <div className="flex items-center justify-between">
              <Icon className="h-[18px] w-[18px] text-sx-gold" aria-hidden />
              <StatusBadge value={c.state} />
            </div>
            <div className="mt-3 text-[13px] font-medium">{c.name}</div>
            <div className="text-[11px] text-sx-mute">{c.note}</div>
          </Link>
        );
      })}
      <p className="text-[11px] text-sx-mute sm:col-span-2 xl:col-span-4">
        “Connected” is only shown after a successful backend health check. States above are sample values for the demo.
      </p>
    </Panel>
  );
}
