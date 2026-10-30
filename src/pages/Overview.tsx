import { BellRing, FolderKanban, Monitor, Plug } from 'lucide-react';
import { useAlerts } from '../hooks/useAlerts';
import { useCases } from '../hooks/useCases';
import { useLocalStore } from '../hooks/useLocalStore';
import { assetsStore, loadAssets } from '../services/miscService';
import { getIntegrations, loadIntegrations } from '../services/integrationsService';
import { useData } from '../hooks/useData';
import { isDemoMode, isBackendConfigured } from '../services/apiClient';
import { useData } from '../hooks/useData';
import { IntegrationHealth } from '../components/dashboard/IntegrationHealth';
import { RecentAlerts } from '../components/dashboard/RecentAlerts';
import { SecurityTrendChart } from '../components/dashboard/SecurityTrendChart';
import { SeverityChart } from '../components/dashboard/SeverityChart';
import { StatCard } from '../components/dashboard/StatCard';
import { PageHeader } from '../components/layout/PageHeader';

export default function Overview() {
  const { alerts } = useAlerts();
  const cases = useCases();
  const localAssets = useLocalStore(assetsStore);
  const { data: backendAssets } = useData(loadAssets);
  const assets = isBackendConfigured ? backendAssets ?? [] : localAssets;
  const { data: integrationData } = useData(loadIntegrations);
  const integrations = integrationData ?? getIntegrations();

  const openCases = cases.filter((c) => c.status !== 'closed' && c.status !== 'resolved').length;
  const critical = alerts.filter((a) => a.severity === 'critical' && a.status !== 'resolved' && a.status !== 'false_positive').length;
  const verified = assets.filter((a) => a.monitoring === 'verified').length;
  const connected = integrations.filter((i) => i.state === 'connected').length;

  return (
    <>
      <PageHeader title="Security Operations Overview" subtitle="Monitor, investigate, and respond to security events." />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Open Cases" value={openCases} caption="Not resolved or closed" icon={FolderKanban} accent="gold" spark={[2, 3, 3, 4, 3, 5, openCases]} isDemo={isDemoMode} />
        <StatCard label="Critical Alerts" value={critical} caption="Active, unresolved" icon={BellRing} accent="red" spark={[0, 1, 0, 2, 1, 3, critical]} isDemo={isDemoMode} />
        <StatCard label="Monitored Assets" value={assets.length} caption={`${verified} with verified telemetry`} icon={Monitor} accent="neutral" spark={[9, 10, 10, 11, 11, 12, assets.length]} isDemo={isDemoMode} />
        <StatCard label="Connected Integrations" value={connected} caption={`of ${integrations.length} planned · ${integrations.filter((i) => i.verified).length} verified`} icon={Plug} accent="neutral" isDemo={isDemoMode} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <SecurityTrendChart />
        <SeverityChart alerts={alerts} />
      </div>

      <div className="mt-4"><RecentAlerts /></div>
      <div className="mt-4"><IntegrationHealth /></div>
    </>
  );
}
