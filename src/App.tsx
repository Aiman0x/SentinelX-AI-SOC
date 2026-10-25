import { Route, Routes } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';
import Alerts from './pages/Alerts';
import Assets from './pages/Assets';
import AuditLogs from './pages/AuditLogs';
import Cases from './pages/Cases';
import DetectionRules from './pages/DetectionRules';
import Integrations from './pages/Integrations';
import Investigation from './pages/Investigation';
import NotFound from './pages/NotFound';
import Overview from './pages/Overview';
import Playbooks from './pages/Playbooks';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="cases" element={<Cases />} />
        <Route path="investigation" element={<Investigation />} />
        <Route path="assets" element={<Assets />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="rules" element={<DetectionRules />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="audit" element={<AuditLogs />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
