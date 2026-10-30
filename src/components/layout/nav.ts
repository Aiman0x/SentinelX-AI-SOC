import { Activity, BellRing, Radio, BookOpenCheck, Boxes, FolderKanban, LayoutDashboard, Microscope, Plug, ScrollText, Settings, UsersRound, type LucideIcon } from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

export const navItems: NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Security Alerts', icon: BellRing },
  { to: '/telemetry', label: 'Windows Telemetry', icon: Radio },
  { to: '/cases', label: 'Incidents & Cases', icon: FolderKanban },
  { to: '/investigation', label: 'Investigation', icon: Microscope },
  { to: '/assets', label: 'Assets & Endpoints', icon: Boxes },
  { to: '/integrations', label: 'Integrations', icon: Plug },
  { to: '/rules', label: 'Detection Rules', icon: Activity },
  { to: '/playbooks', label: 'Response Playbooks', icon: BookOpenCheck },
  { to: '/audit', label: 'Audit Logs', icon: ScrollText },
  { to: '/users', label: 'User Management', icon: UsersRound },
  { to: '/settings', label: 'Settings', icon: Settings },
];
