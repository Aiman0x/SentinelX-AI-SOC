import { Compass } from 'lucide-react';
import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';

export default function NotFound() {
  return (
    <div className="panel mx-auto mt-10 max-w-lg">
      <EmptyState icon={<Compass className="h-9 w-9 text-sx-gold" />} title="Page not found" description="This page does not exist in SentinelX."
        action={<Link to="/" className="btn btn-gold mt-2">Back to Overview</Link>} />
    </div>
  );
}
