import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="page-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <h1 style={{ fontSize: 'var(--text-3xl)', marginBottom: 16 }}>404</h1>
      <p className="text-secondary text-lg" style={{ marginBottom: 8 }}>Page not found</p>
      <p className="text-muted text-sm" style={{ marginBottom: 24 }}>
        The page you are looking for does not exist.
      </p>
      <Link to="/" className="btn btn-primary">Go to Dashboard</Link>
    </div>
  );
}
