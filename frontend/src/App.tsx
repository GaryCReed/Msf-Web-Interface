import { useEffect, useState } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import './App.css';
import ProjectsPage from './components/ProjectsPage';
import Dashboard from './components/Dashboard';
import LoginPage from './components/LoginPage';
import SessionDetail from './components/SessionDetail';
import ReportPage from './components/ReportPage';
import ProjectReportPage from './components/ProjectReportPage';
import TopographyPage from './components/TopographyPage';

interface AppProps {}

interface Project {
  id: number;
  name: string;
  network_range: string;
}

// Wrapper that fetches project data then renders Dashboard
function ProjectView({ onLogout }: { onLogout: () => void }) {
  const { id } = useParams<{ id: string }>();
  const projectId = parseInt(id || '0', 10);
  const [project, setProject] = useState<Project | null>(null);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (!projectId) { setNotFound(true); return; }
    axios.get(`/api/projects/${projectId}`)
      .then(res => setProject(res.data.project))
      .catch(() => setNotFound(true));
  }, [projectId]);

  if (notFound) return <Navigate to="/" replace />;
  if (!project) return <div className="app loading">Loading…</div>;
  return <Dashboard onLogout={onLogout} project={project} />;
}

function App(_: AppProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/health')
      .then(() => setIsAuthenticated(true))
      .catch(() => setIsAuthenticated(false))
      .finally(() => setIsLoading(false));
  }, []);

  const handleLogout = async () => {
    await axios.post('/api/auth/logout', {});
    setIsAuthenticated(false);
  };

  if (isLoading) {
    return <div className="app loading">Loading...</div>;
  }

  return (
    <BrowserRouter>
      <div className="app">
        <Routes>
          {/* /login shows the login form when not authenticated; redirects to /
              once authenticated so the user lands on projects after logging in. */}
          <Route
            path="/login"
            element={
              isAuthenticated
                ? <Navigate to="/" replace />
                : <LoginPage onLogin={() => setIsAuthenticated(true)} />
            }
          />

          {isAuthenticated ? (
            <>
              <Route path="/" element={<ProjectsPage onLogout={handleLogout} />} />
              <Route path="/project/:id" element={<ProjectView onLogout={handleLogout} />} />
              <Route path="/session/:id" element={<SessionDetail onLogout={handleLogout} />} />
              <Route path="/report/:id" element={<ReportPage />} />
              <Route path="/project-report/:id" element={<ProjectReportPage />} />
              <Route path="/topology/:id" element={<TopographyPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </>
          ) : (
            <Route path="*" element={<LoginPage onLogin={() => setIsAuthenticated(true)} />} />
          )}
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
