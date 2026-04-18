import { useEffect, useState } from 'react';

export interface ComponentStatus {
  status: 'connected' | 'error' | 'loaded' | 'not_loaded';
  detail: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  version: string;
  response_time_ms: number;
  components: {
    database: ComponentStatus;
    redis: ComponentStatus;
    ml_model: ComponentStatus;
  };
}

export const useSystemHealth = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch('http://localhost:8080/health');
        const data: HealthResponse = await r.json();
        setHealth(data);
      } catch {
        setHealth(null);
      } finally {
        setLoading(false);
      }
    };

    check();
    const interval = setInterval(check, 30000); // re-check every 30s
    return () => clearInterval(interval);
  }, []);

  return { health, loading };
};
