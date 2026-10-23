import '@fontsource/jetbrains-mono/400.css';
import './index.css';
import './ds/ds.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { api } from './api/client';
import { qk } from './api/queryKeys';
import { App } from './App';
import { queryClient, router } from './router';
import { watchSystemTheme } from './stores/theme';

api.setHandlers({
  onUnauthorized: () => {
    const { pathname, href } = router.state.location;
    if (pathname === '/login' || pathname === '/setup') {
      return;
    }
    queryClient.clear();
    void router.navigate({ to: '/login', search: { next: href }, replace: true });
  },
  onSessionRotated: () => queryClient.invalidateQueries({ queryKey: qk.me }),
});

watchSystemTheme();

const root = document.getElementById('root');
if (!root) {
  throw new Error('#root element missing');
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
