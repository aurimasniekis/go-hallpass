import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';

import { ReauthGate } from './ds/ReauthGate';
import { ThemeProvider } from './ds/theme/ThemeProvider';
import { queryClient, router } from './router';
import { useResolvedTheme } from './stores/theme';

// Dev-only: `import.meta.env.DEV` is statically false in production builds, so this import (and the
// devtools packages) are removed from the bundle. scripts/check-dist.mjs verifies it.
const Devtools = import.meta.env.DEV ? lazy(() => import('./devtools/Devtools')) : null;

export function App() {
  const mode = useResolvedTheme();
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider mode={mode} applyToDocument>
        <RouterProvider router={router} />
        <ReauthGate />
      </ThemeProvider>
      {Devtools ? (
        <Suspense fallback={null}>
          <Devtools router={router} />
        </Suspense>
      ) : null}
    </QueryClientProvider>
  );
}
