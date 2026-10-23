import { createFileRoute, notFound } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';

/**
 * Design-system gallery (docs/PLAN.md §14.2): dev builds only. In production `import.meta.env.DEV` is
 * statically false, so the gallery module is never imported or bundled and the route answers 404.
 */
const DsGallery = import.meta.env.DEV ? lazy(() => import('../ds/gallery/DsGallery')) : null;

export const Route = createFileRoute('/__ds')({
  beforeLoad: () => {
    if (!import.meta.env.DEV) {
      throw notFound();
    }
  },
  component: DsRoute,
});

function DsRoute() {
  if (!DsGallery) {
    return null;
  }
  return (
    <Suspense fallback={null}>
      <DsGallery />
    </Suspense>
  );
}
