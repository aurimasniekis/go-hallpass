import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { OnboardingWizard, type WizardLocation } from '../../../features/servers/onboarding/OnboardingWizard';
import { parseStep } from '../../../features/servers/onboarding/model';

export const Route = createFileRoute('/_app/servers/onboard')({
  validateSearch: (search: Record<string, unknown>): WizardLocation => {
    const step = parseStep(search.step);
    return {
      ...(typeof search.server === 'string' && search.server !== '' ? { server: search.server } : {}),
      ...(step ? { step } : {}),
    };
  },
  component: OnboardRoute,
});

function OnboardRoute() {
  const location = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  return (
    <OnboardingWizard
      location={location}
      onNavigate={(next, replace) => {
        void navigate({ search: next, ...(replace ? { replace: true } : {}) });
      }}
    />
  );
}
