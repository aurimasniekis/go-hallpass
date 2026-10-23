import { Store, useSelector } from '@tanstack/react-store';

import { readPersisted, writePersisted } from './persist';

export type Density = 'compact' | 'comfortable';

export const DENSITY_STORAGE_KEY = 'hallpass.density';

export function parseDensity(value: unknown): Density {
  return value === 'comfortable' ? 'comfortable' : 'compact';
}

export const densityStore = new Store<{ density: Density }>({
  density: parseDensity(readPersisted(DENSITY_STORAGE_KEY)),
});

export function setDensity(density: Density): void {
  densityStore.setState(() => ({ density }));
  writePersisted(DENSITY_STORAGE_KEY, density);
}

export function useDensity(): Density {
  return useSelector(densityStore, (s) => s.density);
}
