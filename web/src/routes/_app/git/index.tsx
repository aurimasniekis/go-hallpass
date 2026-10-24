import { createFileRoute } from '@tanstack/react-router';

import { GitRemotesPage } from '../../../features/git/GitRemotesPage';

export const Route = createFileRoute('/_app/git/')({
  component: GitRemotesPage,
});
