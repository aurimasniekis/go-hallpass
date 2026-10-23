import { Card } from 'antd';

import { PageHeader } from '../../ds/PageHeader';
import { NotImplemented } from '../../ds/states';

export interface PlaceholderPageProps {
  title: string;
  description?: string;
  workPackage: string;
}

/** Page frame for routes whose content has not been built yet. Shows no data, real or fake. */
export function PlaceholderPage({ title, description, workPackage }: PlaceholderPageProps) {
  return (
    <>
      <PageHeader title={title} description={description} />
      <Card>
        <NotImplemented feature={title} workPackage={workPackage} />
      </Card>
    </>
  );
}
