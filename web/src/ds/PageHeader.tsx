import type { ReactNode } from 'react';

export interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  /** Right-aligned actions. */
  extra?: ReactNode;
  /** Optional element above the title (breadcrumb, back link). */
  above?: ReactNode;
}

export function PageHeader({ title, description, extra, above }: PageHeaderProps) {
  return (
    <header className="hp-page-header">
      <div>
        {above}
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </div>
      {extra ? <div>{extra}</div> : null}
    </header>
  );
}
