import { Card } from 'antd';
import type { ReactNode } from 'react';

export function AuthLayout({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="hp-auth">
      <div className="hp-auth__panel">
        <Card>
          <h1 className="hp-auth__title">{title}</h1>
          {subtitle ? <p style={{ marginTop: 0 }}>{subtitle}</p> : null}
          {children}
        </Card>
      </div>
    </main>
  );
}
