import { Card } from 'antd';
import type { ReactNode } from 'react';

import { Logo } from '../../ds/Logo';

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
          <div className="hp-auth__brand">
            <Logo size={40} />
          </div>
          <h1 className="hp-auth__title">{title}</h1>
          {subtitle ? <p style={{ marginTop: 0 }}>{subtitle}</p> : null}
          {children}
        </Card>
      </div>
    </main>
  );
}
