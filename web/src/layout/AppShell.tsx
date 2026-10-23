import { LogoutOutlined, UserOutlined } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router';
import { App, Button, Dropdown, Layout, Menu, type MenuProps } from 'antd';
import { useEffect, useMemo, useState } from 'react';

import { api } from '../api/client';
import { errorMessage } from '../api/errors';
import type { Me } from '../api/types';
import { ConnectionBanner } from '../ds/ConnectionBanner';
import { SseManager } from '../sse/manager';
import { activeNavPath, NAV_SECTIONS } from './nav';
import { ThemeToggle } from './ThemeToggle';

const { Sider, Header, Content } = Layout;

function useLiveEvents(): SseManager {
  const queryClient = useQueryClient();
  const [manager] = useState(() => new SseManager({ queryClient }));
  useEffect(() => {
    manager.start();
    return () => {
      manager.stop();
    };
  }, [manager]);
  return manager;
}

export function AppShell({ me }: { me: Me }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const sse = useLiveEvents();

  const items = useMemo<MenuProps['items']>(
    () =>
      NAV_SECTIONS.map((section) => ({
        type: 'group' as const,
        key: section.label,
        label: section.label,
        children: section.items.map((item) => ({
          key: item.to,
          label: <Link to={item.to}>{item.label}</Link>,
        })),
      })),
    [],
  );
  const selected = activeNavPath(pathname);

  const signOut = async () => {
    try {
      await api.post('/auth/logout', undefined, { authRedirect: false, reauth: false });
    } catch (e) {
      // Logout must not be reported as successful unless the server confirmed it.
      void message.error(`Sign-out failed: ${errorMessage(e)}`);
      return;
    }
    api.clearSession();
    queryClient.clear();
    await navigate({ to: '/login' });
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <a className="hp-skip-link" href="#main">
        Skip to content
      </a>
      <Sider
        width={224}
        breakpoint="lg"
        collapsedWidth={0}
        theme="light"
        style={{ borderRight: '1px solid var(--hp-color-border-secondary)' }}
      >
        <div className="hp-shell-brand">Hallpass</div>
        <nav aria-label="Main">
          <Menu
            mode="inline"
            items={items}
            selectedKeys={selected ? [selected] : []}
            style={{ borderInlineEnd: 0, padding: '8px 4px' }}
          />
        </nav>
      </Sider>
      <Layout>
        <Header className="hp-shell-header">
          <span />
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <ThemeToggle />
            <Dropdown
              trigger={['click']}
              menu={{
                items: [
                  { key: 'me', icon: <UserOutlined />, label: <Link to="/me">My account</Link> },
                  { type: 'divider' },
                  {
                    key: 'logout',
                    icon: <LogoutOutlined />,
                    label: 'Sign out',
                    onClick: () => {
                      void signOut();
                    },
                  },
                ],
              }}
            >
              <Button type="text" icon={<UserOutlined />}>
                {me.display_name}
              </Button>
            </Dropdown>
          </div>
        </Header>
        <ConnectionBanner
          onReconnect={() => {
            sse.reconnectNow();
          }}
        />
        <Content>
          <main id="main" tabIndex={-1} className="hp-shell-content">
            <Outlet />
          </main>
        </Content>
      </Layout>
    </Layout>
  );
}
