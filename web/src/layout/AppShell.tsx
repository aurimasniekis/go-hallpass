import { LogoutOutlined, MenuOutlined, UserOutlined } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router';
import { App, Button, Drawer, Dropdown, Layout, Menu, type MenuProps } from 'antd';
import { useEffect, useMemo, useState } from 'react';

import { api } from '../api/client';
import { errorMessage } from '../api/errors';
import type { Me } from '../api/types';
import { ConnectionBanner } from '../ds/ConnectionBanner';
import { Logo } from '../ds/Logo';
import { watchScrollableRegions } from '../ds/scrollableRegions';
import { LockdownBanner } from '../features/dashboard/LockdownControls';
import { COMPACT_SHELL_QUERY, useMediaQuery } from '../lib/useMediaQuery';
import { SseManager } from '../sse/manager';
import { activeNavPath, visibleNavSections } from './nav';
import { ThemeToggle } from './ThemeToggle';

const { Sider, Header, Content } = Layout;

/** Only absolute http(s) URLs are followed; anything else (javascript:, data:) is ignored. */
export function safeExternalUrl(value: string | null | undefined): string | null {
  if (!value) {
    return null;
  }
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null;
  } catch {
    return null;
  }
}

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
  useEffect(() => watchScrollableRegions(), []);

  const items = useMemo<MenuProps['items']>(
    () =>
      visibleNavSections(me.permissions).map((section) => ({
        type: 'group' as const,
        key: section.label,
        label: section.label,
        children: section.items.map((item) => ({
          key: item.to,
          label: <Link to={item.to}>{item.label}</Link>,
        })),
      })),
    [me.permissions],
  );
  const selected = activeNavPath(pathname);
  // Phones and small tablets: the navigation is a drawer opened from the header instead of a sidebar that squeezes
  // the page.
  const compact = useMediaQuery(COMPACT_SHELL_QUERY);
  const [navOpen, setNavOpen] = useState(false);

  const { modal } = App.useApp();
  const signOut = async () => {
    let providerLogoutUrl: string | null;
    try {
      const res = await api.call('post', '/api/v1/auth/logout', { authRedirect: false, reauth: false });
      providerLogoutUrl = res.provider_logout_url ?? null;
    } catch (e) {
      // Logout must not be reported as successful unless the server confirmed it.
      void message.error(`Sign-out failed: ${errorMessage(e)}`);
      return;
    }
    api.clearSession();
    queryClient.clear();
    await navigate({ to: '/login' });
    const idpLogout = safeExternalUrl(providerLogoutUrl);
    if (idpLogout) {
      // RP-initiated logout is optional and not a global logout (HP-OIDC-015): offer it as an extra step.
      modal.confirm({
        title: 'Signed out of HallPass',
        content: 'You are still signed in at your identity provider. Sign out there too?',
        okText: 'Sign out at provider',
        cancelText: 'Not now',
        onOk: () => {
          window.location.assign(idpLogout);
        },
      });
    }
  };

  const brand = (
    <>
      <Logo size={22} />
      HallPass
    </>
  );
  const navigation = (
    <nav aria-label="Main">
      <Menu
        mode="inline"
        items={items}
        selectedKeys={selected ? [selected] : []}
        style={{ borderInlineEnd: 0, padding: '8px 4px' }}
        onClick={() => {
          setNavOpen(false);
        }}
      />
    </nav>
  );

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <a className="hp-skip-link" href="#main">
        Skip to content
      </a>
      {compact ? (
        <Drawer
          placement="left"
          open={navOpen}
          size={280}
          className="hp-shell-drawer"
          title={<span className="hp-shell-header__start">{brand}</span>}
          onClose={() => {
            setNavOpen(false);
          }}
        >
          {navigation}
        </Drawer>
      ) : (
        <Sider
          width={224}
          theme="light"
          style={{ borderRight: '1px solid var(--hp-color-border-secondary)' }}
        >
          <div className="hp-shell-brand">{brand}</div>
          {navigation}
        </Sider>
      )}
      <Layout style={{ minWidth: 0 }}>
        <Header className="hp-shell-header">
          <div className="hp-shell-header__start">
            {compact ? (
              <>
                <Button
                  type="text"
                  icon={<MenuOutlined />}
                  aria-label="Open navigation"
                  aria-expanded={navOpen}
                  onClick={() => {
                    setNavOpen(true);
                  }}
                />
                {brand}
              </>
            ) : null}
          </div>
          <div className="hp-shell-header__end">
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
              <Button type="text" icon={<UserOutlined />} aria-label={`Account: ${me.operator.display_name}`}>
                {compact ? null : me.operator.display_name}
              </Button>
            </Dropdown>
          </div>
        </Header>
        <ConnectionBanner
          onReconnect={() => {
            sse.reconnectNow();
          }}
        />
        <LockdownBanner />
        <Content>
          <main id="main" tabIndex={-1} className="hp-shell-content">
            <Outlet />
          </main>
        </Content>
      </Layout>
    </Layout>
  );
}
