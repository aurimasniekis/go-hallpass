import { DesktopOutlined, MoonOutlined, SunOutlined } from '@ant-design/icons';
import { Segmented } from 'antd';

import { setThemeMode, useThemeMode, type ThemeMode } from '../stores/theme';

export function ThemeToggle() {
  const mode = useThemeMode();
  return (
    <Segmented<ThemeMode>
      size="small"
      aria-label="Color theme"
      value={mode}
      onChange={setThemeMode}
      options={[
        {
          value: 'light',
          icon: <SunOutlined aria-hidden />,
          title: 'Light theme',
          label: <span className="hp-visually-hidden">Light</span>,
        },
        {
          value: 'dark',
          icon: <MoonOutlined aria-hidden />,
          title: 'Dark theme',
          label: <span className="hp-visually-hidden">Dark</span>,
        },
        {
          value: 'system',
          icon: <DesktopOutlined aria-hidden />,
          title: 'Follow system theme',
          label: <span className="hp-visually-hidden">System</span>,
        },
      ]}
    />
  );
}
