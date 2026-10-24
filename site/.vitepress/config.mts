import { defineConfig } from 'vitepress';

const repo = 'https://github.com/aurimasniekis/go-hallpass';

export default defineConfig({
  title: 'HallPass',
  description:
    'A terminating SSH gateway for AI agents: policy, human approval, credentials agents never see, and encrypted session recording.',
  lang: 'en-US',
  // GitHub Pages project site: https://aurimasniekis.github.io/go-hallpass/
  base: '/go-hallpass/',
  cleanUrls: true,
  lastUpdated: false,
  srcExclude: ['README.md'],
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/go-hallpass/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#2251b5' }],
  ],
  markdown: {
    theme: { light: 'github-light', dark: 'github-dark' },
  },
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Get started', link: '/guide/what-is-hallpass' },
      { text: 'Operators', link: '/operators/' },
      { text: 'Agents', link: '/agents/' },
      { text: 'Security', link: '/security/' },
      { text: 'Reference', link: '/reference/configuration' },
    ],
    sidebar: [
      {
        text: 'Get started',
        items: [
          { text: 'What is HallPass?', link: '/guide/what-is-hallpass' },
          { text: 'Concepts', link: '/guide/concepts' },
          { text: 'Try it locally', link: '/guide/try-locally' },
          { text: 'Install with Docker Compose', link: '/guide/install-docker' },
          { text: 'Install the binary (systemd)', link: '/guide/install-binary' },
          { text: 'First run', link: '/guide/first-run' },
          { text: 'Connect your first agent', link: '/guide/first-agent' },
        ],
      },
      {
        text: 'Operator guides',
        items: [
          { text: 'Overview', link: '/operators/' },
          { text: 'Servers and roles', link: '/operators/servers' },
          { text: 'Git remotes', link: '/operators/git' },
          { text: 'File transfer', link: '/operators/file-transfer' },
          { text: 'Agents and keys', link: '/operators/agents' },
          { text: 'Access policy', link: '/operators/policy' },
          { text: 'Approving requests', link: '/operators/approvals' },
          { text: 'Slack approvals', link: '/operators/slack' },
          { text: 'Telegram approvals', link: '/operators/telegram' },
          { text: 'Single sign-on (OIDC)', link: '/operators/sso' },
          { text: 'Sessions and recordings', link: '/operators/sessions' },
          { text: 'Home and lab servers', link: '/operators/remote-networks' },
          { text: 'Keys and the KEK', link: '/operators/keys' },
          { text: 'Backup and restore', link: '/operators/backup' },
          { text: 'Monitoring', link: '/operators/monitoring' },
          { text: 'Upgrades', link: '/operators/upgrades' },
          { text: 'Incident runbooks', link: '/operators/incidents' },
        ],
      },
      {
        text: 'For agents',
        items: [
          { text: 'Agent guide', link: '/agents/' },
          { text: 'AI agent skill (Claude Code, Codex)', link: '/agents/skill' },
        ],
      },
      {
        text: 'Destination servers',
        items: [
          { text: 'Setup and hardening', link: '/destinations/hardening' },
          { text: 'Destination-side audit', link: '/destinations/audit' },
        ],
      },
      {
        text: 'Security',
        items: [{ text: 'Security model and guarantees', link: '/security/' }],
      },
      {
        text: 'Help',
        items: [
          { text: 'Troubleshooting', link: '/help/troubleshooting' },
          { text: 'FAQ', link: '/help/faq' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/reference/configuration' },
          { text: 'Server CLI', link: '/reference/cli' },
          { text: 'Agent commands', link: '/reference/agent-commands' },
          { text: 'Exit codes', link: '/reference/exit-codes' },
          { text: 'REST API', link: '/reference/api' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: repo }],
    editLink: {
      pattern: `${repo}/edit/main/site/:path`,
      text: 'Edit this page on GitHub',
    },
    search: { provider: 'local' },
    outline: { level: [2, 3] },
    footer: {
      message: 'Released under the Apache-2.0 license.',
      copyright: 'HallPass contributors',
    },
  },
});
