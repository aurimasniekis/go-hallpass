import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';

import Flow from './Flow.vue';
import Shot from './Shot.vue';
import './custom.css';

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('Shot', Shot);
    app.component('Flow', Flow);
  },
} satisfies Theme;
