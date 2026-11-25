import { registerComponent, unregisterComponent } from '@solovey/component-ui/contributions'

export function register() {
  registerComponent({
    id: 'blockcheck', apiVersion: '1.0',
    routes: [{ path: '/blockcheck', name: 'component.blockcheck', meta: { title: 'blockcheck.title' }, component: () => import('./BlockCheck.vue') }],
    locales: { en: () => import('./locales/en'), ru: () => import('./locales/ru') },
  })
}

export function unregister() { unregisterComponent('blockcheck') }
