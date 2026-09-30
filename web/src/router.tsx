import { createRootRoute, createRoute, createRouter } from '@tanstack/react-router'

import { AppShell } from './components/AppShell'
import { AuthGate } from './components/AuthGate'
import { RouteError, RouteNotFound } from './components/RouteFallback'
import { RoutePending } from './components/RoutePending'
import { EventsPage } from './pages/Events'
import { IPRulesPage } from './pages/IPRules'
import { OverviewPage } from './pages/Overview'
import { PlaygroundPage } from './pages/Playground'
import { RateLimitPage } from './pages/RateLimit'
import { RuleEditorPage } from './pages/RuleEditor'
import { RulesPage } from './pages/Rules'
import { SettingsPage } from './pages/Settings'

const rootRoute = createRootRoute({
  errorComponent: RouteError,
  notFoundComponent: RouteNotFound,
  pendingComponent: RoutePending,
  component: () => (
    <AuthGate>
      <AppShell />
    </AuthGate>
  ),
})

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: OverviewPage })
const eventsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/traffic/events', component: EventsPage })
const rulesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/security/rules', component: RulesPage })
const newRuleRoute = createRoute({ getParentRoute: () => rootRoute, path: '/security/rules/new', component: RuleEditorPage })
const editRuleRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/security/rules/$ruleId',
  component: RuleEditorPage,
})
const ipRulesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/security/ip-rules', component: IPRulesPage })
const rateLimitRoute = createRoute({ getParentRoute: () => rootRoute, path: '/security/rate-limit', component: RateLimitPage })
const playgroundRoute = createRoute({ getParentRoute: () => rootRoute, path: '/security/playground', component: PlaygroundPage })
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/settings', component: SettingsPage })

const routeTree = rootRoute.addChildren([
  indexRoute,
  eventsRoute,
  rulesRoute,
  newRuleRoute,
  editRuleRoute,
  ipRulesRoute,
  rateLimitRoute,
  playgroundRoute,
  settingsRoute,
])

export const router = createRouter({
  routeTree,
  defaultNotFoundComponent: RouteNotFound,
  defaultErrorComponent: RouteError,
  defaultPendingComponent: RoutePending,
  defaultPendingMs: 120,
  defaultPendingMinMs: 240,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
