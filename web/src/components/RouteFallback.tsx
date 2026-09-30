import { Link, useRouter } from '@tanstack/react-router'
import type { ErrorComponentProps } from '@tanstack/react-router'

import { Button } from './ui'
import s from './route-fallback.module.scss'

// Shared route-level fallbacks. Keep these outside AppShell so a crash in the
// shell itself can still render a usable recovery screen.
function Fallback({ code, title, message, detail, retry }: {
  code: string
  title: string
  message: string
  detail?: string
  retry?: () => void
}) {
  return (
    <main className={s.wrapper}>
      <div className={s.card}>
        <span className={s.code}>{code}</span>
        <h1 className={s.title}>{title}</h1>
        <p className={s.message}>{message}</p>
        {detail ? <pre className={s.detail}>{detail}</pre> : null}
        <div className={s.actions}>
          {retry ? <Button onClick={retry}>Try again</Button> : null}
          <Link to="/" className={s.home}>Back to dashboard</Link>
        </div>
      </div>
    </main>
  )
}

export function RouteError({ error, reset }: ErrorComponentProps) {
  const router = useRouter()
  const notFound = (error as { status?: number }).status === 404
  return (
    <Fallback
      code={notFound ? '404' : '500'}
      title={notFound ? 'Page not found' : 'Something went wrong'}
      message={notFound ? 'This page does not exist or has been removed.' : 'An unexpected error occurred while rendering this page.'}
      detail={notFound ? undefined : error instanceof Error ? error.message : undefined}
      retry={notFound ? undefined : () => { reset(); void router.invalidate() }}
    />
  )
}

export function RouteNotFound() {
  return <Fallback code="404" title="Page not found" message="Check the URL or return to the dashboard." />
}
