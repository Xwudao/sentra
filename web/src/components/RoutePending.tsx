import { Spinner } from './ui'
import s from './route-pending.module.scss'

export function RoutePending() {
  return <div className={s.pending}><Spinner label="Loading page" /></div>
}
