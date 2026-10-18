'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function NavLink({
  href,
  index,
  label,
  implemented,
  phase,
}: {
  href: string;
  index: number;
  label: string;
  implemented: boolean;
  phase: number;
}) {
  const active = usePathname() === href;
  return (
    <Link
      href={href}
      aria-current={active ? 'page' : undefined}
      className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition ${active ? 'bg-surface-2 text-fg' : 'text-muted hover:bg-surface-2 hover:text-fg'}`}
    >
      <span className="ltr w-5 text-xs tabular-nums text-muted">{index}</span>
      <span className="flex-1 truncate">{label}</span>
      {!implemented ? (
        <span className="ltr rounded bg-border px-1.5 py-0.5 text-[10px] text-muted">P{phase}</span>
      ) : null}
    </Link>
  );
}
