import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="flex min-h-full items-center justify-center p-6">
      <div className="text-center">
        <p className="ltr text-6xl font-semibold text-muted">404</p>
        <Link href="/command-center" className="mt-4 inline-block text-accent underline">
          ← Command Center
        </Link>
      </div>
    </main>
  );
}
