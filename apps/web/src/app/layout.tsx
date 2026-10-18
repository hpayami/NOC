import type { Metadata } from 'next';
import './globals.css';
import { getI18n } from '@/i18n/server';

export const metadata: Metadata = {
  title: { default: 'NOC — Cyber Defense Platform', template: '%s · NOC' },
  description: 'Unified NIDS/NIPS, NOC, SOC and authorized assessment platform',
  robots: { index: false, follow: false },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const { locale, dir } = await getI18n();
  return (
    <html lang={locale} dir={dir} className="h-full">
      <body className="h-full antialiased">{children}</body>
    </html>
  );
}
