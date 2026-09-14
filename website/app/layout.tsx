import { RootProvider } from 'fumadocs-ui/provider/next';
import type { Metadata } from 'next';
import localFont from 'next/font/local';
import type { ReactNode } from 'react';
import './global.css';

const bricolageGrotesque = localFont({
  src: './fonts/bricolage-grotesque-variable.ttf',
  variable: '--font-bricolage-grotesque',
  weight: '200 800',
  display: 'swap',
});

const onest = localFont({
  src: './fonts/onest-variable.ttf',
  variable: '--font-onest',
  weight: '100 900',
  display: 'swap',
});

export const metadata: Metadata = {
  metadataBase: new URL('https://authlier.vercel.app'),
  title: {
    default: 'Authlier',
    template: '%s | Authlier',
  },
  description: 'Composable authentication for Go applications.',
  openGraph: {
    title: 'Authlier',
    description: 'Composable authentication for Go applications.',
    siteName: 'Authlier',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authlier',
    description: 'Composable authentication for Go applications.',
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${bricolageGrotesque.variable} ${onest.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
