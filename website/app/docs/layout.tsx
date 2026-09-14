import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import Image from 'next/image';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';

export default function DocumentationLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <DocsLayout
      tree={source.getPageTree()}
      nav={{
        title: (
          <span className="flex items-center gap-2 font-semibold">
            <Image src="/icon.png" width={24} height={24} alt="" priority />
            <span className="authlier-wordmark">
              <span>Auth</span>lier
            </span>
          </span>
        ),
        url: '/',
      }}
      githubUrl="https://github.com/Rahmannugar/authlier"
    >
      {children}
    </DocsLayout>
  );
}
