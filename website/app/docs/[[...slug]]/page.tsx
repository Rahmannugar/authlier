import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
} from 'fumadocs-ui/layouts/docs/page';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { GitHubStars } from '@/components/github-stars';
import { getMDXComponents } from '@/components/mdx';
import { getGitHubStarCount } from '@/lib/github';
import { source } from '@/lib/source';

export default async function DocumentationPage({
  params,
}: PageProps<'/docs/[[...slug]]'>) {
  const { slug } = await params;
  const page = source.getPage(slug);
  if (!page) notFound();

  const Content = page.data.body;
  const starCount = slug ? null : await getGitHubStarCount();

  return (
    <DocsPage toc={page.data.toc} full={page.data.full}>
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      {!slug ? (
        <GitHubStars className="docs-github-stars" starCount={starCount} />
      ) : null}
      <DocsBody>
        <Content components={getMDXComponents()} />
      </DocsBody>
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata({
  params,
}: PageProps<'/docs/[[...slug]]'>): Promise<Metadata> {
  const { slug } = await params;
  const page = source.getPage(slug);
  if (!page) notFound();

  return {
    title: slug ? page.data.title : { absolute: 'Authlier' },
    description: page.data.description,
  };
}
