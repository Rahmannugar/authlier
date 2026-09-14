'use client';

import { GithubLogoIcon, StarIcon } from '@phosphor-icons/react';

const AUTHLIER_GITHUB_URL = 'https://github.com/Rahmannugar/authlier';

type GitHubStarsProps = {
  className?: string;
  starCount: number | null;
};

export function GitHubStars({ className, starCount }: GitHubStarsProps) {
  const formattedStarCount = starCount?.toLocaleString('en-US');
  const accessibleLabel =
    starCount === null
      ? 'View Authlier on GitHub'
      : `View Authlier on GitHub, ${formattedStarCount} ${
          starCount === 1 ? 'star' : 'stars'
        }`;

  return (
    <a
      className={className}
      href={AUTHLIER_GITHUB_URL}
      aria-label={accessibleLabel}
    >
      <GithubLogoIcon size={19} weight="bold" aria-hidden="true" />
      <span>GitHub</span>
      {formattedStarCount ? (
        <span className="github-stars__count" aria-hidden="true">
          <StarIcon size={15} weight="fill" />
          {formattedStarCount}
        </span>
      ) : null}
    </a>
  );
}
