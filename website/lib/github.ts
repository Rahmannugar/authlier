const AUTHLIER_REPOSITORY_URL =
  'https://api.github.com/repos/Rahmannugar/authlier';

type GitHubRepositoryResponse = {
  stargazers_count?: unknown;
};

export async function getGitHubStarCount(): Promise<number | null> {
  try {
    const response = await fetch(AUTHLIER_REPOSITORY_URL, {
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      next: { revalidate: 3600 },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return null;
    }

    const repository = (await response.json()) as GitHubRepositoryResponse;
    const starCount = repository.stargazers_count;

    return typeof starCount === 'number' &&
      Number.isInteger(starCount) &&
      starCount >= 0
      ? starCount
      : null;
  } catch {
    return null;
  }
}
