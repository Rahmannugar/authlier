import { LandingNavigation } from '@/components/landing-navigation';
import { LandingStart } from '@/components/landing-start';
import { getGitHubStarCount } from '@/lib/github';

export default async function HomePage() {
  const starCount = await getGitHubStarCount();

  return (
    <main className="landing">
      <section className="landing-hero">
        <LandingNavigation starCount={starCount} />

        <div className="landing-hero__content">
          <h1>
            Composable authentication
            <span>for Go applications.</span>
          </h1>
          <p>
            Authlier provides email and password authentication, session
            management, MFA, passkeys, OAuth, and SSO through OIDC and SAML.
            Configure the methods your application needs, connect Authlier to
            your database, and mount its HTTP handler in your Go server.
          </p>
        </div>
      </section>

      <LandingStart />
    </main>
  );
}
