import { LandingNavigation } from '@/components/landing-navigation';
import { LandingStart } from '@/components/landing-start';

export default function HomePage() {
  return (
    <main className="landing">
      <section className="landing-hero">
        <LandingNavigation />

        <div className="landing-hero__content">
          <h1>
            Composable authentication
            <span>for Go applications.</span>
          </h1>
          <p>
            Add passwords, sessions, MFA, passkeys, OAuth, OIDC, and SAML to
            your Go application through one configurable library, while keeping
            your data and access rules under your control.
          </p>
        </div>
      </section>

      <LandingStart />
    </main>
  );
}
