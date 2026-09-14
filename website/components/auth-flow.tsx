function FlowArrow({ label }: { label?: string }) {
  return (
    <span className="auth-flow__arrow" aria-hidden="true">
      {label && <small>{label}</small>}
      <span>→</span>
    </span>
  );
}

function FlowStep({ title, detail }: { title: string; detail: string }) {
  return (
    <span className="auth-flow__step">
      <strong>{title}</strong>
      <small>{detail}</small>
    </span>
  );
}

export function AuthFlow() {
  return (
    <figure className="auth-flow">
      <figcaption className="auth-flow__context">
        Authlier is part of your Go server. It does not run as a separate
        service.
      </figcaption>

      <section className="auth-flow__lane" aria-labelledby="sign-in-flow">
        <div className="auth-flow__heading">
          <span>1</span>
          <div>
            <strong id="sign-in-flow">Sign in</strong>
            <small>The Go server creates the authenticated session.</small>
          </div>
        </div>
        <div className="auth-flow__sequence">
          <FlowStep title="Browser client" detail="Sends a sign-in request" />
          <FlowArrow label="HTTP" />
          <div className="auth-flow__server">
            <span className="auth-flow__server-label">Your Go server</span>
            <FlowStep
              title="Authlier handler"
              detail="Verifies the credential and creates a session"
            />
          </div>
          <FlowArrow />
          <FlowStep
            title="Your database"
            detail="Stores users, credentials, and session hashes"
          />
        </div>
        <p className="auth-flow__result">
          Authlier returns the result and an HttpOnly session cookie to the
          browser.
        </p>
      </section>

      <section className="auth-flow__lane" aria-labelledby="session-flow">
        <div className="auth-flow__heading">
          <span>2</span>
          <div>
            <strong id="session-flow">Use the session</strong>
            <small>
              Your server decides what the authenticated user may do.
            </small>
          </div>
        </div>
        <div className="auth-flow__sequence">
          <FlowStep
            title="Browser client"
            detail="Requests one of your application routes"
          />
          <FlowArrow label="Cookie" />
          <div className="auth-flow__server">
            <span className="auth-flow__server-label">Your Go server</span>
            <FlowStep
              title="ResolveSession"
              detail="Validates the session and returns its subject ID"
            />
          </div>
          <FlowArrow />
          <FlowStep
            title="Your application"
            detail="Loads its user data, roles, and permissions"
          />
        </div>
      </section>
    </figure>
  );
}
