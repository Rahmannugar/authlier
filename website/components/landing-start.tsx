'use client';

import { CheckIcon, CopyIcon } from '@phosphor-icons/react';
import Link from 'next/link';
import { useState } from 'react';

const installCommand = 'go get github.com/Rahmannugar/authlier';

export function LandingStart() {
  const [copied, setCopied] = useState(false);

  async function copyInstallCommand() {
    await navigator.clipboard.writeText(installCommand);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="landing-start" aria-label="Get started">
      <div className="landing-start__inner">
        <Link className="landing-start__docs" href="/docs">
          Read the docs
        </Link>
        <button
          className="landing-start__command"
          type="button"
          onClick={copyInstallCommand}
          aria-label="Copy the Authlier installation command"
        >
          <code>$ {installCommand}</code>
          {copied ? (
            <CheckIcon size={20} weight="bold" aria-hidden="true" />
          ) : (
            <CopyIcon size={20} aria-hidden="true" />
          )}
          <span className="sr-only" aria-live="polite">
            {copied ? 'Copied' : ''}
          </span>
        </button>
      </div>
    </section>
  );
}
