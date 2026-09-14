'use client';

import { GithubLogoIcon, ListIcon, XIcon } from '@phosphor-icons/react';
import Image from 'next/image';
import Link from 'next/link';
import { useEffect, useState } from 'react';

export function LandingNavigation() {
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    if (!menuOpen) {
      return;
    }

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    }

    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [menuOpen]);

  return (
    <header className={`landing-header${menuOpen ? ' is-open' : ''}`}>
      <nav className="landing-nav" aria-label="Primary navigation">
        <Link
          className="landing-brand"
          href="/"
          onClick={() => setMenuOpen(false)}
        >
          <Image src="/icon.png" width={38} height={38} alt="" priority />
          <span>Authlier</span>
        </Link>

        <div className="landing-nav__links">
          <a href="https://github.com/Rahmannugar/authlier">
            <GithubLogoIcon size={19} weight="bold" aria-hidden="true" />
            GitHub
          </a>
          <Link className="landing-nav__docs" href="/docs/getting-started">
            Get started
          </Link>
        </div>

        <button
          className="landing-nav__menu"
          type="button"
          aria-expanded={menuOpen}
          aria-controls="landing-mobile-menu"
          aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
          onClick={() => setMenuOpen((open) => !open)}
        >
          {menuOpen ? (
            <XIcon size={25} weight="bold" aria-hidden="true" />
          ) : (
            <ListIcon size={25} weight="bold" aria-hidden="true" />
          )}
        </button>
      </nav>

      <div className="landing-mobile-menu" id="landing-mobile-menu">
        <Link
          className="landing-mobile-menu__docs"
          href="/docs/getting-started"
          onClick={() => setMenuOpen(false)}
        >
          Get started
        </Link>
        <a
          className="landing-mobile-menu__github"
          href="https://github.com/Rahmannugar/authlier"
        >
          <GithubLogoIcon size={22} weight="bold" aria-hidden="true" />
          GitHub
        </a>
      </div>
    </header>
  );
}
