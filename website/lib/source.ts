import {
  BookOpenIcon,
  BooksIcon,
  BrowserIcon,
  BuildingsIcon,
  DatabaseIcon,
  EnvelopeSimpleIcon,
  FingerprintIcon,
  GearSixIcon,
  GoogleChromeLogoIcon,
  KeyIcon,
  ListBulletsIcon,
  LockKeyIcon,
  PackageIcon,
  RocketLaunchIcon,
  ShieldCheckIcon,
  TreeStructureIcon,
  UserCircleIcon,
} from '@phosphor-icons/react/dist/ssr';
import { loader } from 'fumadocs-core/source';
import { defineDocs } from 'fumadocs-mdx/macro';
import { createElement } from 'react';

const icons = {
  BookOpen: BookOpenIcon,
  Books: BooksIcon,
  Browser: BrowserIcon,
  Buildings: BuildingsIcon,
  Database: DatabaseIcon,
  Email: EnvelopeSimpleIcon,
  Fingerprint: FingerprintIcon,
  Gear: GearSixIcon,
  Google: GoogleChromeLogoIcon,
  Key: KeyIcon,
  List: ListBulletsIcon,
  Lock: LockKeyIcon,
  Package: PackageIcon,
  Rocket: RocketLaunchIcon,
  Shield: ShieldCheckIcon,
  Structure: TreeStructureIcon,
  User: UserCircleIcon,
};

const docs = defineDocs({
  dir: 'content/docs',
});

export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
  icon(name) {
    const Icon = name ? icons[name as keyof typeof icons] : undefined;
    return Icon
      ? createElement(Icon, { size: 18, weight: 'duotone' })
      : undefined;
  },
});
