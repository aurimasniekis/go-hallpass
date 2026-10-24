/**
 * Well-known git hosts. Fingerprints are the providers' published SSH host key fingerprints; a scanned key is only
 * marked as matching when it is byte-for-byte one of them, and the operator still confirms it.
 */
export interface GitHostPreset {
  id: string;
  name: string;
  alias: string;
  address: string;
  port: number;
  fingerprints: string[];
  /** Where the provider publishes its host key fingerprints. */
  fingerprintsUrl: string;
  /** How to install a profile's login key on this host. */
  keyHint: string;
}

export const GIT_HOST_PRESETS: GitHostPreset[] = [
  {
    id: 'github',
    name: 'GitHub',
    alias: 'github',
    address: 'github.com',
    port: 22,
    fingerprints: [
      'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU',
      'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM',
      'SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s',
    ],
    fingerprintsUrl:
      'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints',
    keyHint:
      'Add the public key as a deploy key on each repository (tick "Allow write access" for push profiles), or to a machine user that has access to the repositories.',
  },
  {
    id: 'gitlab',
    name: 'GitLab.com',
    alias: 'gitlab',
    address: 'gitlab.com',
    port: 22,
    fingerprints: [
      'SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8',
      'SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw',
      'SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ',
    ],
    fingerprintsUrl: 'https://docs.gitlab.com/ee/user/gitlab_com/#ssh-host-keys-fingerprints',
    keyHint:
      'Add the public key as a deploy key on each project (enable "Grant write permissions" for push profiles), or to a bot user with access to the projects.',
  },
  {
    id: 'bitbucket',
    name: 'Bitbucket Cloud',
    alias: 'bitbucket',
    address: 'bitbucket.org',
    port: 22,
    fingerprints: [
      'SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM',
      'SHA256:FC73VB6C4OQLSCrjEayhMp9UMxS97caD/Yyi2bhW/J0',
      'SHA256:46OSHA1Rmj8E8ERTC6xkNcmGOw9oFxYr0WF6zWW8l1E',
    ],
    fingerprintsUrl: 'https://bitbucket.org/site/ssh',
    keyHint:
      'Add the public key as an access key on each repository (read-only), or to a bot account for push profiles.',
  },
];

export const CUSTOM_KEY_HINT =
  "Add the public key to the account the git host uses for these repositories (for plain git over SSH, that user's authorized_keys).";

/** The preset whose host the server points at, if any. */
export function presetFor(address: string | undefined): GitHostPreset | undefined {
  const host = (address ?? '').toLowerCase();
  return GIT_HOST_PRESETS.find((p) => p.address === host);
}
