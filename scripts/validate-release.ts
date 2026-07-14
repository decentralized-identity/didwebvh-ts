import { execSync } from 'node:child_process';

type SemVer = { major: number; minor: number; patch: number };

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var ${name}`);
  return value;
}

export function parseTag(tag: string): SemVer | null {
  const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(tag);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export function cmp(a: SemVer, b: SemVer): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

export function isSingleSemverBump(prev: SemVer, next: SemVer): boolean {
  // patch
  if (next.major === prev.major && next.minor === prev.minor && next.patch === prev.patch + 1) {
    return true;
  }
  // minor (patch resets to 0)
  if (next.major === prev.major && next.minor === prev.minor + 1 && next.patch === 0) {
    return true;
  }
  // major (minor/patch reset to 0)
  if (next.major === prev.major + 1 && next.minor === 0 && next.patch === 0) {
    return true;
  }
  return false;
}

async function ghJson(url: string, token: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub API request failed (${res.status}) for ${url}\n${body}`);
  }
  return await res.json();
}

export function getLatestStrictSemverTagBefore(allTags: string[], nextTag: string): string | null {
  const next = parseTag(nextTag);
  if (!next) return null;

  const parsed = allTags
    .map((t) => ({ tag: t, v: parseTag(t) }))
    .filter((x): x is { tag: string; v: SemVer } => x.v !== null)
    .map((x) => ({ tag: x.tag, v: x.v }));

  let best = null;
  for (const item of parsed) {
    if (item.tag === nextTag) continue; // exclude current tag
    if (cmp(item.v, next) >= 0) continue; // only consider tags strictly lower than next
    if (!best || cmp(item.v, best.v) > 0) best = item;
  }
  return best?.tag ?? null;
}

async function main() {
  const tag = requireEnv('TAG_NAME');
  const repo = requireEnv('REPO'); // owner/repo
  const actor = requireEnv('ACTOR');
  const ghToken = requireEnv('GH_TOKEN');

  console.log(`Tag: ${tag}`);
  console.log(`Actor: ${actor}`);

  const next = parseTag(tag);
  if (!next) {
    throw new Error(`Release tag must be vMAJOR.MINOR.PATCH (example: v2.7.5). Got: ${tag}`);
  }

  const perm = await ghJson(`https://api.github.com/repos/${repo}/collaborators/${actor}/permission`, ghToken);
  const permission = (perm?.permission as string) ?? '';
  if (!['admin', 'maintain', 'write'].includes(permission)) {
    throw new Error(`${actor} must have write/maintain/admin permission to publish. Detected: '${permission}'`);
  }

  execSync('git fetch --tags --force', { stdio: 'inherit' });
  const allTags = execSync("git tag -l 'v*'", {
    encoding: 'utf8',
  })
    .split('\n')
    .map((t) => t.trim())
    .filter(Boolean);

  const latestTag = getLatestStrictSemverTagBefore(allTags, tag);

  if (!latestTag) {
    const hasAnyStrict = allTags.some((t) => parseTag(t));
    if (!hasAnyStrict) {
      console.log('No prior strict semver tags found; allowing first release.');
      return;
    }
    throw new Error(`Tag ${tag} must be greater than all existing strict semver tags.`);
  }

  const prev = parseTag(latestTag);
  if (!prev) throw new Error(`Latest strict tag is not semver (unexpected): ${latestTag}`);
  if (cmp(next, prev) <= 0) throw new Error(`Tag ${tag} must be greater than latest ${latestTag}`);
  if (!isSingleSemverBump(prev, next)) {
    throw new Error(`Tag ${tag} must be a single major/minor/patch bump from ${latestTag}`);
  }

  console.log(`Semver bump ok: ${latestTag} -> ${tag}`);
}

import { fileURLToPath } from 'node:url';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main().catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`ERROR: ${message}`);
    process.exit(1);
  });
}
