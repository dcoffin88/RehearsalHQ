/**
 * Version and GitHub release tracking utilities for RehearsalHQ
 * Repository: https://github.com/dcoffin88/RehearsalHQ
 */

export const CURRENT_APP_VERSION = '1.2.1';
export const GITHUB_REPO_OWNER = 'dcoffin88';
export const GITHUB_REPO_NAME = 'RehearsalHQ';
export const GITHUB_REPO_URL = `https://github.com/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}`;
export const GITHUB_LATEST_RELEASE_URL = `${GITHUB_REPO_URL}/releases/latest`;
export const GITHUB_API_RELEASE_URL = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/releases/latest`;

export interface AppVersionInfo {
  currentVersion: string;
  latestVersion: string;
  latestTag: string;
  updateAvailable: boolean;
  releaseName: string;
  releaseUrl: string;
  publishedAt: string | null;
  body?: string;
  checkedAt: string;
  repoUrl: string;
  error?: string;
}

/**
 * Compare two semver strings (e.g., '1.0.1' and '1.0.2').
 * Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if equal.
 */
export function compareSemver(v1: string, v2: string): number {
  const clean = (v: string) =>
    (v || '')
      .trim()
      .replace(/^v/i, '')
      .split('-')[0]
      .split('.')
      .map((n) => parseInt(n, 10) || 0);

  const parts1 = clean(v1);
  const parts2 = clean(v2);
  const maxLen = Math.max(parts1.length, parts2.length);

  for (let i = 0; i < maxLen; i++) {
    const p1 = parts1[i] ?? 0;
    const p2 = parts2[i] ?? 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

const STORAGE_KEY = 'rehearsalhq_version_cache_v1';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes cache

/**
 * Check GitHub releases for updates with multi-layer fallback:
 * 1. Local backend proxy endpoint /api/version/check
 * 2. Direct client-side fetch to GitHub API with CORS
 * 3. Graceful offline fallback with cached release data
 */
export async function fetchVersionInfo(force = false): Promise<AppVersionInfo> {
  // Check cached data if not forcing refresh
  if (!force && typeof window !== 'undefined') {
    try {
      const cachedRaw = localStorage.getItem(STORAGE_KEY);
      if (cachedRaw) {
        const cached = JSON.parse(cachedRaw);
        if (Date.now() - new Date(cached.checkedAt).getTime() < CACHE_TTL_MS) {
          // Re-evaluate updateAvailable in case CURRENT_APP_VERSION changed
          return {
            ...cached,
            currentVersion: CURRENT_APP_VERSION,
            updateAvailable: compareSemver(cached.latestVersion, CURRENT_APP_VERSION) > 0,
          };
        }
      }
    } catch {
      // Ignore cache parse errors
    }
  }

  // Attempt 1: Internal API route
  try {
    const res = await fetch('/api/version/check', {
      headers: {
        'x-rehearsalhq-request': '1',
      },
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.latestVersion) {
        const result: AppVersionInfo = {
          currentVersion: CURRENT_APP_VERSION,
          latestVersion: data.latestVersion,
          latestTag: data.latestTag || `v${data.latestVersion}`,
          updateAvailable: compareSemver(data.latestVersion, CURRENT_APP_VERSION) > 0,
          releaseName: data.releaseName || `RehearsalHQ ${data.latestTag || data.latestVersion}`,
          releaseUrl: data.releaseUrl || GITHUB_LATEST_RELEASE_URL,
          publishedAt: data.publishedAt || null,
          body: data.body || '',
          checkedAt: new Date().toISOString(),
          repoUrl: GITHUB_REPO_URL,
        };
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(result));
        } catch {}
        return result;
      }
    }
  } catch {
    // Proceed to direct fallback
  }

  // Attempt 2: Direct GitHub API
  try {
    const res = await fetch(GITHUB_API_RELEASE_URL, {
      headers: {
        Accept: 'application/vnd.github.v3+json',
      },
      signal: AbortSignal.timeout(5000),
    });

    if (res.ok) {
      const release = await res.json();
      const latestTag = String(release.tag_name || release.name || '').trim();
      const latestVersion = latestTag.replace(/^v/i, '') || CURRENT_APP_VERSION;

      const result: AppVersionInfo = {
        currentVersion: CURRENT_APP_VERSION,
        latestVersion,
        latestTag: latestTag || `v${latestVersion}`,
        updateAvailable: compareSemver(latestVersion, CURRENT_APP_VERSION) > 0,
        releaseName: release.name || latestTag || `RehearsalHQ v${latestVersion}`,
        releaseUrl: release.html_url || GITHUB_LATEST_RELEASE_URL,
        publishedAt: release.published_at || release.created_at || null,
        body: (release.body || '').slice(0, 1000),
        checkedAt: new Date().toISOString(),
        repoUrl: GITHUB_REPO_URL,
      };

      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(result));
      } catch {}
      return result;
    }
  } catch {
    // Fall back to offline/current state
  }

  // Fallback: Current version
  const fallbackResult: AppVersionInfo = {
    currentVersion: CURRENT_APP_VERSION,
    latestVersion: CURRENT_APP_VERSION,
    latestTag: `v${CURRENT_APP_VERSION}`,
    updateAvailable: false,
    releaseName: `RehearsalHQ v${CURRENT_APP_VERSION}`,
    releaseUrl: GITHUB_LATEST_RELEASE_URL,
    publishedAt: null,
    body: '',
    checkedAt: new Date().toISOString(),
    repoUrl: GITHUB_REPO_URL,
  };
  return fallbackResult;
}
