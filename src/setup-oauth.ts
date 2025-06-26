import { mkdir, writeFile } from "fs/promises";
import { join } from "path";
import { getClaudeConfigHomeDir } from "./setup-claude-code-settings";
import { execSync } from "child_process";

const OAUTH_TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token';
const CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';

interface OAuthCredentials {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  secretsAdminPat?: string; // optional - used for Secrets Admin API
}

interface TokenRefreshResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  scope?: string;
}

function tokenExpired(expiresAtMs: number): boolean {
  // Add 60 minutes buffer to refresh before actual expiry
  const bufferMs = 60 * 60 * 1000;
  const currentTimeMs = Date.now();
  return currentTimeMs >= (expiresAtMs - bufferMs);
}

async function performRefresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string; expiresAt: number } | null> {
  try {
    const response = await fetch(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
    });

    if (response.ok) {
      const data = await response.json() as TokenRefreshResponse;

      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: (Math.floor(Date.now() / 1000) + data.expires_in) * 1000,
      };
    } else {
      const errorBody = await response.text();
      console.log(`❌ Token refresh failed: ${response.status} - ${errorBody}`);
      return null;
    }
  } catch (error) {
    console.log(`❌ Error making refresh request: ${error instanceof Error ? error.message : error}`);
    return null;
  }
}

function updateGitHubSecrets(secretsAdminPat: string, accessToken: string, refreshToken: string, expiresAt: number) {
  const env = { ...process.env, GH_TOKEN: secretsAdminPat };

  try {
    // Update CLAUDE_ACCESS_TOKEN
    execSync(`gh secret set CLAUDE_ACCESS_TOKEN --body "${accessToken}"`, { env, stdio: 'inherit' });
    console.log('✅ Updated CLAUDE_ACCESS_TOKEN secret');

    // Update CLAUDE_REFRESH_TOKEN
    execSync(`gh secret set CLAUDE_REFRESH_TOKEN --body "${refreshToken}"`, { env, stdio: 'inherit' });
    console.log('✅ Updated CLAUDE_REFRESH_TOKEN secret');

    // Update CLAUDE_EXPIRES_AT
    execSync(`gh secret set CLAUDE_EXPIRES_AT --body "${expiresAt}"`, { env, stdio: 'inherit' });
    console.log('✅ Updated CLAUDE_EXPIRES_AT secret');
  } catch (error) {
    console.error('❌ Failed to update GitHub secrets:', error);
    throw error;
  }
}

export async function setupOAuthCredentials(credentials: OAuthCredentials) {
  const claudeDir = getClaudeConfigHomeDir();
  const credentialsPath = join(claudeDir, ".credentials.json");

  // Create the .claude directory if it doesn't exist
  await mkdir(claudeDir, { recursive: true });

  let accessToken = credentials.accessToken;
  let refreshToken = credentials.refreshToken;
  let expiresAt = parseInt(credentials.expiresAt);

  // Check if token needs refresh
  if (tokenExpired(expiresAt)) {
    if (!credentials.secretsAdminPat) {
      console.warn(`
⚠️  WARNING: OAuth token is expiring soon but SECRETS_ADMIN_PAT is not set!
⚠️
⚠️  The GitHub Action cannot automatically refresh your OAuth tokens without the SECRETS_ADMIN_PAT.
⚠️  Your Claude Code execution may fail if the token expires during the workflow or has expired.
⚠️
⚠️  To enable automatic token refresh:
⚠️  1. Create a Personal Access Token with 'secrets:write' permission
⚠️  2. Add it as a repository secret named SECRETS_ADMIN_PAT
⚠️  3. Pass it to this action using: secrets_admin_pat: \${{ secrets.SECRETS_ADMIN_PAT }}
⚠️
⚠️  For detailed instructions, see:
⚠️  https://github.com/grll/claude-code-login/blob/main/README.md#prerequisites-setting-up-secrets_admin_pat
⚠️
⚠️  Continuing with potentially expired token...
`);
    } else {
      console.log('🔄 Token expired or expiring soon, refreshing...');
      const newTokens = await performRefresh(refreshToken);

      if (newTokens) {
        accessToken = newTokens.accessToken;
        refreshToken = newTokens.refreshToken;
        expiresAt = newTokens.expiresAt;

        console.log('✅ Token refreshed successfully!');

        // Update GitHub secrets with new tokens
        console.log('📝 Updating GitHub secrets with refreshed tokens...');
        updateGitHubSecrets(credentials.secretsAdminPat, accessToken, refreshToken, expiresAt);
      } else {
        console.error('❌ Failed to refresh token, using existing credentials');
      }
    }
  } else {
    const minutesUntilExpiry = Math.round((expiresAt - Date.now()) / 1000 / 60);
    console.log(`✅ Token is still valid (expires in ${minutesUntilExpiry} minutes)`);
  }

  // Create the credentials JSON structure
  const credentialsData = {
    claudeAiOauth: {
      accessToken: accessToken,
      refreshToken: refreshToken,
      expiresAt: expiresAt,
      scopes: ["user:inference", "user:profile"],
    },
  };

  // Write the credentials file
  await writeFile(credentialsPath, JSON.stringify(credentialsData, null, 2));

  console.log(`OAuth credentials written to ${credentialsPath}`);
}
