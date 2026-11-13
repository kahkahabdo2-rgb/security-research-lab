# Mattermost DSI: OAuth Dynamic Client Registration and Token Redemption
Date: 2026-11-13
Status: **NEGATIVE E2E — NO UNAUTHORIZED IMPACT PROVEN**
Novelty registry: selected from prior untested DCR surface; separate from historic outgoing OAuth, Jira callbacks, interactive-dialog SSRF, SAML, Magic Link, or Desktop token research.

## Official release and isolation
- Image: `mattermost/mattermost-team-edition:12.0.2` unmodified, disposable PostgreSQL.
- Isolated branch: `research/mattermost-dcr-allowlist-dsi-20261113`.
- Exact evidence: https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43524751295 (23 strict-mode E2E checks, all successful; DCR-disabled control also successful).
- Earlier verified config-only run: https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43524436999 (13 strict checks plus 1 disabled-mode check).
- Runnable files: [Python test](https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-dcr-allowlist-dsi-20261113/labs/mattermost_dcr_allowlist_dsi.py), [GitHub Actions workflow](https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-dcr-allowlist-dsi-20261113/.github/workflows/mattermost-dcr-allowlist-dsi-20261113.yml).

## Tested permission and trust transitions
1. Anonymous POST `/api/v4/oauth/apps/register`: accepted when DCR enabled, with approved redirect; declined with `unsupported_operation` when DCR disabled (intended behavior).
2. The real strict administrator allowlist was `ServiceSettings.DCRRedirectURIAllowlist = ["https://approved.example.invalid/cb"]`. The environment override must be spelled `MM_SERVICESETTINGS_DCRREDIRECTURIALLOWLIST`; space-separated values, **not JSON strings**. Earlier attempts accidentally used a mistyped env name and ineffective allowlist; they are **NOT evidence** of a vulnerability.
3. With strict policy applied: wrong host suffix, userinfo authority confusion, lookalike hostname, encoded dot path traversal, path prefix, query, fragment, scheme, explicit default port, multi-callback partial allowlist all returned HTTP 400 and created no clients.
4. Unauthenticated direct OAuth-app detail read returned 401. An unsupported token auth method returned 400.
5. Created two disposable users (the second as ordinary test account) and two distinct public OAuth clients sharing the one allowed test callback; client secrets and tokens were never printed.
6. Ordinary test user attempted to grant a public client access without PKCE: 400. Attempted unregistered redirect URI: 400.
7. Authorized own public OAuth app normally with S256 challenge: 200 redirect with a single-use code; no code value is logged.
8. Redeem A's code using client B: 400 and no token. Redeem A's code using wrong PKCE verifier: 400, no token.
9. Redeem same code with correct client+verifier: 200; own user OAuth access token issued, no refresh token. Reuse the consumed code: 400. Token resolves only to same test user.
10. Attempt to use OAuth-issued session token to grant another client: 403, no code issued.

## Root analysis
- API: `server/channels/api4/oauth.go` DCR enrollment, `server/channels/web/oauth.go` user consent and token exchange.
- Model: `server/public/model/oauth_dcr.go` strict URL-component matching against allowlist; `server/public/model/authorize.go` PKCE constraints.
- App: `server/channels/app/oauth.go` client-specific authorization code, redirect URI equality, PKCE proof, and code consumption.

No working authorization or account boundary bypass, exfiltration, or unexpected role grant found in these tested flows. The admin allowlist is a deliberately optional feature and DCR itself allows anonymous client *registration* when enabled; neither is a vulnerability.

## Prior changes checked
- [#37170](https://github.com/mattermost/mattermost/pull/37170) merged 2026-07-10 to make URL allowlist matching component-aware. Matches our tested class; avoid re-running naive host/path parser variants unless evidence of a new code boundary.
- [#37917](https://github.com/mattermost/mattermost/pull/37917) merged 2026-09-01 for DCR custom URI schemes.
- [#39421](https://github.com/mattermost/mattermost/pull/39421) was open at time of research for custom-scheme OAuth callbacks and PKCE. It describes a known custom-scheme functional limitation; no unique security issue established here.

**EXCLUDE**: This exact DCR allowlist and public-client PKCE/client-boundary flow, unless a different, demonstrably exploitable trust boundary and official E2E security effect arises. No Bugcrowd submission.
