# Mattermost OAuth: Cross-Application Consent Forgery and Post-Revocation Session Persistence

Date: 2026-11-13  
Status: **NATIVE END-TO-END UNAUTHORIZED EFFECT CONFIRMED** (not yet submitted to Bugcrowd).  
Tested official image: `mattermost/mattermost-team-edition:12.0.2`, image ID `sha256:72d95a56a40134941e9dc46cd5fb4520c107bb55f22410e9d17a681c76b20f93`, **production source unmodified**.

## Evidence
- **Final official E2E run (19/19 checks):** https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43527775960
- **Independent preceding full run (18/18 checks):** https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43527542385
- Script: https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-oauth-consent-preference-chain-20261113/labs/mattermost_oauth_consent_preference_chain_20261113.py
- Workflow: https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-oauth-consent-preference-chain-20261113/.github/workflows/mattermost-oauth-consent-preference-chain-20261113.yml

## Preconditions and actor
- Mattermost OAuth Service Provider enabled and Dynamic Client Registration (DCR) enabled (both explicit settings in disposable lab).
- One normal Mattermost user has voluntarily approved OAuth **app A** once; attacker controls A and its legitimately issued OAuth bearer token.
- Other OAuth apps **B** and **C** are newly registered and are *not* individually trusted or authorized by the victim. All app registrations use the same disposable callback `https://approved.example.invalid/cb`, permitted by a strict DCR allowlist. No actual external callback was contacted.
- Victim test user has `system_user` but **not** `system_admin`. A second fully owned user creates private-channel test content. Everything is disposable.

## Proven multi-component attack sequence
1. Ordinary user can read their own private channel post (200); anonymous cannot (401).
2. DCR creates separate untrusted public OAuth apps A, B and C. GET authorization for B under legitimate user session returns 200 consent HTML **without redirect or authorization code**.
3. User explicitly authorizes app A once (PKCE S256). OAuth A gets an access token for that same normal user.
4. OAuth A attempts direct `POST /oauth/authorize` for B, rejected HTTP **403** due to `Session.IsOAuth`. GET authorization for B with the OAuth A token *before preference injection* returns consent HTML 200, no redirect.
5. **Attacker-controlled app A**, using only its OAuth bearer token, executes:
   `PUT /api/v4/users/{victim_user_id}/preferences` with entries `{"user_id":"<victim>","category":"oauth_app","name":"<app_B_id>","value":"user"}` and similarly for C. Returns HTTP **200** and writes the authorization preferences. Read-back confirms B's pref exists. A cannot write another user's prefs (403).
6. App A's **own OAuth bearer token** makes `GET /oauth/authorize?response_type=code&client_id=<B>&redirect_uri=https%3A...&code_challenge=...&code_challenge_method=S256`; because B's forged `oauth_app` preference exists, handler auto-approves and issues HTTP **302 with B's auth code**. No new user/browser interaction needed. This is a GET-path bypass of the explicit POST prohibition.
7. Attacker redeems B's code with B's PKCE verifier at `POST /oauth/access_token` -> **200, new B OAuth bearer token**. Tokens and codes never printed/saved.
8. User revokes *app A* via legitimate `POST /oauth/deauthorize` -> 200. OAuth A token returns **401** on subsequent authenticated requests.
9. **App B token still reads the victim's private channel post** after A revocation -> **200 with exact lab canary**. A token cannot read same content -> 401.
10. As an independent state-transition control, after A revocation victim's normal browser simply GETs app C's authorization URL; C receives code via 302 without separate consent. C exchanges for *fresh* token -> 200 and reads same private post -> 200. Thus forged trust persists for *both* new and existing access.

## Why this is not a simple authorized-user API operation
- Legitimate OAuth apps may use the consenting user's standard API permissions. But the explicit security boundary preventing OAuth-session-to-OAuth-session chaining (`POST /oauth/authorize` -> 403) is bypassed via **generic Preferences write** and the **auto-consent GET branch**, not by the user approving app B or C.
- Result is a second app's independent bearer token that remains valid after the user revokes A. That is durable third-party access outside the approved app lifecycle.
- No need to control someone else's cookies, credentials, server filesystem, or admin role. The initial user consent to A is a required condition; no subsequent consent/visit is needed to create B's access.

## Source-level cross-component root cause (v12.0.2)
- `server/channels/api4/preference.go`, `updatePreferences`: accepts arbitrary preference category except targeted check for `flagged_post`, and allows same-user writes from OAuth sessions.
- `server/channels/app/preference.go`, `UpdatePreferences`: validates `UserId` matches, then stores category `oauth_app` without proving it originated from OAuth consent.
- `server/public/model/preference.go`: defines `PreferenceCategoryAuthorizedOAuthApp = "oauth_app"`; only generic shape/value checks.
- `server/channels/web/oauth.go`, `authorizeOAuthApp`: rejects `c.AppContext.Session().IsOAuth` with 403 on **POST**.
- `server/channels/web/oauth.go`, `authorizeOAuthPage`: **GET** treats the existence of category `oauth_app` with client ID as preexisting consent and calls `AllowOAuthAppAccessToUser` automatically, without parallel OAuth-session prohibition.
- `server/channels/app/oauth.go`, `DeauthorizeOAuthAppForUser`: revokes only A's access data/session and only A's authorization preference, not separately planted B/C approvals.
- `server/channels/app/oauth.go`, `GetOAuthAccessTokenForCodeFlow`: code exchange issues B/C OAuth sessions in the original user context; independent OAuth application association.

The source segments above also remain conceptually present on publicly visible `master` at time of checking, but that cannot disprove private disclosure/duplicates.

## Reproduction integrity and limitations
- 19/19 final checks passed, including role control, original consent absence, direct OAuth POST denial, cross-user denial, real OAuth B token, explicit A revocation, and B/C private-content read.
- Only local owned users, temporary OAuth apps and one private-channel canary; no real user data or external systems were accessed. Secrets/codes never output to CI logs.
- DCR was enabled and strict redirect allowlist configured; cannot claim default DCR-enabled deployment. Under a non-DCR deployment the attacker would need another legitimate way to have app B registered; not tested.
- Existing user consent to OAuth A is a prerequisite; no account take-over without that authorization is claimed.
- **No private Bugcrowd duplicate search available here.** Do not claim unique or guaranteed rewardable merely from public GitHub searches. Submission would require checking the live engagement's targets/constraints.

## Not the same as prior DCR allowlist audit
Earlier DCR-only negative checks covered URL registration and PKCE. This finding crosses **authorized OAuth A session -> special preference storage -> OAuth GET auto-approval for different client B -> revocation -> durable independent private data access**. An observable unauthorized post-revocation effect was demonstrated.
