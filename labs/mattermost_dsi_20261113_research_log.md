# Mattermost DSI — Interactive Dialog Submit and WebSocket Revocation (2026-11-13)

## Surface A: Interactive Dialog Submit SSRF trust-boundary bypass

**Official release:** `mattermost/mattermost-team-edition:12.0.2` (unmodified).
**Status:** VALID LAB REPRODUCTION, **KNOWN UPSTREAM FIX / NOT RECOMMENDED FOR BUG BOUNTY SUBMISSION**.

Proof: https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43515830663

1. Ordinary authenticated user with read permission to public channel sends `POST /api/v4/actions/dialogs/submit` with attacker-selected `url` and valid channel_id.
2. With default `AllowedUntrustedInternalConnections` empty, a URL to an internal probe on `127.0.0.1:19487/owned-internal` is rejected (HTTP 400), no request reaches probe.
3. Same hostname as configured SiteURL (`127.0.0.1`) and `/plugins/owned-internal` on a *different TCP port* unexpectedly uses trusted HTTP client. Probe gets POST, endpoint returns 200. Test confirms `Authorization: Bearer` header is present, but its value is neither printed nor saved.
4. A URL `/plugins-malformed-branch` also gets trusted transport because of broad prefix matching. HTTP 307 redirects from `/plugins/redirect-internal` to `http://127.0.0.2:19487/redirect-final`, and the second loopback probe receives a POST. All addresses are temporary local probes inside the CI runner; no cloud metadata or real internal assets were accessed.
5. An unauthorized private channel ID fails at permission check (403), proving a channel that user can read is needed.

**Root cause in 12.0.2:** `getPostActionClient` at `server/channels/app/integration_action.go` compares target hostname with SiteURL hostname and only checks an unsafe cleaned path prefix before choosing `MakeClient(true)` and forwarding caller token. It ignores port, URL scheme, and redirect destination.

**Crucial Known Issue:** Public Mattermost [PR #39114](https://github.com/mattermost/mattermost/pull/39114), opened 2026-10-13, merged 2026-11-13 20:34:45 UTC, tightens URL matching to scheme + hostname + effective port + exact plugin path prefix and adds redirect restrictions. This directly covers the observed bug family. No claim of uniqueness or non-duplicate can be made; do not submit as novel.

**Limitations:** The captured Bearer token belongs to the test caller, not a separate victim. On real deployments, exploitation of cross-port local services depends on the configured SiteURL hostname resolving to an internal service and on the availability of reachable endpoints. No real-world service compromise proven.

### Files
- https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-dialog-submit-dsi-20261113/labs/mattermost_dialog_submit_dsi.py
- https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-dialog-submit-dsi-20261113/.github/workflows/mattermost-dialog-submit-dsi-20261113.yml

## Surface B: Core WebSocket channel-membership revocation

**Status:** NEGATIVE E2E, EXCLUDED THIS SPECIFIC FLOW.

Proof: https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43516396981

Two configurations tested separately: `EnableWebHubChannelIteration=false` (default) and `true`.
- Before removal, B receives one private-channel `posted` event containing a test canary, positive control.
- A removes B from channel; B's native REST read immediately returns 403.
- A posts two distinct new private canaries, each observed through B's still-connected WebSocket for at least ~2.3 seconds. Neither reaches B (0).
- B receives `user_removed`; direct GET for a later post is 403.

Underlying cache invalidation from `App.RemoveUserFromChannel` to `PlatformService.InvalidateChannelCacheForUser`, `Hub.InvalidateUser`, `WebConn.InvalidateCache` is consistent with observed isolation.

No general claim that every possible race or HA cluster scenario is impossible.

### Files
- https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-ws-revocation-dsi-20261113/labs/mattermost_ws_revocation_dsi.py
- https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-ws-revocation-dsi-20261113/.github/workflows/mattermost-ws-revocation-dsi-20261113.yml

## Surface C: Custom Emoji Upload (code inspection only)

Ordinary authorized users can create custom emojis. `image.DecodeConfig` validates the image; small images (<=128 pixels in both dimensions) are written as original bytes and later returned with `Content-Type: image/${decodedType}`. SVG is not a supported decoder in the visible import set; no browser-executable payload or unauthorized cross-user effect proven. No security finding declared; no E2E executed on this surface.

## Overall classification

- Strong SSRF lab effect confirmed on official 12.0.2 but publicly fixed upstream / known issue.
- WebSocket revocation negative controls completed, no leak.
- Emoji candidate remains exploratory and is not ready.
- **Zero currently unique, non-known, rewardable findings demonstrated in this research session.**
