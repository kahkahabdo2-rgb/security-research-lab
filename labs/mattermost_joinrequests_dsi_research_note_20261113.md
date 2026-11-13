# Mattermost Deep Surface Investigation — Discoverable Private Channel Cross-Team Metadata Exposure

**Status:** VERIFIED E2E candidate; **NOT SUBMITTED**. Product-intent and program-scope validation still required.
**Date:** 2026-11-13
**Target:** Official, unmodified `mattermost/mattermost-team-edition:12.0.2`
**Image SHA256:** `72d95a56a40134941e9dc46cd5fb4520c107bb55f22410e9d17a681c76b20f93`
**Configuration:** `MM_FEATUREFLAGS_DISCOVERABLECHANNELS=true`; otherwise standard disposable official server and Postgres.
**Evidence:** [Successful official CI E2E run #43495506429](https://github.com/kahkahabdo2-rgb/security-research-lab/actions/runs/43495506429)
**Runnable source:** [mattermost_joinrequests_dsi_20261113.py](https://github.com/kahkahabdo2-rgb/security-research-lab/blob/research/mattermost-joinrequests-dsi-20261113/labs/mattermost_joinrequests_dsi_20261113.py)

## New trust boundary and access conditions

- A owns an **invite-only team T1** and a **private channel C** (`type=P`, `discoverable=true`).
- Channel C's header and purpose contain distinct harmless canaries, controlled by A.
- B is an ordinary authenticated user of another team T2, **not T1** and **not C**.
- C is not ABAC policy-controlled. No commercial features, integration hooks, admin credentials for B, or modifications to production Go source.
- A second private channel D in T1 has `discoverable=false`.

### Direct unauthorized metadata reads

All values below came from the disposable real server, not static inference.

| Ordinary user B request | HTTP | Observed |
|---|---:|---|
| `GET /api/v4/teams/T1/members/B` (checked with A) | 404 | B is not a team member |
| `GET /api/v4/teams/T1` | 403 | Invite-only team is not readable |
| `GET /api/v4/teams/T1/channels` | 403 | No list of team channels |
| `GET /api/v4/channels/C` | **200** | `header` and `purpose` equal A's private test canaries |
| `GET /api/v4/teams/T1/channels/name/CHANNEL_NAME` | **200** | Same private metadata; no channel ID needed |
| `GET /api/v4/teams/name/TEAM_NAME/channels/name/CHANNEL_NAME` | **200** | Same private metadata; team/channel slugs suffice |
| `GET /api/v4/channels/D` | 403 | A non-discoverable private channel remains hidden |
| Anonymous `GET /api/v4/channels/C` | 401 | Authentication is required |
| B `POST /api/v4/posts` to C | 403 | No ability to post to the private channel |
| A `GET /api/v4/channels/C` | 200 | Positive control verifies canaries persisted |
| Same-team non-channel member `GET /api/v4/channels/C` | 200 | Intended discoverable metadata within the team |

**Separate write-side observation:** B outside T1 can `POST /api/v4/channels/C/join_request`, get `201 pending` and trigger an admin-only WebSocket event. Reviewer A cannot approve B's request while B is outside T1 (`404`), and B cannot join or read posts. B cannot approve his own request, and withdrawing the request prevents later approval.

## Multi-component data flow

1. `GET /api/v4/teams/name/{team_name}/channels/name/{channel_name}` is authenticated, but B is not a team member.
2. `server/channels/api4/channel.go` handler `getChannelByNameForTeamName` sees B does not have channel read permission, but calls `serveDiscoverableNonMember` instead of rejecting.
3. `discoverableNonMemberView` calls `App.IsDiscoverableJoinAllowed`.
4. `server/channels/app/channel_discoverable_visibility.go` returns `true` for a private discoverable channel without a policy **without testing membership of the channel's team**.
5. `sanitizeDiscoverableChannel` deliberately includes `Header` and `Purpose`, so the outsider receives them as JSON. It strips other fields such as `Props`.
6. Browser Browse Channels uses `channel.team_id === currentTeamId`, and the team's ordinary API rejects B. The direct endpoint is inconsistent with these same-team discovery restrictions.

### Core source locations

- [getChannel and discoverable fallback](https://github.com/mattermost/mattermost/blob/v12.0.2/server/channels/api4/channel.go#L997-L1150)
- [getChannelByNameForTeamName](https://github.com/mattermost/mattermost/blob/v12.0.2/server/channels/api4/channel.go#L1996-L2035)
- [IsDiscoverableJoinAllowed](https://github.com/mattermost/mattermost/blob/v12.0.2/server/channels/app/channel_discoverable_visibility.go#L253-L280)
- [Join request guard and request persistence](https://github.com/mattermost/mattermost/blob/v12.0.2/server/channels/app/channel_join_request.go#L28-L142)
- [Team membership check on eventual channel addition](https://github.com/mattermost/mattermost/blob/v12.0.2/server/channels/app/channel.go#L2002-L2020)

## Reproduction on official release

1. Launch the official Mattermost 12.0.2 Team Edition image and Postgres as shown in the linked CI workflow; enable `MM_FEATUREFLAGS_DISCOVERABLECHANNELS=true`.
2. Create a new invite-only team T1 as A. Add no membership for B to T1; B is only a user in T2.
3. Create a private channel C in T1 as A with `discoverable:true`, and canary `header` and `purpose`.
4. Authenticate as B and request `GET /api/v4/teams/name/{T1_NAME}/channels/name/{C_NAME}`.
5. Inspect the `200` JSON, matching `header` and `purpose` set by A. Neither team nor channel ID is required if the names are known.
6. Repeat against `discoverable:false` C2; the equivalent direct metadata read returns `403`.
7. Verify `GET /api/v4/teams/{T1}` and `GET /api/v4/teams/{T1}/channels` both return `403` for B, and attempts to post into C return `403`.
8. Use the native Python suite for all controls.

## Risk review / exclusions

**Demonstrated:** Cross-team reading of a private channel's title, header and purpose from an invite-only team when `discoverable=true`, plus creation of a cross-team request-to-join that appears in its admin queue.

**Not demonstrated / not claimed:** Access to channel posts, attachments, Props, members, direct approval bypass, role escalation or code execution.

**By-design question:** Discoverability intentionally reveals limited metadata to *non-channel members*, but the UI browse flow is team-scoped and the invite-only team's own API rejects outsiders. We have not obtained authoritative product confirmation that discoverability is intended to extend to authenticated non-team members. This is a candidate until policy clarified.

**Program scope:** The feature is behind `FeatureFlags.DiscoverableChannels`, explicitly enabled for this test. Verify the program accepts feature-flag-enabled official functionality before filing.

**Duplicate:** Three public GitHub issue searches for cross-team discoverable metadata produced no matches. This does not rule out private Bugcrowd duplicates or unpublished fixes.

**Submission:** Not yet filed. No suggested VRT priority or bounty severity.
