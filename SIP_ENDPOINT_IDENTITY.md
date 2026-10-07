# SIP endpoint identity compatibility — VPS 1.6.15

On 7 October 2026, legitimate direct SIP calls to 1026, 1027, 1603, 1605 and 1028 were rejected. Asterisk logged `Unknown or unavailable item requested: 'pjsip,endpoint'` followed by an account-guard rejection with an empty endpoint identity. The security guard was reading an unsupported accessor on the installed Asterisk 16.2.1 engine.

Use `${CHANNEL(endpoint)}` to read the endpoint selected by Asterisk. The same supported accessor is used in incoming/direct-call events, source matching, conference authorization and supervision. Do not replace authenticated endpoint identity with caller ID, From headers, a blanket allow rule or anonymous access. Same-account restrictions and trusted internal Local-channel compatibility remain intact.

Version 1.6.15 was deployed with an online database backup and binary/configuration rollback files at `/opt/simson/backups/endpoint-identity-20261007T101750Z`. Asterisk PID stayed unchanged, generated PJSIP endpoint configuration stayed byte-identical, and the contact count was 71 before and after deployment. The loaded dialplan contains the supported accessor. No telephone test calls were placed; handset-to-handset confirmation remains a user check.

Regression tests cover same-account enabled sources, rejection of foreign/disabled/caller-ID identities, guard ordering, and supported endpoint identity in generated lifecycle events. All Go tests passed before deployment.

Reference: [Asterisk CHANNEL function](https://docs.asterisk.org/Latest_API/API_Documentation/Dialplan_Functions/CHANNEL/). The installed engine's `core show function CHANNEL` output also documents the `endpoint` item.
