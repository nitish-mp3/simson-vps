# Native SIP video: 1.6.16

Ordinary browser-to-extension calls previously originated through a Local channel. Explicitly adding H.264 to that topology triggered invalid audio translator paths on the installed Asterisk 16 engine. Do not restore H.264 seeding on the legacy Local originate.

Eligible enabled video endpoints now originate directly as `PJSIP/<extension>` into `from-simson-video-source`. `simson_video_source` marks the camera and `simson_video_bridge` uses `first_marked` video selection. The browser remains receive-only for SIP video. Gateway/audio routes and the existing direct display automation remain unchanged.

Eligibility deliberately excludes reserved gateways, default-outbound endpoints, auto-answer/speaker, callback bridges, announcements and nonempty duration rules. These features retain their existing routing rather than silently losing behavior. Native media support for those advanced configurations is not claimed.

## Verification

Go tests cover endpoint eligibility, direct AMI PJSIP channel/context/codecs, tracking and conference generation. The integration's explicit manual `frontend/tests/native-video-probe.mjs` starts a separate temporary Asterisk instance with dummy endpoints, loopback signaling and its own RTP range. It never calls production extensions. The fixture is removed afterwards.

The successful probe reported `isolatedAsterisk: true`, `directPJSIP: true`, `framesDecoded: 1`, `audioPackets: 9`, with no errors. Assertions use actual decoded-frame and received-packet counters, not SDP or track presence. This establishes the installed engine's dummy-media path, not physical Akuvox video delivery.

## Deployment on 15 October 2026

VPS 1.6.16 was installed with rollback files at `/opt/simson/backups/native-sip-video-20261015T110551Z`. Health reported 1.6.16, production Asterisk PID remained 1606027, and 69 contacts remained registered before and after deployment. Asterisk was not restarted and no real test call was made.

Startup generation also exposed pre-existing gateway-default drift outside this change. The pre-deploy PJSIP file was restored byte-for-byte and reloaded, preserving gateway configuration; only the new video dialplan/conference definitions were retained. Future generator writes can reapply those existing defaults and should be reviewed separately.

Binary SHA256: `CC7153E5B145D255E96C8621C16182E4478412F08FB433268819F703FE15E170`.
