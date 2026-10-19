# Outbound gateway disconnect recovery: 1.6.17

Scope: SIP handset or HA/browser → gateway → outside number, including handset-first automation callbacks. The reported gateway is 1701. Existing SIP/video routes, gateway registration, dialing prefixes and physical line settings are not changed by this release.

## Corrected failure paths

- The answered outbound Local leg ending now terminates its call instead of being discarded as a helper transition. Only the current answered outbound leg qualifies; ringing retries, stale attempts and unrelated SIP helpers retain their existing behavior.
- Immediate cleanup now addresses real Local halves (`;1` and `;2`), rather than sending an invalid suffix-free channel name. It sends hangup requests without waiting on the AMI event reader; synchronous inspection and retry run separately.
- Missing-peer reconciliation now covers ordinary desk-phone and browser gateway calls, not only handset-first callbacks. It checks the exact conference and its related channels, including the actual selected PJSIP gateway leg; an observer or another call on that gateway cannot conceal a missing peer.
- Ended calls with remaining channels are retried. Failed cleanup retains tracking. Late originate successes after cancellation are released, not adopted as active calls.
- Delayed cleanup of a bound call cannot fall back to endpoint-wide prefixes and terminate a new call on the same gateway. Pending broad prefixes are retired when terminal cleanup begins.
- AMI command errors, incomplete/malformed snapshots and disconnected AMI connections are not evidence that a peer disappeared. Observations reset on unavailable inspection. Both older and newer Asterisk command-response completion formats are handled.

The peer grace is configurable as `asterisk.gateway_peer_grace_sec`, default 20 seconds, valid range 5–300 seconds. With the five-second sweep, persistent missing peers normally recover within approximately 20–25 seconds. Confirmed hangup events initiate immediate cleanup. Healthy long calls, silent calls and held calls are not expired merely because of duration or silence. Pending transfers suspend missing-peer observations and restart the grace afterwards. Existing explicit call-duration rules and RTP timeout settings remain unchanged.

## What a VPS cannot infer

For an analog FXO gateway, outside-party disconnect must become a SIP termination or a detectable loss of the gateway leg. If the physical gateway continues reporting an answered dialog and transmitting RTP after the outside user hangs up, both VPS call legs still look live. A silence timer or arbitrary maximum duration would cut legitimate calls and is not a reliable fix.

That remaining case requires checking the gateway's line-disconnect supervision against the line provider: current disconnect/CPC, polarity supervision or the correct disconnect/busy-tone detection, depending on what the line and firmware actually support. Do not guess a tone cadence or polarity setting globally. The vendor lists busy-tone detection among the FTA5120's FXO features, but this release does not claim that the device's current configuration or provider signals have been verified.

The historical VPS logs contain calls where the handset ended first and 1701 cleared afterwards; that does not establish when the outside party disconnected. During this investigation the supplied private gateway portal `192.168.80.174` was unreachable. No real telephone call was placed, no gateway was rebooted and no physical line settings were changed. Therefore software recovery tests are not certification of 1701's analog disconnect supervision.

Reference: [Flyingvoice FTA5120 specifications](https://www.flyingvoice.com/Uploads/Temp/downloads/20210325/Flyingvoice_FTA5120_Datasheet_v1.1.pdf).

## Repeatable isolated verification

`go test ./...` covers routing, cleanup scope, old/new AMI parsing, invalid inspection, configurable grace, duplicate/stale attempts and ordinary desk-call recovery. `go vet ./...` checks the Go packages.

An explicit Linux test starts a second Asterisk instance in its own temporary directory, uses loopback-only AMI/SIP, and creates two dummy SIP agents with static loopback contacts. It does not use the production Asterisk socket, registrations or phone numbers, even though fixture endpoint labels mirror 3101 and 1701. Test startup waits for the isolated PBX to finish booting, and cleanup kills only that child instance.

```sh
SIMSON_ASTERISK_TEST=1 go test ./server -run TestGatewayRealAsteriskDisconnectLifecycle -v
```

The scenarios verify actual SIP BYE reception by the surviving dummy phone and the absence of remaining PJSIP/Local channels: gateway hangs up, handset hangs up, gateway's Hangup event is lost, all Hangup events are lost (reconciliation), and an originate succeeds after cancellation. Healthy silence and pending-transfer grace are checked without placing any real call.

All five scenarios passed against an isolated instance of the installed Asterisk 16.2.1 engine on 19 October. This tests the real SIP dialogs and Go cleanup code, not physical PSTN supervision.

## Deployment evidence

VPS 1.6.17 was installed on 19 October 2026 at approximately 13:48 IST, with rollback files at `/opt/simson/backups/gateway-disconnect-20261019T081829Z`. The health endpoint reports 1.6.17; production Asterisk PID remained 1606027. Contacts remained 63 before and after deployment. No Asterisk restart, real test call or gateway reboot occurred.

All pre-deploy Asterisk configuration contents and ownership were preserved. Startup generation exposed existing PJSIP-default drift, so the original PJSIP snippet was restored and reloaded. No dialing, codec, transport, RTP timeout or physical gateway settings were intentionally changed. Binary SHA256: `2c45e1653ce8d68defc8d4a69dd877caf51a870fe26a6492e383a6dedfa0359f`.

A read-only Postman request to the public health endpoint passed three assertions: HTTP 200, version 1.6.17 and status `ok`. AMI reconnected successfully and subsequent read-only checks found zero active channels and 1701 registered/reachable. This health evidence does not prove outside-party disconnect on the physical line.

## 1701 gateway inspection and scoped correction

The private portal became reachable later on 19 October and administrator login succeeded. The FTA5120 FVSAS V1.2.10 gateway showed FXO1 idle/connected, FXO2 disconnected and both configured SIP trunks registered.

FXO1 already selected the India (`in`) tone region, but its busy detector used automatic mode, explicitly labelled by this firmware as supporting only 200–500 ms. The stored manual timings were 350 ms on and 350 ms off. The ITU national-tone table specifies India's busy cadence as 400 Hz, 750 ms on / 750 ms off, outside that documented automatic range. This establishes a configuration mismatch with the selected national profile; it is not a measurement of the specific provider's actual disconnect signal.

Only FXO1 was changed through its existing Save & Apply action:

| Field | Before | After |
| --- | --- | --- |
| `DBID_FXO_AUTO_BUSY_DETECT` | 1 (automatic) | 0 (manual) |
| `DBID_FXO_BUSY_DETECT_HOLD` | 350 ms | 750 ms |
| `DBID_FXO_BUSY_DETECT_INTERVAL` | 350 ms | 750 ms |

The three-cycle filter, India region, polarity settings, duration limits, gain, dial plan and SIP settings were retained. Batch configuration and reboot flags were disabled. Readback confirmed exactly these three FXO1 changes, all FXO2 values unchanged and both SIP trunk configurations unchanged (compared using in-memory hashes without logging credentials). Both trunks remained registered and FXO1 returned idle/connected.

The pre-change FXO settings and planned changes are backed up locally in `bin/gateway-1701-fxo-backup-20261019T111011Z.json`, which is outside version control. To restore the earlier detector, select FXO1 only, enable automatic busy detection, restore 350/350 ms and retain count 3; do not apply these values to FXO2 or unrelated gateways.

No real test call was placed and no reboot was requested. Actual outside-party hangup must still be observed on the next normal call. If the provider sends a different cadence or no disconnect tone, measure its supervision signal before further changes rather than adding a blind silence cutoff or changing polarity speculatively.

Reference: [ITU national-tone table, India, page 13](https://www.itu.int/ITU-T/inr/forms/files/tones-0203.pdf).
