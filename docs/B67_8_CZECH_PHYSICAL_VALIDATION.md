# B67.8 - Physical validation on an ordinary, unrestricted network (Czech Republic)

**Status: PHYSICALLY VALIDATED on an ordinary/unrestricted Czech Republic
network only. This is explicitly NOT Russia/restricted-network evidence - see
B67.9, which stays NOT VERIFIED until real restricted-network field evidence
exists.**

This record is written up from the repository owner's own field-test report
of a physical run performed after B67.2-B67.7 landed on `main`. It is recorded
here, in the same evidentiary-record style this roadmap uses for other
physical-validation rows (e.g. `B45B4P_SHADOWSOCKS_SELECTION_PHYSICAL_VALIDATION.md`,
`B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md`), so the claim is traceable
to a named document rather than only to a roadmap table cell. Per this task's
own constraint, no activation ID, credential, activation envelope, private
key, or other secret material is recorded anywhere in this document.

## 1. Environment

- **Device**: OPPO CPH2173, Android 14 (SDK 34), `arm64-v8a`, serial
  `c618ee06`.
- **Network**: Czech Republic, an ordinary/unrestricted network. Both Wi-Fi
  and cellular were available during the test.
- **APK under test**: package `net.pocvpn.client`, `versionCode 1`,
  `versionName 0.1-poc`, SHA-256
  `0b41084c88ee6c877f42e3c17be7a24dc987035068b7bc5118807f5613123e6c`.
- The test was performed against the then-current production-equivalent
  `main` content. No source files were intentionally modified during the
  physical test.

## 2. Flow demonstrated

1. Activation package accepted.
2. Activation succeeded.
3. Device became bound.
4. An entitlement-scoped gateway list was applied (B67.6 eligibility).
5. Frankfurt was eligible for this entitlement.
6. Stockholm was NOT eligible for this entitlement (an explicit negative
   case, not merely the absence of a positive one).
7. Smart Connect (B67.7) selected Frankfurt from the eligible set.
8. Transport connected successfully.
9. The VPN interface became active.
10. Client tunnel IP was `10.77.0.19`.
11. Frankfurt gateway endpoint was `152.70.43.1:2083`.
12. Public exit IP observed from the device was `152.70.43.1`.
13. Reconnect succeeded.
14. IPv4 VPN traffic worked.
15. IPv6 was fail-closed (no IPv6 leak observed).
16. DNS used `1.1.1.1` / `1.0.0.1`.

Server-side, activation status was later confirmed as `devices_bound=1`. The
activation ID exists in server-side records but is intentionally not
reproduced here; no credential or envelope content is reproduced anywhere in
this document.

## 3. What this proves and what it does not

- This is real evidence that the B67.4 (enrollment/activation) -> B67.6
  (entitlement gateway eligibility) -> B67.7 (Smart Connect integration) ->
  connect pipeline works end-to-end on a real device, including a genuine
  negative eligibility case (Stockholm correctly excluded) alongside a
  genuine positive one (Frankfurt correctly selected).
- It is evidence for an **ordinary, unrestricted** network only. It proves
  nothing about hard-whitelist, UDP/AWG filtering, DPI, or any other
  restricted-network condition, and must never be cited as such.
- It is **not** B67.9 (Russia field proof) evidence. Per this roadmap's own
  standing discipline (see the B67.9 row and the "Real restrictive-network/
  Russia behavior" note in the verification table), a Czech/ordinary-network
  test is never generalized into a Russia or restricted-network claim.
- It does not itself constitute physical validation of B67.4's enrollment
  broker in isolation - the broker remains disabled by default and this test
  exercised the activation-package/entitlement/Smart-Connect path, not a
  zero-touch field-enrollment flow. B67.4's own row records enrollment-broker
  physical validation separately as not yet confirmed.

## 4. Test-environment note (not an application defect)

An ADB long-input truncation was observed during the test session. This is a
test-environment/ADB input-injection limitation (`adb shell input text`
truncating very long strings), not a defect in the application under test,
and is recorded here only so it is not misread as an app bug in a future
audit pass.

## 5. Cleanup / infrastructure

No temporary infrastructure changes were made for this test beyond what
B67.2-B67.7's own landed work already required. No production credential,
activation-issuer key, or manifest-signing key was created, modified, or
exposed by this test.
