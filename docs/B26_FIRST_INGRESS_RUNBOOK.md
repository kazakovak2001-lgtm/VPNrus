# B26 - first real DIRECT_IP ingress deployment runbook

Precise, executable sequence for the FIRST real ingress deployment. None of
these steps have been performed yet - see ROADMAP's B26 row. Do not run
step 1 (host provisioning) or any step past 6 without the repository
owner's explicit approval, per this repository's merge/infra-safety rule.

Every command below assumes the pinned EXIT this ingress relays to already
exists and is reachable (Frankfurt or Stockholm - see the read-only
suitability assessment in ROADMAP's B26 row / this PR's own report).

## 1. Provision a clean Ubuntu host

Operator/owner action, out of band (a fresh VPS - Hetzner/OVH/Oracle/etc,
Ubuntu 22.04+ recommended). Record its public IPv4 - this becomes
`NOVA_INGRESS_ENDPOINT_HOST`/`public_host`.

## 2. Install the ingress role

```bash
git clone <this repo> /tmp/nova-vpn-src   # or scp a release tarball
sudo /tmp/nova-vpn-src/gateway/scripts/install-ingress-role.sh --repo-root /tmp/nova-vpn-src
```

Creates users/groups, installs application code read-only under
`/opt/pocvpn/gateway`, the privileged wrapper, the sudoers drop-in
(`visudo`-validated before install), `/etc/pocvpn/ingress.env` (seeded from
the tracked template, not yet filled in), state directories, and the two
systemd units - nothing is started yet.

## 3. Configure ingress secrets

Step 2's `install-ingress-role.sh` already fetched and verified the pinned
xray-core binary at `/opt/pocvpn/xray/<XRAY_CORE_TAG>/xray` (see
`gateway/xray/VERSION`/`fetch-xray-server.sh`) - never a manual symlink to
whatever `xray` a host happens to already have installed for an unrelated
role.

```bash
# REALITY keypair for this ingress's own client-facing inbound (use the
# EXACT path fetch-xray-server.sh reported, matching gateway/xray/VERSION's
# current XRAY_CORE_TAG):
/opt/pocvpn/xray/*/xray x25519   # prints a private/public pair
# write the PRIVATE half only - owned by pocvpn-api (this process, not
# root, is what actually reads it at activation time) and mode 0600
# (B31A: ingress_preflight.py requires STRICT 0600, not merely
# group-readable - see that check's own docs):
sudo install -o pocvpn-api -g pocvpn-api -m 0600 /dev/stdin /etc/pocvpn/ingress/reality-private-key.txt <<< '<private key>'
```

Edit `/etc/pocvpn/ingress.env`: fill in `NOVA_INGRESS_ENDPOINT_ID`,
`NOVA_INGRESS_ENDPOINT_HOST`, `NOVA_INGRESS_SERVER_NAME`/`DEST` (a real,
unrelated, always-on HTTPS camouflage domain), `NOVA_INGRESS_SHORT_ID`,
`NOVA_INGRESS_REALITY_PUBLIC_KEY` (the public half just generated).

## 4. Configure the dedicated upstream EXIT identity

On any trusted machine (operator's own laptop, never the ingress host
itself, so the exit-fragment file never touches the ingress host at all):

```bash
python3 gateway/tools/provision_relay_upstream_identity.py \
    --ingress-endpoint-id <NOVA_INGRESS_ENDPOINT_ID> \
    --upstream-uuid-file /tmp/upstream-relay-uuid.txt \
    --exit-fragment-file /tmp/exit-fragment.json \
    --probe-hmac-secret-file /tmp/probe-hmac-secret.txt
```

Transfer (scp over an already-authenticated channel, never email/chat/PR):
- `/tmp/upstream-relay-uuid.txt` -> the ingress host, at the path
  `NOVA_INGRESS_UPSTREAM_UUID_FILE` names (0600, owned by `pocvpn-api` -
  same B31A convention as step 3's REALITY private key: this process
  itself reads the file, so it must be the file's own OWNER, not merely
  in its group);
- `/tmp/probe-hmac-secret.txt` -> the ingress host, at the path
  `NOVA_INGRESS_PROBE_HMAC_SECRET_FILE` names (same 0600 `pocvpn-api`-owned
  convention);
- `/tmp/exit-fragment.json` -> the EXIT operator (out of band).

```bash
# on the ingress host, after transferring both files above:
sudo chown pocvpn-api:pocvpn-api /etc/pocvpn/ingress/upstream-relay-uuid.txt /etc/pocvpn/ingress/probe-hmac-secret.txt
sudo chmod 0600 /etc/pocvpn/ingress/upstream-relay-uuid.txt /etc/pocvpn/ingress/probe-hmac-secret.txt
```

Fill in `NOVA_INGRESS_UPSTREAM_HOST`/`PORT`/`TRANSPORT`/`SERVER_NAME`/
`PUBLIC_KEY`/`SHORT_ID` (the pinned EXIT's own real REALITY facts) and
`NOVA_INGRESS_EXIT_ENDPOINT_ID`/`NOVA_INGRESS_EXIT_PROBE_HOST` in
`/etc/pocvpn/ingress.env`.

## 5. Apply exit authorization (on the EXIT host, by its own operator)

```bash
# on the EXIT host:
python3 gateway/tools/apply_relay_upstream_identity.py apply \
    --static-clients-file <this EXIT's POCVPN_API_STATIC_RELAY_CLIENTS_FILE> \
    --exit-fragment-file /tmp/exit-fragment.json
# copy the SAME probe-hmac-secret.txt contents (byte-for-byte) to this
# EXIT's own POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE path, then:
python3 gateway/tools/xray_reconcile.py --env-file /etc/pocvpn/api.env
```

Requires the EXIT operator's own explicit approval and access - this step
is never performed by the ingress host or automated by this repository.

## 6. Start the ingress

B31A: every durable store/lock below is initialized AS THE `pocvpn-api`
USER (`sudo -u pocvpn-api`), never plain root - a store/lock file created
by root cannot be written by the `pocvpn-api-ingress` service itself
afterward (found live on the first real deployment: this is exactly what
left the durable state directories unwritable even after
`install-ingress-role.sh`'s own directory-level `chown`, until every file
inside them was individually re-owned by hand). This also includes the
GLOBAL activation lock (`NOVA_INGRESS_ACTIVATION_GLOBAL_LOCK_PATH`) - a
step this runbook previously omitted entirely, which fails the very first
real `/v1/ingress-profile` request with "activation lock not found - run
'init' first" until created.

```bash
# on the ingress host, as operator/root, using sudo -u for each actual
# store/lock file so pocvpn-api ends up owning every one of them:
sudo -u pocvpn-api python3 gateway/tools/activation_tokens.py --store <NOVA_INGRESS_ACTIVATION_STORE_PATH> \
    --lock <NOVA_INGRESS_ACTIVATION_LOCK_PATH> init
cd /opt/pocvpn/gateway && sudo -u pocvpn-api python3 -c \
    "from api import xray_provisioning; xray_provisioning.init_store('<NOVA_INGRESS_XRAY_STORE_PATH>', '<NOVA_INGRESS_XRAY_LOCK_PATH>')"
cd /opt/pocvpn/gateway && sudo -u pocvpn-api python3 -c \
    "from api import xray_activation; xray_activation.init_activation_lock('<NOVA_INGRESS_ACTIVATION_GLOBAL_LOCK_PATH>')"
python3 gateway/tools/ingress_preflight.py --env-file /etc/pocvpn/ingress.env   # must PASS
sudo systemctl enable --now pocvpn-api-ingress.service
python3 gateway/tools/ingress_reconcile.py --env-file /etc/pocvpn/ingress.env  # first real activation, starts nova-xray-ingress.service
```

**>>> HUMAN APPROVAL GATE: everything above this line is repository-side /
mechanical. Steps 7+ require the repository owner's explicit go-ahead to
touch the chosen ingress host and a physical Android device. <<<**

## 7. Verify ingress preflight/status

```bash
python3 gateway/tools/ingress_preflight.py --env-file /etc/pocvpn/ingress.env
python3 gateway/tools/ingress_status.py --env-file /etc/pocvpn/ingress.env
```

Both must report healthy/configured/activated before proceeding.

## 8. Add secret-free ingress endpoint metadata/config

Author a real `docs/ingress_deployment_descriptor.example.json`-shaped
descriptor for this host (see `docs/B26_INGRESS_DEPLOYMENT_DESCRIPTOR.md`).
Do NOT fold it into the signed production manifest yet - only after steps
9-15 below physically succeed.

## 9. Activate the physical Android device

Issue an activation credential the same way any gateway's is
(`gateway/tools/activation_tokens.py issue` against THIS ingress's own
store), then, ON THE DEVICE, attempt a real Auto connect toward this
ingress (e.g. by making it the only/best-ranked relayed candidate once
step 8's descriptor is folded into a real manifest entry - see step 11).
The app itself surfaces the activation prompt automatically: the first
relayed Auto attempt against an unprovisioned ingress fails closed with
`PROFILE_NOT_PROVISIONED`, which `MainViewModel` turns into a real,
product-visible `ActivationScreen` (the SAME screen every other gateway's
activation already uses - only the ordinary activation credential is ever
entered, never a UUID/REALITY-key/probe-token). Enter the credential and
submit - no manual profile/UUID/key paste exists or is needed.

## 10. Fetch/store ingress profile

Submitting the credential runs `MainViewModel.activateIngress`, which calls
`POST /v1/ingress-profile` and, on success, persists the returned
`IngressClientProfile` via `FileIngressProfileStore`, then automatically
retries the connect flow once - confirm via `MainViewModel
.ingressActivationState` (or just watch the app: the activation screen
dismisses itself and a fresh connect attempt starts) that the outcome was
`Saved`.

## 11. Auto builds a relayed candidate

Requires this ingress's endpoint to be present in the device's TRUSTED
manifest (embedded bootstrap or a real signed update) with a `relayTo`
target naming the pinned EXIT - see `AutoGatewaySelector.buildRelayedCandidates`.
Not possible until step 8's descriptor becomes a real signed manifest entry.

## 12. Client connects to ingress

A real `RelayIngressResolverImpl.resolve()` call returns `Resolved`
(profile matched, not expired) and `VpnController`/`TransportOrchestrator`
dial the SAME way a Direct candidate would.

## 13. Ingress connects to exit

Observed indirectly: the ingress's own `nova-xray-ingress.service` opens
its configured upstream VLESS connection to the pinned EXIT as part of
serving the client's tunneled traffic - confirm via `ingress_status.py`'s
`active_client_count` and, on the EXIT, that host's own connection logs.

## 14. Real E2E probe succeeds

`HttpRelayEndToEndProbe` calls `GET /v1/relay-health` on the pinned EXIT
with the profile's `endToEndProbeToken`, over the just-established tunnel -
must return HTTP 200 with a body containing this attempt's `historyPathId`.

## 15. VpnSessionHealth becomes RelayProtected

Confirm in-app (or via the existing debug diagnostics) that session health
reads `RelayProtected`, not merely `RelayHandshake`.

## 16. Verify public IP == chosen EXIT, NOT ingress

From the device, hit a real IP-echo endpoint (e.g. `https://cdn-cgi/trace`
style check already used elsewhere in this repo's own physical-validation
history) and confirm the returned IP matches the EXIT's public IP, never
the ingress's.

## 17. DNS test

Confirm DNS resolution succeeds through the tunnel and does not leak to
the device's original resolver.

## 18. IPv6 fail-closed test

Confirm no IPv6 route/leak exists through the relayed session (same
invariant already proven for Direct - see PROJECT_ARCHITECTURE.md's B18
section).

## 19. Deliberate upstream failure test

Reversible, ingress-host-local fault only (e.g. temporarily block the
ingress's outbound to the EXIT's Xray port via a host firewall rule) -
never touch the EXIT itself. Confirm the client's E2E probe fails and the
attempt is recorded as a failure under the FULL `historyPathId`.

## 20. Verify fallback to next combined candidate

Confirm `attemptCombined()` advances to the next globally-ranked candidate
(Direct or another relayed path) rather than stalling - restore the fault
afterward and confirm normal reconnect.

---

**Do not mark any of steps 7-20 as completed until physically performed.**
Completing steps 1-6 makes the repository/software side DEPLOYMENT READY;
it does NOT constitute physical verification, and it does NOT verify
Russian hard-whitelist bypass (a normal unrestricted-network relay test
does not prove that either - see PROJECT_ARCHITECTURE.md's own caveat).
