# Optional network apps

Cloudflare Tunnel is an optional, outbound-only app. It reuses the appliance app
helper and its confirmed, audited install/start/stop/uninstall tasks. It publishes
no host port and adds no inbound firewall row. The container runs under the
platform's `container_t` SELinux domain; the helper keeps its existing
`olivares_helper_apps_t` domain. The token bind is read-only and relabeled by the
container runtime; the helper checks its metadata, never its contents.

Create a **named, remotely managed** tunnel in Cloudflare and provision its token
as `/var/lib/olivares-apps/cloudflared/tunnel-token`, a nonempty regular file owned
by root with mode `0600`, inside the root-owned `0700` directory. Provision the
file through a protected host session or your secret manager. Do not put its
contents in a command argument, environment variable, issue or log. Missing,
symlinked, oversized or loosely readable token files refuse install/start.
Uninstall retains the token and origin certificate so an operator can explicitly rotate or remove them.

Provision the engine's public TLS certificate (or its issuing CA chain) as
`/var/lib/olivares-apps/cloudflared/origin-ca.pem`, also root-owned with mode
`0600`. This public certificate input is mounted read-only at
`/run/certs/origin-ca.pem`; it contains no private key. Missing, symlinked,
oversized or loosely readable certificate files refuse install/start.

Configure the tunnel's service origin in Cloudflare to match the engine's local
HTTPS listener. Set the route's `originRequest.caPool` to
`/run/certs/origin-ca.pem` and its `originServerName` to a hostname in the engine
certificate (for example `localhost` when present). Keep `noTLSVerify` disabled.
This also supports the engine's default self-signed certificate without disabling
TLS verification. See [Cloudflare's origin parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/origin-parameters/). A stable public hostname belongs in
the console's managed public URL setting. Verify sign-in and the console event
stream through that hostname before relying on it. A running connector does not
prove origin readiness or external reachability. Quick Tunnels are not used:
[Cloudflare documents that they do not support SSE](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

Install/start needs the product's configured administrative step-up policy and
retains the managed-exposure registration before the native effect. The native
product authority keeps registrations after stop/uninstall and after clearing or replacing a saved public URL: authorizing a stop or editing a field does not prove every running route stopped. The product
therefore keeps step-up required rather than trusting an unverified stop claim.
The existing initial engine startup remains available.
