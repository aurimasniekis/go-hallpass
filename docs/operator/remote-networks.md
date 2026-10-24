# Reaching servers in other networks (home labs, VPNs, tunnels)

HallPass dials destinations directly over TCP. A destination behind NAT (a home server, a lab network, another
VPC) is reachable once HallPass has a route to it. HallPass does not need to know how that route exists. This page
describes the supported ways to provide one. The security rules don't change:
- the destination's host key is still pinned;
- `egress.allow_cidrs` must explicitly include the remote range;
- the login key's `from=` should name the address the destination sees HallPass connect from.

## Option 1: Tailscale (or Headscale)

The simplest option for home servers: no port forwarding, and the connection is end-to-end encrypted.

1. Install Tailscale on the HallPass host and on each destination, and join both to the tailnet.
2. In the tailnet ACL, allow only `hallpass-host → destinations:22`. Deny destinations → HallPass and everything
   else, so a compromised destination gains nothing from the tailnet.
3. Allow the tailnet range in HallPass:

   ```yaml
   egress:
     allow_cidrs:
       - 100.64.0.0/10            # Tailscale IPv4 (CGNAT range)
       - fd7a:115c:a1e0::/48      # Tailscale IPv6
   ```

   To restrict further, list the individual destination addresses (`100.101.102.103/32`) instead of the whole range.
4. Enroll the server with its tailnet address (or MagicDNS name) as the address. Enroll its host key as usual (scan
   and confirm the fingerprint out of band).
5. Pin the login key to the HallPass host's tailnet address:
   `restrict,from="100.64.0.10" ssh-ed25519 …`. The suggested line uses `egress.source_addresses`, so set that to
   the HallPass tailnet address(es).

Running HallPass in a container: use the Tailscale container as a sidecar sharing the network namespace, or run
`tailscaled` on the host with the container on the host network.

## Option 2: WireGuard

Same model with a self-managed tunnel. Give the HallPass host and each remote site a WireGuard peer, route the remote
subnets over it, add those subnets to `egress.allow_cidrs`, and pin `from=` to the HallPass WireGuard address. Use
`AllowedIPs` and firewall rules so that peers can reach only destination port 22, and cannot reach the HallPass host's
web console or any other port.

## Option 3: reverse SSH tunnel from the destination (no inbound access to the home network)

When the destination can only make outbound connections, it can publish its sshd on the HallPass host through a
reverse tunnel. Use a dedicated, locked-down tunnel account on the HallPass host. Never use the agent SSH port 2222:
that port runs the HallPass gateway, not OpenSSH.

```sh
# On the destination (systemd unit or autossh), as an unprivileged user:
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    -R 127.0.0.1:22001:127.0.0.1:22 tunnel-web7@hallpass-host
```

On the HallPass host, give `tunnel-web7` only that forward. In its `authorized_keys`:

```
restrict,port-forwarding,permitlisten="127.0.0.1:22001",command="/bin/false" ssh-ed25519 AAAA… web7-tunnel
```

Then enroll the server as `127.0.0.1` port `22001`, and allow the loopback port explicitly:

```yaml
egress:
  allow_cidrs: [127.0.0.0/8]
  allow_special_cidrs: [127.0.0.1/32]   # loopback is denied by default (HP-SRV-009)
```

Caveats:
- Any local process on the HallPass host can reach the forwarded port. Host-key pinning still stops impersonation,
  but keep the HallPass host single-purpose.
- `allow_special_cidrs: [127.0.0.1/32]` lets operators enroll other loopback services too. Server enrollment is
  administrator-only and audited, but treat this as a deliberate exception.
- The destination sees connections from `127.0.0.1`, so pin `from="127.0.0.1"` on the destination's login key.

## Built-in connector (not available)

A built-in reverse-tunnel connector would let a small HallPass connector on the remote network dial out and carry
destination connections, without host tunnel accounts or a VPN. It is not implemented. Its design (connector
identity and enrollment, mutual authentication, which destinations a connector may serve, and audit) is open
review item R-16 in [../DECISIONS.md](../DECISIONS.md).
