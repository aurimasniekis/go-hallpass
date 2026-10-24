# Reaching home and lab servers

HallPass dials destinations directly over TCP. A server behind NAT (a home server, a lab, another VPC) works as soon
as HallPass has a route to it. The security rules stay the same:

- the destination's host key is still pinned;
- `egress.allow_cidrs` must include the remote range;
- the login key's `from=` should name the address the destination sees HallPass connect from.

Reference: [remote-networks.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/remote-networks.md).

## Option 1: Tailscale or Headscale (simplest)

1. Install Tailscale on the HallPass host and on each destination; join both to the tailnet.
2. In the tailnet ACL allow only `hallpass-host → destinations:22`. Deny everything else, so a compromised destination
   gains nothing from the tailnet.
3. Allow the tailnet range (or individual `/32` addresses) in HallPass:

   ```yaml
   egress:
     allow_cidrs:
       - 100.64.0.0/10            # Tailscale IPv4
       - fd7a:115c:a1e0::/48      # Tailscale IPv6
     source_addresses:
       - 100.64.0.10              # the HallPass host's tailnet address
   ```

4. Enroll the server with its tailnet address (or MagicDNS name) and pin its host key as usual.
5. Install the login key line; its `from=` now names the HallPass tailnet address.

In a container, run Tailscale as a sidecar sharing the network namespace, or run `tailscaled` on the host and use host
networking.

## Option 2: WireGuard

Same model with your own tunnel: a WireGuard peer on the HallPass host and at each site, the remote subnets routed
over it and added to `egress.allow_cidrs`, and `from=` pinned to the HallPass WireGuard address. Use `AllowedIPs` and
firewall rules so peers reach only destination port 22, never the HallPass console.

## Option 3: reverse SSH tunnel from the destination

When the destination can only connect out, it can publish its sshd on the HallPass host through a reverse tunnel into a
dedicated, locked-down tunnel account. **Never** use the agent port 2222 for this; it is the gateway, not OpenSSH.

```sh
# On the destination (systemd unit or autossh), as an unprivileged user:
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    -R 127.0.0.1:22001:127.0.0.1:22 tunnel-web7@hallpass-host
```

On the HallPass host, allow only that forward in the tunnel account's `authorized_keys`:

```
restrict,port-forwarding,permitlisten="127.0.0.1:22001",command="/bin/false" ssh-ed25519 AAAA… web7-tunnel
```

Enroll the server as `127.0.0.1` port `22001` and re-allow loopback explicitly:

```yaml
egress:
  allow_cidrs: [127.0.0.0/8]
  allow_special_cidrs: [127.0.0.1/32]   # loopback is denied by default
```

Any local process on the HallPass host can reach the forwarded port, so keep that host single-purpose. The destination
sees connections from `127.0.0.1`; pin `from="127.0.0.1"` on its login key.

## Not available yet

A built-in connector that dials out from the remote network is not implemented yet. Its design is still open.
