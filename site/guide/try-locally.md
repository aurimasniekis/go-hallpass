# Try it locally

This page runs HallPass on your own machine in **development mode**: plain HTTP on loopback and a generated master
key inside the data directory. It is the fastest way to click through the console and connect a test agent. Never
use development mode for real servers; install with [Docker Compose](/guide/install-docker) or
[systemd](/guide/install-binary) instead.

## 1. Get the binary

Download the archive for your platform from the
[releases page](https://github.com/aurimasniekis/go-hallpass/releases): `linux_amd64`, `linux_arm64` or
`darwin_arm64` (Apple silicon; for trying out and development only). The binary has the web UI embedded.

```sh
V=0.6.1 PLATFORM=darwin_arm64      # or linux_amd64, linux_arm64
curl -fLO "https://github.com/aurimasniekis/go-hallpass/releases/download/v$V/hallpass_${V}_${PLATFORM}.tar.gz"
tar -xzf "hallpass_${V}_${PLATFORM}.tar.gz"
export PATH="$PWD/hallpass_${V}_${PLATFORM}:$PATH"
hallpass version
```

Or build from source with Go 1.27 or later, Node 24 and pnpm:

```sh
git clone https://github.com/aurimasniekis/go-hallpass.git && cd go-hallpass
(cd web && pnpm install --frozen-lockfile && pnpm build)      # the web UI
go build -tags embedui -o bin/hallpass ./cmd/hallpass          # binary with the UI embedded
export PATH="$PWD/bin:$PATH"
```

`make build` also works but produces a binary **without** the web UI.

## 2. Configure

Create a scratch directory and a development configuration. The ports below avoid the defaults, so they do not clash
with a real installation.

```sh
mkdir -p ~/hallpass-try && chmod 700 ~/hallpass-try && cd ~/hallpass-try
cat > hallpass.yaml <<EOF
mode: development
data_dir: $HOME/hallpass-try/data
public_url: http://127.0.0.1:7272
kek:
  file: ""                 # development only: generate a KEK inside the data directory
ssh:
  listen: "127.0.0.1:2422"
http:
  listen: "127.0.0.1:7272"
log:
  format: text
egress:
  allow_cidrs: [127.0.0.0/8]
  allow_special_cidrs: [127.0.0.1/32]   # loopback destinations are denied unless re-allowed
EOF
hallpass config check --config hallpass.yaml
```

Change `egress.allow_cidrs` to the network of the test server you want to reach. HallPass refuses destinations
outside these ranges. An empty list means no destination is reachable.

## 3. Initialize and start

`migrate`, `hostkey show` and `admin bootstrap` take the data-directory lock, so run them before `serve`:

```sh
hallpass migrate --config hallpass.yaml
hallpass hostkey show --config hallpass.yaml --host center    # known_hosts line for your agents
hallpass admin bootstrap --config hallpass.yaml               # one-time setup link, valid 30 minutes
hallpass serve --config hallpass.yaml
```

Open the setup link that `admin bootstrap` printed and continue with [First run](/guide/first-run).

## 4. A destination to practice on

Use any OpenSSH server you control and can reach from your machine: a VM, a spare host, or a container with
`sshd`. Give it a dedicated account for each role you want to try (for example `ro` and `deploy`). The
[onboarding wizard](/guide/first-run#enroll-your-first-server) shows the exact `authorized_keys` line to install.

::: tip Containers on Docker Desktop
Docker Desktop translates the source address of connections to published ports, so the `from="…"` restriction in
the suggested `authorized_keys` line will not match on a laptop. For a throwaway test you can widen it; on a real
destination, install the line unchanged.
:::

## Clean up

Stop `hallpass serve` with Ctrl-C (it drains sessions for up to 30 seconds) and delete `~/hallpass-try`.
