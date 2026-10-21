# End-to-end Retry benchmark

Not for merge. Compares `main@7616e6b2` with this branch over loopback UDP, using the public
async API.

The client spawns the server as a separate process. It checks that a real client completes a
handshake through the server's Retry, then sends `WINDOW` unique Initials at a time and waits for
all their Retries. A lost or duplicate response fails the run. The server reports its own CPU
time (user + sys, so socket syscalls count), which gives **server CPU per Initial** independently
of the client. Retries/s and RTT include the client's cost.

Configurations:

| Label | Build | Server |
| --- | --- | --- |
| main, manual Retry | `main` | accept loop calls `Incoming::retry()` |
| series, manual Retry | this branch | same, no filter |
| series, manual Retry, MAC tokens | this branch | same, with `token_authentication_key` |
| series, fast Retry | this branch | `InitialFilter` returns `Retry` |
| series, fast Retry, MAC tokens | this branch | same, with `token_authentication_key` |

Each runs with no token and with a bogus token, and with 1 and 2 server runtime threads.

## Running

```sh
# Large socket buffers, so a burst of Initials isn't dropped
sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608

retry-e2e/run.sh            # 5 rounds; about 2 minutes once built
```

Optional environment: `WINDOW` (default 64), `WORKERS` (default `"1 2"`), `KINDS` (default
`"empty bogus"`), `RCVBUF_KB` (default 4096), `RETRY_E2E_N` (requests per sample, default 32768),
and `CLIENT_CPUS` / `SERVER_CPUS` to pin both processes with `taskset`, e.g.:

```sh
CLIENT_CPUS=0 SERVER_CPUS=2,3 retry-e2e/run.sh
```

Results go to `retry-e2e/results/<timestamp>/`: `env.txt`, `results.txt` (raw, one line per run
with all nine samples) and `summary.md` (medians over rounds, relative to main).

A `WARN receive buffer capped` line means `net.core.rmem_max` is too low. A `missing Retry` panic
means a response was lost, usually for the same reason.

## Two hosts

Measures the Retry rate a server sustains: the client sends unique Initials at fixed rates,
without waiting for responses, and counts the Retries that come back.

On both hosts:

```sh
sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
export RETRY_E2E_RCVBUF_KB=8192
```

Server host, one server at a time:

```sh
(cd retry-e2e/base && cargo build --release)
(cd retry-e2e/v3 && cargo build --release --features filter)
retry-e2e/base/target/release/retry_e2e server manual 1 0.0.0.0:4433   # main, manual Retry
retry-e2e/v3/target/release/retry_e2e server manual 1 0.0.0.0:4433     # this branch, no filter
retry-e2e/v3/target/release/retry_e2e server fast 1 0.0.0.0:4433       # this branch, fast Retry
```

The server prints its CPU use every second; at ~100% of a core its endpoint driver is
saturated. The second argument is the number of runtime threads.

Client host:

```sh
(cd retry-e2e/v3 && cargo build --release --features filter)
retry-e2e/v3/target/release/retry_e2e flood <server>:4433 empty 50 100 150 200 250 300 400 500
```

Rates are in thousands of Initials per second. Use `bogus` instead of `empty` for Initials with a
bogus token (`bogus-mac` against a `fast-mac` server). Each rate runs for `RETRY_E2E_STEP_SECS`
(default 5) after a second of warm-up, from `RETRY_E2E_THREADS` sockets (default 4). Each line
reports the target rate, the rate actually sent, the Retries received per second, and the
answered fraction. The sustained rate is the highest rate with `answered` ≥ 0.99.

- `sent_k` below `rate_k` means the client can't keep up: raise `RETRY_E2E_THREADS`.
- Check the path first, e.g. with `iperf3 -u -l 1200 -b 5G`: at 1200 bytes, 300K Initials/s is
  about 2.9 Gbit/s.
- On the server, `nstat -az UdpRcvbufErrors UdpInErrors` shows datagrams dropped because the
  socket buffer was full, i.e. the server didn't keep up.

### With alessandrod/recvmmsg-main

Two more builds have Alessandro Decina's `recvmmsg-main` (`bf2b67f9`) merged in: `ar` (main +
his branch, branch `ar-main`) and `ar-v3` (this series + his branch, branch `ar-fast-retry-v3`).
His branch takes the receive syscalls out from under the endpoint lock and can run the endpoint
driver on a runtime of its own, which `split` turns on:

```sh
(cd retry-e2e/ar && cargo build --release)
(cd retry-e2e/ar-v3 && cargo build --release)
retry-e2e/ar/target/release/retry_e2e server manual 1 0.0.0.0:4433          # main + his branch
retry-e2e/ar/target/release/retry_e2e server manual 1 0.0.0.0:4433 split    # driver on its own thread
retry-e2e/ar-v3/target/release/retry_e2e server fast 1 0.0.0.0:4433         # series + his branch
retry-e2e/ar-v3/target/release/retry_e2e server fast 1 0.0.0.0:4433 split
```

With `split`, the driver gets a thread of its own besides the `<workers>` runtime threads, so
compare `1 split` with `2` as well as with `1`. MAC tokens are not in these builds.
