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
