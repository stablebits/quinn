## HTTP/0.9 File Serving Example

The `server` and `client` examples demonstrate fetching files using a HTTP-like toy protocol.

1. Server (`server.rs`)

The server listens for any client requesting a file. 
If the file path is valid and allowed, it returns the contents. 

Open up a terminal and execute:

```text
$ cargo run --example server ./
```

2. Client (`client.rs`)

The client requests a file and prints it to the console. 
If the file is on the server, it will receive the response. 

In a new terminal execute:

```test
$ cargo run --example client https://localhost:4433/Cargo.toml
```

where `Cargo.toml` is any file in the directory passed to the server.

**Result:**

The output will be the contents of this README.

**Troubleshooting:**

If the client times out with no activity on the server, try forcing the server to run on IPv4 by
running it with `cargo run --example server -- ./ --listen 127.0.0.1:4433`. The server listens on
IPv6 by default, `localhost` tends to resolve to IPv4, and support for accepting IPv4 packets on
IPv6 sockets varies between platforms.

If the client prints `failed to process request: failed reading file`, the request was processed
successfully but the path segment of the URL did not correspond to a file in the directory being
served.

## Minimal Example
The `connection.rs` example intends to use the smallest amount of code to make a simple QUIC connection.
The server issues it's own certificate and passes it to the client to trust.

```text
$ cargo run --example connection
```

This example will make a QUIC connection on localhost, and you should see output like:

```text
[client] connected: addr=127.0.0.1:5000
[server] connection accepted: addr=127.0.0.1:53712
```

## Insecure Connection Example

The `insecure_connection.rs` example demonstrates how to make a QUIC connection that ignores the server certificate.

```text
$ cargo run --example insecure_connection --features="rustls/dangerous_configuration"
```

## Single Socket Example

You can have multiple QUIC connections over a single UDP socket. This is especially
useful, if you are building a peer-to-peer system where you potentially need to communicate with
thousands of peers or if you have a
[hole punched](https://en.wikipedia.org/wiki/UDP_hole_punching) UDP socket.
Additionally, QUIC servers and clients can both operate on the same UDP socket.
This example demonstrates how to make multiple outgoing connections on a single UDP socket.

```text 
$ cargo run --example single_socket
```

The expected output should be something like:

```text
[client] connected: addr=127.0.0.1:5000
[server] incoming connection: addr=127.0.0.1:48930
[client] connected: addr=127.0.0.1:5001
[client] connected: addr=127.0.0.1:5002
[server] incoming connection: addr=127.0.0.1:48930
[server] incoming connection: addr=127.0.0.1:48930
```

Notice how the server sees multiple incoming connections with different IDs coming from the same
endpoint.

### Early Initial admission and Retry

`cargo run -p quinn --example initial_filter` completes a loopback handshake using
`ServerConfig::initial_filter`. Its global atomic budget admits at most 100 new
Initials per one-second window, before token authentication or Initial-key
creation. The first Initial and its Retry return each consume a slot. Boundary
bursts can consume two windows' allowances close together; racing callers may be
dropped conservatively. The example's deterministic test verifies rejection and
refill without relying on network timing.

After admission, the policy retries unvalidated peers and proceeds for validated
ones. A bogus token does not bypass admission. Valid Retry tokens are replayable
within their lifetime, so validation is not a single-use handshake reservation.
Applications can also enforce a separate handshake budget in `decide`.

Both hooks execute synchronously in the receive path and must not block or
re-enter the endpoint. Gate rejection avoids token crypto, replay-log access,
Initial keys, responses, and incoming state. Later Ignore may have paid token
costs; fast Retry still authenticates tokens and generates a protected Retry.
Custom crypto providers should override `supports_version` to avoid the default
Initial-key derivation on fast Retry. This does not isolate the endpoint lock or
shared UDP queue, and a finite admission budget does not guarantee client fairness
under a sustained flood. Existing connections bypass the hooks.
