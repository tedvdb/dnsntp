# dnsntp

A small **UDP DNS server** that answers **TXT queries only**. For each valid TXT request it returns **three TXT records** with the current time:

1. **Unix time in seconds** (decimal string)  
2. **Unix time in milliseconds** (decimal string)  
3. **The same instant in RFC 3339 UTC** (e.g. with fractional seconds aligned to the milliperiod)

Any other query type (**A**, **AAAA**, **NS**, …) gets **`REFUSED`** (RCODE 5) with no answer records. Malformed packets or queries with no questions are ignored (no response).

The binary listens on **`0.0.0.0:53535/udp`** by default.

## Build and run locally

```bash
cargo build --release
./target/release/dnsntp
```

You should see: `Listening on 0.0.0.0:53535`.

## Docker

```bash
docker build -t dnsntp .
docker run --rm -p 53535:53535/udp dnsntp
```

## Querying the public host

Examples use **`dnsntp.tedtec.nl`**. If your resolver or `dig` talks to port **53**, point **`dig`** at the server explicitly and set the **UDP port to 53535** (this service does not use 53 by default).

### TXT (success)

```bash
dig TXT dnsntp.tedtec.nl @dnsntp.tedtec.nl
```

You should see **`status: NOERROR`**, **`ANSWER: 3`**, and three TXT strings: seconds, milliseconds, and an RFC 3339 timestamp.

### Non-TXT (refused)

```bash
dig A dnsntp.tedtec.nl @dnsntp.tedtec.nl
dig AAAA dnsntp.tedtec.nl @dnsntp.tedtec.nl
```

You should see **`status: REFUSED`** and no usable answer records for the requested type.

### Short output

```bash
dig +short TXT dnsntp.tedtec.nl @dnsntp.tedtec.nl
```

## Library

The crate exposes a library (`dnsntp`) with parsing, reply building, and `process_dns_request`—the same logic the binary uses. Run **`cargo test`** for examples in tests and integration tests.

## Limits and behavior

- Only the **first question** in a packet is used to decide TXT vs refused; answers repeat that question’s owner name and type for all TXT RRs.
- Replies are **authoritative-style stubs** for time service; this is not a general-purpose DNS zone server.
- **Port 53535** must be reachable from the client when not using a front proxy that maps 53 → 53535.
