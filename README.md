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

### Image from GitHub Container Registry

```bash
docker pull ghcr.io/tedvdb/dnsntp:latest
docker run --rm -p 53535:53535/udp ghcr.io/tedvdb/dnsntp:latest
```

The container listens on **UDP 53535** (mapped to the host in the example above). Quick check:

```bash
dig TXT @127.0.0.1 -p 53535 example.com
```

### Build the image locally

```bash
docker build -t dnsntp .
docker run --rm -p 53535:53535/udp dnsntp
```

### Docker Compose (host port 53 → service on 53535)

The binary still listens on **UDP 53535 inside the container**. The mapping **`53:53535/udp`** forwards **host UDP 53** to that port, so DNS clients can use the usual port:

```bash
dig TXT @127.0.0.1 example.com
```

That setup is correct. It **usually works** on a host where **no other service** owns UDP 53 on the interface Docker binds (often `0.0.0.0`). Publishing port 53 is normally done by the Docker daemon, so you typically do **not** need extra capabilities for this mapping.

It often **fails** if something else already listens on 53 (**systemd-resolved**, **dnsmasq**, another DNS stack, etc.): you may see *address already in use* or replies from the wrong resolver. Fix by freeing port 53, publishing only on a spare IP (e.g. `203.0.113.10:53:53535/udp`), or keep `53535:53535/udp` and use `dig -p 53535`.

```yaml
services:
  dnsntp:
    image: ghcr.io/tedvdb/dnsntp:latest
    ports:
      - "53:53535/udp"
    restart: unless-stopped
```

Save as `docker-compose.yml`, then:

```bash
docker compose up -d
```

## Querying the public host

Examples use **`dnsntp.tedtec.nl`**. With the compose mapping above, **`dig`** can use **port 53** (default). If the server only exposes **53535**, add **`-p 53535`** to `dig`.

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
- **Reachability:** clients must reach **UDP 53535** (direct or in Docker), or **UDP 53** if you publish **`53:53535/udp`** on the host.
