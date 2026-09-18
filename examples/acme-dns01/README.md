# dns-01 with a private validation zone

ACME's `dns-01` challenge proves control of a name through DNS: the client
publishes a TXT record `_acme-challenge.<name>` and the CA reads it back. It
is the only challenge that can prove a **wildcard** (`*.example.lan`), and it
works for hosts the CA cannot reach on port 80.

The client must be able to *write* that record. This example runs a small
authoritative BIND 9 next to Chancery for exactly that purpose:

- ACME clients add and remove the TXT records over RFC 2136 dynamic updates,
  authenticated with a TSIG key (`setup.sh` generates it).
- Chancery reads the records straight from this server (`ACME_DNS_RESOLVERS=dns`),
  so no cache sits in between and a record is visible the moment it is written.
- Your LAN's regular DNS (router, Pi-hole, dnsmasq) is not involved and needs no
  change. The zone here only ever holds `_acme-challenge` records.

If your network already runs an authoritative server that accepts dynamic
updates (BIND, Knot, PowerDNS, Technitium, Windows DNS), skip the container:
point `ACME_DNS_RESOLVERS` at that server and give the clients its update
credentials. The client commands below stay the same.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Overlay for the main compose file: adds the `dns` service and points the app at it |
| `named.conf.template` | BIND configuration; `setup.sh` renders it to `named.conf` (gitignored, holds the secret) |
| `zones/example.lan.zone` | The validation zone. Rename it (here and in the template) to the domain your certificates use |
| `setup.sh` | Generates the TSIG secret (`tsig.secret`), the nsupdate/acme.sh key file (`tsig.key`) and `named.conf` |

## Steps

1. Rename `example.lan` to your domain in `zones/example.lan.zone` and
   `named.conf.template` (file name included), then render the config:

   ```bash
   ./examples/acme-dns01/setup.sh
   ```

2. Start Chancery with the overlay, from the repository root (the overlay's
   paths are resolved from there). It sets `ACME_ENABLED=true` and
   `ACME_DNS_RESOLVERS=dns` on the app and publishes BIND on host port
   `ACME_DNS_PORT` (default `5354`; port 53 is usually taken by
   systemd-resolved or a Pi-hole):

   ```bash
   docker compose -f docker-compose.yml -f examples/acme-dns01/docker-compose.yml up -d
   ```

3. On the CA page tick *Enable ACME*, *Allow wildcard names (dns-01)* and keep
   *Require EAB key* on; create one EAB key per client (`kid` + MAC key, shown
   once). Prefer a name-constrained CA (`DNS:example.lan`) for wildcard issuance.

4. Check the update path from a client machine (`bind9-dnsutils` / `bind-tools`):

   ```bash
   nsupdate -k examples/acme-dns01/tsig.key <<'EOF'
   server ca.example.lan 5354
   zone example.lan
   update add _acme-challenge.example.lan 60 TXT "probe"
   send
   EOF
   dig @ca.example.lan -p 5354 _acme-challenge.example.lan TXT +short   # "probe"
   ```

   (delete it again with `update delete _acme-challenge.example.lan TXT`).

5. Issue. Replace `ca.example.lan`, the CA id, `KID` and `HMAC`; the secret is
   in `tsig.secret`.

   **lego 5** (provider `dnsupdate`; lego 4 calls it `rfc2136` with `RFC2136_*` variables):

   ```bash
   export DNSUPDATE_NAMESERVER=ca.example.lan:5354 DNSUPDATE_TSIG_KEY=chancery-acme \
          DNSUPDATE_TSIG_SECRET="$(cat examples/acme-dns01/tsig.secret)" \
          DNSUPDATE_TSIG_ALGORITHM=hmac-sha256. DNSUPDATE_ZONES=example.lan
   lego run --server https://ca.example.lan/acme/3/directory --email ops@example.lan --accept-tos \
     --eab --eab.kid KID --eab.hmac HMAC \
     --dns dnsupdate --dns.resolvers ca.example.lan:5354 --dns.propagation.disable-ans \
     -d '*.example.lan' -d example.lan
   ```

   `--dns.resolvers` makes lego's own propagation check ask this server, and
   `--dns.propagation.disable-ans` skips its lookup of the zone's public name
   servers, which a private validation zone does not have. lego pauses
   `DNSUPDATE_SEQUENCE_INTERVAL` (default 60 s) between the records of one
   order; `DNSUPDATE_SEQUENCE_INTERVAL=5` is plenty for a server it writes to directly.

   **certbot** (`certbot-dns-rfc2136` plugin, or the `certbot/dns-rfc2136` image):

   ```bash
   cat > rfc2136.ini <<EOF
   dns_rfc2136_server = 10.0.0.82          # the DNS server's IP (the plugin wants an address)
   dns_rfc2136_port = 5354
   dns_rfc2136_name = chancery-acme
   dns_rfc2136_secret = $(cat examples/acme-dns01/tsig.secret)
   dns_rfc2136_algorithm = HMAC-SHA256
   EOF
   chmod 600 rfc2136.ini
   certbot certonly --server https://ca.example.lan/acme/3/directory --eab-kid KID --eab-hmac-key HMAC \
     --dns-rfc2136 --dns-rfc2136-credentials rfc2136.ini --dns-rfc2136-propagation-seconds 5 \
     -d '*.example.lan' -d example.lan --email ops@example.lan --agree-tos
   ```

   **acme.sh** (`dns_nsupdate` uses the `tsig.key` file):

   ```bash
   export NSUPDATE_SERVER=ca.example.lan NSUPDATE_SERVER_PORT=5354 NSUPDATE_KEY=$PWD/examples/acme-dns01/tsig.key
   acme.sh --register-account --server https://ca.example.lan/acme/3/directory --eab-kid KID --eab-hmac-key HMAC
   acme.sh --issue --server https://ca.example.lan/acme/3/directory --dns dns_nsupdate -d '*.example.lan' -d example.lan
   ```

   **Caddy** needs a build that includes a DNS provider module (for example
   `caddy-dns/rfc2136`) and `acme_dns` in its global options next to
   `acme_ca` / `acme_eab`; see that module's documentation for its fields.

6. Watch it work: `docker compose logs -f app` shows the ACME requests and
   `dig @ca.example.lan -p 5354 _acme-challenge.example.lan TXT` shows the
   record while the client waits for validation. The audit log records
   `acme_challenge_validated` with the challenge type, the attempt count and
   the resolvers used.

## What the TSIG key authorizes

`update-policy { grant chancery-acme zonesub TXT; }` lets the key add and
remove TXT records anywhere in the zone and nothing else. Whoever holds it can
therefore pass dns-01 for **any** name in the zone, so treat `tsig.secret`
like the EAB key: one per client where that matters, and tighten the grant to
`name _acme-challenge.host.example.lan TXT` per host when clients should not
be able to validate each other's names. The EAB key still decides who may open
an ACME account at all.
