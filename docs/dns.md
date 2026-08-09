# DNS and reputation

The hardware was never the constraint on this project — a 2 GB VM sends
more mail than these two applications will ever produce. Reputation is the
constraint, and almost all of it is DNS.

Nothing here is postbud's code. It is the checklist that decides whether
what postbud sends arrives.

## Before the first real send

### PTR, and forward-confirmed reverse DNS

The single most-missed item. The provider sets the PTR; you set the A
record; both must agree.

```
192.0.2.10   PTR   mail.example.com
mail.example.com  A  192.0.2.10
```

One PTR record, not several. Postfix's `smtp_helo_name` must be that same
name. A mismatch is scored by every large receiver, and Gmail rejects
outright over IPv6.

### IPv6: off, unless fully done

`inet_protocols = ipv4` until the v6 address has its own verified PTR.
Partial IPv6 is worse than none: receivers apply stricter reverse-DNS rules
to v6 than to v4.

### SPF

Publish for every domain that appears in a `From:` header — one record per
domain, and `-all`, not `~all`. A soft fail invites the spoofing the record
exists to stop.

```
example.com.   TXT  "v=spf1 ip4:192.0.2.10 -all"
example.org.     TXT  "v=spf1 ip4:192.0.2.10 -all"
```

Do not include third-party `include:` mechanisms you no longer use; each
one is a set of hosts allowed to send as you, and the ten-lookup limit is
easy to blow past.

### DKIM

2048-bit, one selector per domain and per stream. The private key lives on
the relay host, applied by OpenDKIM, and exists nowhere else — not in this
repository, not in a Kubernetes secret, not in a backup. Rotation is a new
selector, not a replaced key.

```
s2026a._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBg…"
```

### DMARC

Start at `p=none` with aggregate reports, and read them before tightening.
The point of `none` is to discover what you are actually sending — including
the forgotten cron job on some other host — before a policy starts
discarding it.

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
```

Tighten to `p=quarantine` and then `p=reject` once reports show only
expected sources, aligned, for a few weeks.

### Stream separation

Transactional mail (invoices, password resets) and anything resembling
updates or marketing get **different subdomains and different DKIM
selectors**, so a complaint about one cannot drag the other down. One IP is
fine — splitting IPs at this volume weakens both, because reputation needs
volume to mean anything — but the streams should be distinguishable.

### Feedback loops, before the first send, not after

- **Microsoft SNDS and JMRP** — register the IP; JMRP complaints arrive at
  `abuse@` and should reach the suppression list.
- **Google Postmaster Tools** — verify the sending domains.

Both require a reachable `abuse@`, which is one of the reasons the relay's
RCPT allowlist exists (`docs/postfix/virtual.sample`).

## The thing that has no DNS fix

Very low volume keeps reputation thin at Gmail and Microsoft regardless of
how correct the records are — there is simply not enough signal. For
transactional mail this is normal and not worth fighting. What it means in
practice:

- Never send anything unsolicited from this IP. Not once.
- Keep the suppression list honest; repeated sends to dead addresses are
  the fastest way to a bad score at this volume.
- Expect the occasional deferral to Microsoft in the first weeks. Postfix
  retries; postbud's window is two days.

## Verifying

```bash
dig +short -x 192.0.2.10                   # PTR
dig +short mail.example.com                  # matches?
dig +short TXT example.com                   # SPF
dig +short TXT s2026a._domainkey.example.com # DKIM
dig +short TXT _dmarc.example.com            # DMARC
```

Then send one message to a Gmail address and read the received headers:
`spf=pass`, `dkim=pass`, `dmarc=pass`, all three aligned with the `From:`
domain. Anything less is worth fixing before the second message.
