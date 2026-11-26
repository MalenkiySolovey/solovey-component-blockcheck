# Solovey BlockCheck

Optional, disabled-by-default, manual connectivity diagnostics. The host supplies
the runtime path and enforces destination policy. BlockCheck does not select a
route, change network configuration, or create a listener or background worker.

The catalog adapts 12 quick-service groups and four control groups from pinned
ZapretGUI data. See `SOURCE_PROVENANCE.json` and `NOTICE`. A default is copied to
the user catalog on the first write; later defaults never overwrite saved groups.
Editing and importing definitions do not run probes. Definitions accept only a
hostname or public IP and supported probe identifiers, not URLs or commands.

The foreground stream checks one group or every included group against one
catalog revision and one host path. It returns progress and probe observations
in batches of up to three, continues after target failures, and stops when its
path retires. Explicit cancellation retains completed batches and sends the
terminal Jobs projection. Closing the request cancels work as well. No job
continues after the request ends. The compatibility JSON endpoint still has a
32-probe, 30-second limit; streamed runs count batches rather than limiting
the number of selected definitions. The serialized catalog and imports retain
a size budget independent of the number of active probes.

Quick runs use the configured probes. On a Deep run, HTTP/HTTPS and TLS probes
add applicable transfer, exact TLS 1.2/1.3 and Chrome-profile HTTPS probes
without editing the group.
HTTP/HTTPS checks use `HEAD /`. Transfer checks use `GET /` and read up to 64 KiB
of body without following redirects or retaining response data. TLS always uses
normal certificate verification. DNS probing is delegated to the selected path,
with no fallback. Named targets reach a policy-checked,
pinned address; the full answer is rejected if any address is disallowed.
The `https-chrome` probe uses the pinned uTLS Chrome 133 ClientHello, verifies
the certificate, and sends one `HEAD /` over the same admitted stream using
negotiated HTTP/2 or HTTP/1.x. It does not reproduce Chrome's HTTP/2 settings,
page loading, or the Chrome 150 profile in the frozen ZapretGUI reference.
A contrast with the standard TLS 1.3 probe requires the same name, admitted
address and path evidence. It can reflect server support, an intermediary or
a transient failure; it is not proof of fingerprint-based filtering.
Where the selected path supplies an admitted connected UDP socket, `quic` checks
an authenticated TLS 1.3 handshake with HTTP/3 ALPN. `http3` also requests
`HEAD /` on that exact session. Neither probe dials another address, falls back
to TCP, or follows redirects. An open UDP socket alone is not evidence of a
response. An incomplete QUIC handshake can also mean the endpoint does not
support HTTP/3, not just an interruption on the network.
On the same kind of connected UDP path, `stun` sends a bounded Binding request
to the configured endpoint on UDP 3478 or 19302. A matching valid response
proves only that the endpoint answered this request, not that calls work. It
does not follow alternate servers or retain the reflected client address.
For `icmp`, the selected Host adapter must supply an explicit Echo capability.
The Linux ordinary-Host adapter can use an unprivileged datagram Echo socket
when permitted by the kernel. No raw socket or substitute path is used. A
missing reply is only reported after the request was sent on an observed path;
it is not evidence that the service itself is unreachable.
The host must qualify each mode separately. HTTP responses and DNS status codes
are observations, not proof of censorship or full service availability. As in
the frozen ZapretGUI diagnostics, the report distinguishes resolution,
connection, TLS, certificate, HTTP and transfer stages. A TLS version contrast
requires the same admitted address and does not establish a filtering cause.

The report view can compare matching probes from recent runs on the same Host
without hiding the entire comparison because a different probe was unavailable.
For observed DNS replies it distinguishes NXDOMAIN, empty replies, other DNS
errors, addresses rejected by the Host, and different admitted address sets.
No resolver is presumed authoritative and differences do not prove tampering.

The shared service view distinguishes failure from an unobserved stage. A
proxy acknowledgement is not endpoint TCP evidence. The active administrator
can see stages and probes grouped by the admitted address actually tried, not
every DNS answer or every server behind a name. The time to HTTP response start
is separate from full probe and transfer duration. HTTP/1 observes the first
response data; HTTP/2 and HTTP/3 use their transport's first-response event.
The body timing is separate and the longest interval is only reported after
at least two positive body reads. A pause is evidence about this bounded
sample, not evidence of bandwidth limits or filtering. Unmeasured times
remain absent even when measured times would round to zero. Raw responses, credentials and
packet content are never retained. Exports remove attempted addresses, path
context and egress details.

The Host adapter retains recent manual runs in its existing component-owned
settings store (14 days, at most 512 KiB). It keeps whole group reports or notes
that details were omitted; resolved addresses are not stored. The catalog and
configured target labels remain user-owned. History retention does not affect
the extent of a run, and there is no idle worker. The component uses GPL-3.0;
adapted target data retains its MIT notice.
