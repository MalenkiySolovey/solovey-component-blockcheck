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
add applicable transfer and exact TLS 1.2/1.3 probes without editing the group.
HTTP/HTTPS checks use `HEAD /`. Transfer checks use `GET /` and read up to 64 KiB
of body without following redirects or retaining response data. TLS always uses
normal certificate verification. DNS probing is delegated to the selected path,
with no fallback. Named targets reach a policy-checked,
pinned address; the full answer is rejected if any address is disallowed.
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

No target address, raw response, credential or packet content is put in the run
result. For exported observations, the HTTP adapter uses `Report.Redacted` to
also remove path context and egress details. Group exports deliberately contain
the operator's definitions. The component uses GPL-3.0; adapted target data
retains its MIT notice.
