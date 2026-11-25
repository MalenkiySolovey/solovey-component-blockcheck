# Solovey BlockCheck

Optional, disabled-by-default, manual connectivity diagnostics. The host supplies
the runtime path and enforces destination policy. BlockCheck does not select a
route, change network configuration, or create a listener or background worker.

The catalog adapts 12 quick-service groups and four control groups from frozen
ZapretGUI data. See `SOURCE_PROVENANCE.json` and `NOTICE`. A default is copied to
the user catalog on the first write; later defaults never overwrite saved groups.
Editing and importing definitions do not run probes. Definitions accept only a
hostname or public IP and supported probe identifiers, not URLs or commands.

A run admits at most 32 selected probes, one at a time, for up to 30 seconds.
TCP/TLS test port 443; HTTP/HTTPS send `HEAD /` to port 80/443 with no redirects
or body reads. TLS uses normal certificate verification. DNS probing is delegated
to the selected path, with no fallback. Named targets reach a policy-checked,
pinned address; the full answer is rejected if any address is disallowed.
The host must qualify each mode separately. HTTP responses and DNS status codes
are observations, not proof of censorship or full service availability.

No target address, raw response, credential or packet content is put in the run
result. For exported observations, the HTTP adapter uses `Report.Redacted` to
also remove path context and egress details. Group exports deliberately contain
the operator's definitions. The component uses GPL-3.0; adapted target data
retains its MIT notice.
