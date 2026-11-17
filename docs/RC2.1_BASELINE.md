# RC2.1 frozen baseline

The original RC2.1 handover archive is retained unchanged outside this candidate. Its SHA-256 is `32a9c5f8746d9416ea9184f417b479d206f012e37d46b91b1bc6b2ca77708011` (also recorded in `manifest.json`) as the baseline archive digest. RC2.2 is a separate working copy; no RC2.1 source or evidence has been overwritten.

The baseline audit identified fallback secrets, accepted active-session sidecar deletion, silent SQLite read-error suppression, generation rollback acceptance, and a contradictory ADV-003-B-R1A result. The candidate changes listed in `RELEASE_STATUS.md` address only the explicitly described subset; the remaining blockers stay visible.
