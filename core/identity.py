"""
core/identity.py: Cryptographic principal-to-agent delegation chain verification.

Proves three enterprise identity invariants before actuation:
1. Who requested the action (leaf requester_id).
2. Who delegated authority (ordered chain of Ed25519-signed DelegationLink hops from root_principal).
3. What bounded chain of authority existed (monotonic scope narrowing and max_alpha_cap enforcement).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_CHAIN_HASH = "0" * 64


@dataclass(frozen=True)
class DelegationLink:
    """Single signed hop delegating bounded authority from issuer to subject."""

    issuer: str
    subject: str
    allowed_scopes: tuple[str, ...]
    max_alpha_cap: float
    issued_at: float
    expires_at: float
    prev_link_hash: str
    signature_hex: str

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "allowed_scopes": list(self.allowed_scopes),
            "max_alpha_cap": round(float(self.max_alpha_cap), 6),
            "issued_at": float(self.issued_at),
            "expires_at": float(self.expires_at),
            "prev_link_hash": self.prev_link_hash,
        }

    def link_hash(self) -> str:
        canonical = json.dumps(
            dict(self.unsigned_payload(), signature_hex=self.signature_hex),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifiedAuthorityContext:
    """Verified identity and bounded authority context extracted from a delegation chain."""

    root_principal: str
    requester_id: str
    delegation_path: tuple[str, ...]
    delegation_depth: int
    effective_scopes: tuple[str, ...]
    effective_alpha_cap: float
    chain_digest: str


def sign_delegation_link(
    private_key: ed25519.Ed25519PrivateKey,
    issuer: str,
    subject: str,
    allowed_scopes: Sequence[str],
    max_alpha_cap: float,
    issued_at: float,
    expires_at: float,
    prev_link_hash: str = GENESIS_CHAIN_HASH,
) -> DelegationLink:
    """Create an Ed25519-signed DelegationLink."""
    if not (0.0 < max_alpha_cap <= 1.0) or not math.isfinite(max_alpha_cap):
        raise ValueError("max_alpha_cap must be finite and within (0.0, 1.0]")
    normalized_scopes = tuple(sorted(set(allowed_scopes)))
    unsigned = {
        "issuer": issuer,
        "subject": subject,
        "allowed_scopes": list(normalized_scopes),
        "max_alpha_cap": round(float(max_alpha_cap), 6),
        "issued_at": float(issued_at),
        "expires_at": float(expires_at),
        "prev_link_hash": prev_link_hash,
    }
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    sig_hex = private_key.sign(canonical).hex()
    return DelegationLink(
        issuer=issuer,
        subject=subject,
        allowed_scopes=normalized_scopes,
        max_alpha_cap=round(float(max_alpha_cap), 6),
        issued_at=float(issued_at),
        expires_at=float(expires_at),
        prev_link_hash=prev_link_hash,
        signature_hex=sig_hex,
    )


class DelegationChainVerifier:
    """Fail-closed verifier for principal-to-agent delegation chains."""

    def __init__(
        self,
        key_registry: Mapping[str, ed25519.Ed25519PublicKey],
        trusted_roots: Sequence[str],
    ) -> None:
        self.key_registry = dict(key_registry)
        self.trusted_roots = set(trusted_roots)
        if not self.trusted_roots:
            raise ValueError("At least one trusted root principal is required")

    def verify(
        self,
        links: Sequence[DelegationLink],
        required_scope: str,
        now: float | None = None,
    ) -> VerifiedAuthorityContext:
        """
        Verify cryptographic signatures, link continuity, root trust, expiry,
        scope containment, and monotonic alpha cap attenuation.
        """
        if not links:
            raise ValueError("Delegation failure: empty delegation chain")

        check_time = float(now) if now is not None else time.time()
        first = links[0]
        if first.issuer not in self.trusted_roots:
            raise ValueError(f"Delegation failure: untrusted root principal '{first.issuer}'")
        if first.prev_link_hash != GENESIS_CHAIN_HASH:
            raise ValueError("Delegation failure: root link prev_link_hash must match genesis hash")

        expected_prev_hash = GENESIS_CHAIN_HASH
        expected_issuer = first.issuer
        current_scopes: set[str] | None = None
        current_alpha_cap = 1.0
        path: list[str] = [first.issuer]

        for idx, link in enumerate(links):
            if link.issuer != expected_issuer:
                raise ValueError(
                    f"Delegation failure: broken principal continuity at hop {idx} "
                    f"(expected '{expected_issuer}', got '{link.issuer}')"
                )
            if link.prev_link_hash != expected_prev_hash:
                raise ValueError(f"Delegation failure: broken prev_link_hash at hop {idx}")

            if link.issuer not in self.key_registry:
                raise ValueError(f"Delegation failure: unknown issuer key '{link.issuer}'")

            if not (math.isfinite(link.issued_at) and math.isfinite(link.expires_at)):
                raise ValueError(f"Delegation failure: non-finite timestamps at hop {idx}")
            if link.expires_at <= link.issued_at or check_time > link.expires_at or check_time < link.issued_at:
                raise ValueError(f"Delegation failure: expired or not-yet-valid link at hop {idx}")

            if not (0.0 < link.max_alpha_cap <= 1.0) or not math.isfinite(link.max_alpha_cap):
                raise ValueError(f"Delegation failure: invalid max_alpha_cap at hop {idx}")

            # Enforce monotonic attenuation: child hop cannot escalate alpha cap above parent
            if link.max_alpha_cap > current_alpha_cap + 1e-9:
                raise ValueError(
                    f"Delegation failure: authority escalation at hop {idx} "
                    f"({link.max_alpha_cap} > parent {current_alpha_cap})"
                )

            link_scopes = set(link.allowed_scopes)
            if current_scopes is None:
                current_scopes = link_scopes
            else:
                if not link_scopes.issubset(current_scopes):
                    raise ValueError(
                        f"Delegation failure: scope escalation at hop {idx} "
                        f"({sorted(link_scopes - current_scopes)} not in parent scopes)"
                    )
                current_scopes = link_scopes

            canonical = json.dumps(
                link.unsigned_payload(),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            try:
                sig_bytes = bytes.fromhex(link.signature_hex)
                self.key_registry[link.issuer].verify(sig_bytes, canonical)
            except (ValueError, InvalidSignature, TypeError) as exc:
                raise ValueError(f"Delegation failure: invalid signature at hop {idx}") from exc

            current_alpha_cap = min(current_alpha_cap, float(link.max_alpha_cap))
            expected_prev_hash = link.link_hash()
            expected_issuer = link.subject
            path.append(link.subject)

        assert current_scopes is not None
        if required_scope not in current_scopes:
            raise ValueError(
                f"Delegation failure: required scope '{required_scope}' not permitted by chain "
                f"(allowed: {sorted(current_scopes)})"
            )

        return VerifiedAuthorityContext(
            root_principal=first.issuer,
            requester_id=links[-1].subject,
            delegation_path=tuple(path),
            delegation_depth=len(links),
            effective_scopes=tuple(sorted(current_scopes)),
            effective_alpha_cap=round(current_alpha_cap, 6),
            chain_digest=expected_prev_hash,
        )
