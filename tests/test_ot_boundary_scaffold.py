"""Unit tests for the non-actuating OT boundary adapter scaffold."""

from __future__ import annotations

import pytest

from adapters.ot.boundary import NonActuatingOTBoundaryAdapter, OTTelemetryFrame
from core.sigilith import GovernanceVerdict


def test_attenuates_setpoint_without_actuating() -> None:
    adapter = NonActuatingOTBoundaryAdapter()
    frame = OTTelemetryFrame(
        protocol="OPC-UA",
        zone_id="zone-3-substation",
        point_id="bus-voltage-pu",
        normalized_state=0.78,
        sensor_noise=0.02,
    )
    decision = adapter.evaluate_proposal(frame, proposed_delta=0.04, recent_deltas=[0.02, 0.02])

    assert decision.non_actuating_only is True
    assert decision.actuation_permitted is True
    assert decision.envelope.verdict == GovernanceVerdict.PERMIT_ATTENUATED
    assert decision.clamped_delta == pytest.approx(decision.envelope.permitted_delta)
    assert abs(decision.clamped_delta) < abs(decision.proposed_delta)


def test_blocks_when_sis_trip_or_bad_quality() -> None:
    adapter = NonActuatingOTBoundaryAdapter()
    frame = OTTelemetryFrame(
        protocol="DNP3",
        zone_id="zone-2-feeder",
        point_id="feeder-load",
        normalized_state=0.50,
        quality_good=True,
        hardware_sis_trip=True,
    )
    decision = adapter.evaluate_proposal(frame, proposed_delta=0.03)

    assert decision.non_actuating_only is True
    assert decision.actuation_permitted is False
    assert decision.clamped_delta == 0.0
    assert decision.envelope.verdict == GovernanceVerdict.FAIL_CLOSED
