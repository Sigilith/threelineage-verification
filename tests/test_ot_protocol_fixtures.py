"""Deterministic protocol traffic fixture replay tests for NonActuatingOTBoundaryAdapter."""

from __future__ import annotations

import pytest

from adapters.ot.boundary import NonActuatingOTBoundaryAdapter, OTTelemetryFrame
from core.sigilith import GovernanceVerdict


@pytest.mark.parametrize(
    "frame,proposed_delta,recent_deltas,expected_verdict,expected_permitted",
    [
        (
            OTTelemetryFrame(
                protocol="OPC-UA",
                zone_id="zone-substation-a",
                point_id="tap-position-norm",
                normalized_state=0.78,
                sensor_noise=0.01,
                quality_good=True,
                hardware_sis_trip=False,
            ),
            0.04,
            [0.02, 0.02],
            GovernanceVerdict.PERMIT_ATTENUATED,
            True,
        ),
        (
            OTTelemetryFrame(
                protocol="DNP3",
                zone_id="zone-feeder-b",
                point_id="rtu-analog-in-04",
                normalized_state=0.52,
                sensor_noise=0.0,
                packet_drop=False,
                quality_good=False,
                hardware_sis_trip=False,
            ),
            0.03,
            [],
            GovernanceVerdict.FAIL_CLOSED,
            False,
        ),
        (
            OTTelemetryFrame(
                protocol="IEC-61850",
                zone_id="bay-01-protection",
                point_id="goose-breaker-state",
                normalized_state=0.48,
                sensor_noise=0.0,
                quality_good=True,
                hardware_sis_trip=True,
            ),
            0.02,
            [],
            GovernanceVerdict.FAIL_CLOSED,
            False,
        ),
    ],
)
def test_ot_protocol_fixture_replay(
    frame: OTTelemetryFrame,
    proposed_delta: float,
    recent_deltas: list[float],
    expected_verdict: GovernanceVerdict,
    expected_permitted: bool,
) -> None:
    adapter = NonActuatingOTBoundaryAdapter()
    decision = adapter.evaluate_proposal(frame, proposed_delta=proposed_delta, recent_deltas=recent_deltas)

    assert decision.non_actuating_only is True
    assert decision.actuation_permitted is expected_permitted
    assert decision.envelope.verdict == expected_verdict
    if not expected_permitted:
        assert decision.clamped_delta == 0.0
    elif expected_verdict == GovernanceVerdict.PERMIT_ATTENUATED:
        assert abs(decision.clamped_delta) < abs(proposed_delta)


def test_ot_protocol_fixtures_stale_drift_and_delegation_cap() -> None:
    adapter = NonActuatingOTBoundaryAdapter()

    opcua_dropped = OTTelemetryFrame(
        protocol="OPC-UA",
        zone_id="zone-substation-a",
        point_id="voltage-regulator-sp",
        normalized_state=0.72,
        sensor_noise=0.05,
        packet_drop=True,
        quality_good=True,
        hardware_sis_trip=False,
    )
    dropped_decision = adapter.evaluate_proposal(
        opcua_dropped,
        proposed_delta=0.05,
        recent_deltas=[0.04, 0.04, 0.04],
    )
    assert dropped_decision.non_actuating_only is True
    assert dropped_decision.envelope.verdict in (
        GovernanceVerdict.PERMIT_ATTENUATED,
        GovernanceVerdict.HOLD_ESCALATE,
    )
    assert abs(dropped_decision.clamped_delta) < 0.05

    dnp3_drift = OTTelemetryFrame(
        protocol="DNP3",
        zone_id="zone-feeder-b",
        point_id="cap-bank-step",
        normalized_state=0.86,
        sensor_noise=0.02,
        packet_drop=False,
        quality_good=True,
        hardware_sis_trip=False,
    )
    drift_decision = adapter.evaluate_proposal(
        dnp3_drift,
        proposed_delta=0.04,
        recent_deltas=[0.05, 0.05, 0.05, 0.05, 0.05],
    )
    assert drift_decision.non_actuating_only is True
    assert drift_decision.actuation_permitted is False
    assert drift_decision.envelope.verdict == GovernanceVerdict.HOLD_ESCALATE
    assert drift_decision.clamped_delta == 0.0

    iec_capped = OTTelemetryFrame(
        protocol="IEC-61850",
        zone_id="bay-02-busbar",
        point_id="load-tap-target",
        normalized_state=0.46,
        sensor_noise=0.01,
        packet_drop=False,
        quality_good=True,
        hardware_sis_trip=False,
    )
    capped_decision = adapter.evaluate_proposal(
        iec_capped,
        proposed_delta=0.04,
        recent_deltas=[],
        max_alpha_cap=0.50,
    )
    assert capped_decision.non_actuating_only is True
    assert capped_decision.actuation_permitted is True
    assert capped_decision.envelope.verdict == GovernanceVerdict.PERMIT_ATTENUATED
    assert capped_decision.envelope.alpha == pytest.approx(0.50)
    assert capped_decision.clamped_delta == pytest.approx(0.02)
