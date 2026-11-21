ThreeLineage OT Boundary Adapter Scaffold (Non-Actuating)

Purpose

Provides a protocol-agnostic boundary translation layer between industrial telemetry/setpoint frames (such as OPC-UA, DNP3, or IEC 61850/62443 zone interfaces) and SigilithAutonomyEngine.

Safety and Scope Boundary

This scaffold is strictly non-actuating and advisory/evaluative only. It produces a clamped candidate proposal (clamped_delta) and telemetry quality flags for upstream evaluation and governance workflows; it does not emit physical field-bus writes, open/close breakers, or substitute for hardware Safety Instrumented Systems (SIS) or IEC 62443 zone/conduit engineering controls.
