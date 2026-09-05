"""API route modules.

Mounted in sentinel.main:
- telemetry:   POST /api/v1/telemetry/ingest
- incidents:   GET  /api/v1/incidents, /api/v1/incidents/{id},
               GET  /api/v1/sessions/{id}/trace, /api/v1/incidents/{id}/evidence
- remediation: POST /api/v1/incidents/{id}/remediation (propose),
               POST /api/v1/remediation/{id}/approve   (human gate → execute)
"""
