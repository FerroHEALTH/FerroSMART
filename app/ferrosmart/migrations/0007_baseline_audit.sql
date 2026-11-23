-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The audit records (docs/architecture.md section 13.2), each a FHIR
-- AuditEvent kept until the Audit Record Repository took or refused it.

CREATE TABLE audit_record (
    seq bigserial PRIMARY KEY,
    recorded_at timestamptz NOT NULL,
    kind text NOT NULL,
    outcome text NOT NULL,
    subject text,
    client_id text,
    document jsonb NOT NULL,
    delivered_at timestamptz,
    refused_at timestamptz
);
CREATE INDEX audit_record_recorded_at ON audit_record (recorded_at);
CREATE INDEX audit_record_subject ON audit_record (subject, recorded_at);
CREATE INDEX audit_record_waiting ON audit_record (seq)
    WHERE delivered_at IS NULL AND refused_at IS NULL;
