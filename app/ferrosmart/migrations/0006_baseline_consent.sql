-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- What a person chose: the consents they remember, per client and resource
-- server (docs/architecture.md section 13.6 item 6), and their recent
-- patients.

CREATE TABLE consent (
    subject text NOT NULL,
    client_id text NOT NULL,
    scope text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    audience text NOT NULL,
    PRIMARY KEY (subject, client_id, audience)
);

-- The patients a person chose on the picker, by the resource server asked
-- (13.6 item 4): a FHIR Patient id, or at an openEHR base without a FHIR
-- server the subject id the EHR was looked up by.
CREATE TABLE recent_patient (
    subject text NOT NULL,
    audience text NOT NULL,
    patient text NOT NULL,
    chosen_at timestamptz NOT NULL,
    PRIMARY KEY (subject, audience, patient)
);
CREATE INDEX recent_patient_chosen ON recent_patient (chosen_at);
