-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The patients a person chose on the picker (docs/architecture.md section
-- 13.6 item 4), by the person's subject and the resource server asked: a
-- FHIR Patient id, or at an openEHR base without a FHIR server the subject
-- id the EHR was looked up by. Each row lives for the configured retention.

CREATE TABLE recent_patient (
    subject text NOT NULL,
    audience text NOT NULL,
    patient text NOT NULL,
    chosen_at timestamptz NOT NULL,
    PRIMARY KEY (subject, audience, patient)
);
CREATE INDEX recent_patient_chosen ON recent_patient (chosen_at);
