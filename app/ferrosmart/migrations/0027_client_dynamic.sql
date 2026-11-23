-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- A client the app registered itself (RFC 7591) carries source 'dynamic'.
-- Its metadata is self-asserted (RFC 7591 section 5), so its row holds no
-- organisation approval and no first-party mark.

ALTER TABLE client DROP CONSTRAINT client_source_check;
ALTER TABLE client ADD CONSTRAINT client_source_check
    CHECK (source IN ('config', 'admin', 'dynamic'));
ALTER TABLE client ADD CONSTRAINT client_dynamic_unapproved
    CHECK (source <> 'dynamic' OR (approved_scope IS NULL AND NOT first_party));
