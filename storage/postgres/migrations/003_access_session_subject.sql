CREATE INDEX authlier_access_sessions_subject_idx
    ON authlier_access_sessions(subject_id, created_at DESC);
