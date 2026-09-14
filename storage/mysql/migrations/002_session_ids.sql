ALTER TABLE authlier_sessions ADD COLUMN id varchar(36);
-- authlier:split
UPDATE authlier_sessions SET id = UUID() WHERE id IS NULL;
-- authlier:split
ALTER TABLE authlier_sessions MODIFY id varchar(36) NOT NULL;
-- authlier:split
CREATE UNIQUE INDEX authlier_sessions_id_unique ON authlier_sessions(id);
