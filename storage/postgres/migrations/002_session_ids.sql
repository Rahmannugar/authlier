ALTER TABLE authlier_sessions ADD COLUMN id text;
-- authlier:split
UPDATE authlier_sessions SET id = gen_random_uuid()::text WHERE id IS NULL;
-- authlier:split
ALTER TABLE authlier_sessions ALTER COLUMN id SET NOT NULL;
-- authlier:split
CREATE UNIQUE INDEX authlier_sessions_id_unique ON authlier_sessions(id);
