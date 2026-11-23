CREATE FUNCTION safe_fn() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT 1; $$;
CREATE POLICY owner_scope ON items USING (owner_id = auth.uid());
