DO $$
DECLARE t record; col record; columns_sql text; values_sql text; value_sql text;
        existing bigint; pass integer;
BEGIN
  FOR pass IN 1..3 LOOP
    FOR t IN SELECT schemaname,tablename FROM pg_tables
      WHERE schemaname='public' AND tablename NOT LIKE '%migration%' AND tablename NOT LIKE 'knex_%' ORDER BY tablename LOOP
      EXECUTE format('SELECT count(*) FROM %I.%I',t.schemaname,t.tablename) INTO existing;
      IF existing>0 THEN CONTINUE; END IF;
      columns_sql:=''; values_sql:='';
      FOR col IN SELECT a.attname, typ.typname, a.attnum, a.atttypmod, c.oid AS table_oid
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_type typ ON typ.oid=a.atttypid
        WHERE n.nspname=t.schemaname AND c.relname=t.tablename AND a.attnum>0 AND NOT a.attisdropped
        AND a.attnotnull AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated='' ORDER BY a.attnum LOOP
        SELECT format('(SELECT %I FROM %s LIMIT 1)',ra.attname,con.confrelid::regclass) INTO value_sql
          FROM pg_constraint con JOIN pg_attribute ra ON ra.attrelid=con.confrelid
          AND ra.attnum=con.confkey[array_position(con.conkey,col.attnum)]
          WHERE con.conrelid=col.table_oid AND con.contype='f' AND col.attnum=ANY(con.conkey) LIMIT 1;
        IF value_sql IS NULL THEN
          value_sql:=CASE
            -- char(n) i varchar(n): atttypmod = n + 4; wartość przycięta do zadeklarowanej długości (np. kod waluty char(3)).
            WHEN col.typname IN ('varchar','bpchar') AND col.atttypmod>4 THEN quote_literal(left('synthetic-item',col.atttypmod-4))
            WHEN col.typname IN ('text','varchar','bpchar','citext','name') THEN quote_literal('synthetic-item')
            WHEN col.typname IN ('int2','int4','int8','numeric','float4','float8') THEN '1'
            WHEN col.typname='bool' THEN 'false'
            WHEN col.typname='uuid' THEN quote_literal('00000000-0000-4000-8000-000000000001')
            WHEN col.typname='date' THEN quote_literal('2026-01-01')
            WHEN col.typname IN ('timestamp','timestamptz') THEN quote_literal('2026-01-01T00:00:00Z')
            WHEN col.typname IN ('json','jsonb') THEN quote_literal('{}')
            WHEN col.typname='bytea' THEN quote_literal('')
            ELSE 'NULL' END;
        END IF;
        columns_sql:=columns_sql||CASE WHEN columns_sql='' THEN '' ELSE ',' END||quote_ident(col.attname);
        values_sql:=values_sql||CASE WHEN values_sql='' THEN '' ELSE ',' END||value_sql;
      END LOOP;
      BEGIN
        IF columns_sql='' THEN EXECUTE format('INSERT INTO %I.%I DEFAULT VALUES',t.schemaname,t.tablename);
        ELSE EXECUTE format('INSERT INTO %I.%I (%s) VALUES (%s)',t.schemaname,t.tablename,columns_sql,values_sql); END IF;
      -- Wiersz, którego nie da się wstawić (wyzwalacz, domena, zakres), zostawia tabelę pustą; nie przerywa całego zasiewu.
      EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'synthetic seed not applicable to %.%: %', t.schemaname,t.tablename,SQLSTATE;
      END;
    END LOOP;
  END LOOP;
END $$;
