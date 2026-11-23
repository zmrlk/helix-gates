-- Stan „przepełniony”: z jednego syntetycznego wiersza na tabelę robi wiele, w tym wiersze z długimi nazwami i dużymi kwotami.
-- Bez tego listy mają jeden wiersz i nie widać ucinania tekstu, łamania liczb, przewijania, sortowania ani stronicowania.
-- Zmieniane są wyłącznie wartości zastępcze Helixa ('synthetic-item', 1, 2026-01-01) i klucze; reszta wiersza jest kopią.
-- Tabele z kolumnami logowania (hasło, sekret, token, sesja, konto dostawcy tożsamości) zostają nietknięte.
-- Słowniki i ustawienia (statusy, role, uprawnienia, jednostki, kategorie, magazyny...) też: 60 sztucznych statusów nie jest
-- stanem, który zdarza się w aplikacji. Rozpoznawane po nazwie; właściciel dopisuje własne przez runtime.seed_skip_tables.
-- :rows = docelowa liczba wierszy w tabeli. Wynik: jedna linia JSON z faktycznym stanem każdej tabeli (przed, po, wstawione ze zmianą,
-- wstawione jako kopia, nieudane), żeby raport nie zgłaszał stanu przepełnionego tam, gdzie go nie ma.
CREATE TEMP TABLE IF NOT EXISTS helix_volume(tbl text, before bigint, after bigint, extreme bigint, copied integer, failed integer, skipped text);
DO $$
DECLARE t record; col record; cols text; varied text; plain text; expr text; rich text; rich_expr text; uniq boolean; isfk boolean; hasdefault boolean;
        present bigint; i integer; pass integer; ref record; failures integer; n_varied integer; n_copied integer; n_failed integer; n_rows integer; inserted boolean; measured bigint; extreme_pred text; n_extreme bigint; first_before bigint; long_text text := repeat('bardzo długa nazwa pozycji testowej ', 6);
BEGIN
  -- Dwa przejścia: tabela łącząca dostaje różne rekordy nadrzędne dopiero wtedy, gdy tabele nadrzędne mają już wiele wierszy.
  FOR pass IN 1..2 LOOP
  FOR t IN SELECT c.oid, n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='r' AND c.relname NOT LIKE '%migration%' AND c.relname NOT LIKE 'knex_%' AND c.relname NOT IN ('alembic_version','flyway_schema_history','databasechangelog','databasechangeloglock')
    ORDER BY c.relname LOOP
    -- Dane logowania zostają nietknięte: tabele kont, sesji i tokenów oraz tabele, w których kolumna hasła, sekretu albo konta
    -- dostawcy tożsamości jest obowiązkowa. W pozostałych tabelach taka kolumna zostaje w kopiach pusta, więc kopia nie niesie
    -- cudzego hasła ani PIN-u. Zwykła tabela robocza z kolumną typu „token” (publiczny adres oferty) jest mnożona.
    IF t.relname ~* '(^|_)(sessions?|tokens?|credentials?|users?|profiles?|accounts?|identities)$' OR EXISTS (SELECT 1 FROM pg_attribute a
         WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull
         AND a.attname ~* '(password|passwd|secret|keycloak|oidc|credential|pin_hash|pin$)') THEN
      IF pass=1 THEN INSERT INTO helix_volume VALUES (t.relname, NULL, NULL, 0, 0, 0, 'login data'); END IF; CONTINUE;
    END IF;
    IF t.relname ~* ('(^slownik_|^dict(ionary)?_|(^|_)(settings?|config|ustawienia|ustawienia_wartosci|slownik|dictionary|roles?|role_functions|permissions?|uprawnienia|grants?|status(es|y)?|stages?|etapy|categories|kategorie\w*|units?|types?|typy|warehouses?|magazyny|currencies|waluty|countries|kraje|flags?)$)' /*:skip*/) THEN
      IF pass=1 THEN INSERT INTO helix_volume VALUES (t.relname, NULL, NULL, 0, 0, 0, 'dictionary or settings'); END IF; CONTINUE;
    END IF;
    EXECUTE format('SELECT count(*) FROM %I.%I', t.nspname, t.relname) INTO present;
    IF present=0 OR present>=:rows THEN
      IF pass=1 THEN INSERT INTO helix_volume VALUES (t.relname, present, present, 0, 0, 0, CASE WHEN present=0 THEN 'empty' END); END IF; CONTINUE;
    END IF;
    cols:=''; varied:=''; plain:=''; rich:=''; extreme_pred:='';
    FOR col IN SELECT a.attname, a.attnum, typ.typname, a.atttypmod, a.atthasdef, a.attidentity, a.attgenerated,
                      pg_get_expr(d.adbin, d.adrelid) AS def
      FROM pg_attribute a JOIN pg_type typ ON typ.oid=a.atttypid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum LOOP
      IF col.attgenerated<>'' OR col.attidentity<>'' OR coalesce(col.def,'') ~* 'nextval' THEN CONTINUE; END IF;
      -- opcjonalna kolumna logowania: w kopiach pusta (pominięta w INSERT, o ile nie ma wartości domyślnej)
      IF col.attname ~* '(password|passwd|secret|keycloak|oidc|credential|pin_hash|pin$)' THEN
        IF NOT col.atthasdef THEN CONTINUE; END IF;
        cols := cols || CASE WHEN cols='' THEN '' ELSE ',' END || quote_ident(col.attname);
        varied := varied || CASE WHEN varied='' THEN '' ELSE ',' END || 'NULL'; rich := rich || CASE WHEN rich='' THEN '' ELSE ',' END || 'NULL'; plain := plain || CASE WHEN plain='' THEN '' ELSE ',' END || 'NULL';
        CONTINUE;
      END IF;
      uniq := EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conrelid=t.oid AND con.contype IN ('p','u') AND col.attnum=ANY(con.conkey))
           OR EXISTS (SELECT 1 FROM pg_index ix WHERE ix.indrelid=t.oid AND ix.indisunique AND col.attnum=ANY(ix.indkey::int2[]));
      isfk := EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conrelid=t.oid AND con.contype='f' AND col.attnum=ANY(con.conkey));
      hasdefault := col.atthasdef;
      -- klucz z wartością domyślną (np. gen_random_uuid()) dostaje ją sam
      IF uniq AND hasdefault AND NOT isfk THEN CONTINUE; END IF;
      cols := cols || CASE WHEN cols='' THEN '' ELSE ',' END || quote_ident(col.attname);
      IF uniq AND NOT isfk THEN
        expr := CASE
          WHEN col.typname='uuid' THEN 'gen_random_uuid()'
          WHEN col.typname IN ('text','varchar','bpchar','citext') AND col.atttypmod>4 THEN format('left(%I::text,%s)||$1::text', col.attname, greatest(col.atttypmod-4-4,0))
          WHEN col.typname IN ('text','varchar','bpchar','citext') THEN format('%I||''-''||$1::text', col.attname)
          WHEN col.typname IN ('int2','int4','int8','numeric') THEN format('%I+$1', col.attname)
          WHEN col.typname='date' THEN format('%I+$1', col.attname)
          WHEN col.typname IN ('timestamp','timestamptz') THEN format('%I+make_interval(days=>$1)', col.attname)
          ELSE quote_ident(col.attname) END;
        varied := varied || CASE WHEN varied='' THEN '' ELSE ',' END || expr;
        rich := rich || CASE WHEN rich='' THEN '' ELSE ',' END || expr;
        plain := plain || CASE WHEN plain='' THEN '' ELSE ',' END || expr;
      ELSIF uniq AND isfk THEN
        -- klucz złożony z odwołań (tabela łącząca): kolejne wiersze wskazują kolejne rekordy nadrzędne
        SELECT con.confrelid::regclass::text AS tbl, ra.attname AS col INTO ref FROM pg_constraint con
          JOIN pg_attribute ra ON ra.attrelid=con.confrelid AND ra.attnum=con.confkey[array_position(con.conkey,col.attnum)]
          WHERE con.conrelid=t.oid AND con.contype='f' AND col.attnum=ANY(con.conkey) LIMIT 1;
        expr := format('(SELECT %I FROM %s ORDER BY 1 OFFSET ($1 %% greatest((SELECT count(*) FROM %s),1)) LIMIT 1)', ref.col, ref.tbl, ref.tbl);
        varied := varied || CASE WHEN varied='' THEN '' ELSE ',' END || expr;
        rich := rich || CASE WHEN rich='' THEN '' ELSE ',' END || expr;
        plain := plain || CASE WHEN plain='' THEN '' ELSE ',' END || expr;
      ELSE
        plain := plain || CASE WHEN plain='' THEN '' ELSE ',' END || quote_ident(col.attname);
        expr := CASE
          WHEN isfk THEN quote_ident(col.attname)
          WHEN col.typname IN ('text','varchar','bpchar','citext') AND col.atttypmod>4 THEN format(
            'CASE WHEN %1$I LIKE ''synthetic%%'' THEN left(CASE WHEN $1%%5=0 THEN %2$L ELSE %1$I||'' ''||$1::text END,%3$s) ELSE %1$I END', col.attname, long_text, col.atttypmod-4)
          WHEN col.typname IN ('text','varchar','bpchar','citext') THEN format(
            'CASE WHEN %1$I LIKE ''synthetic%%'' THEN CASE WHEN $1%%5=0 THEN %2$L ELSE %1$I||'' ''||$1::text END ELSE %1$I END', col.attname, long_text)
          WHEN col.typname IN ('numeric','float4','float8') THEN format('CASE WHEN %1$I=1 THEN CASE WHEN $1%%5=0 THEN 987654.32 ELSE $1*37.5 END ELSE %1$I END', col.attname)
          WHEN col.typname IN ('int4','int8') THEN format('CASE WHEN %1$I=1 THEN CASE WHEN $1%%5=0 THEN 987654 ELSE $1 END ELSE %1$I END', col.attname)
          WHEN col.typname='date' THEN format('CASE WHEN %1$I=DATE ''2026-01-01'' THEN %1$I+$1 ELSE %1$I END', col.attname)
          WHEN col.typname IN ('timestamp','timestamptz') THEN format('CASE WHEN %1$I=''2026-01-01T00:00:00Z'' THEN %1$I+make_interval(days=>$1) ELSE %1$I END', col.attname)
          ELSE quote_ident(col.attname) END;
        varied := varied || CASE WHEN varied='' THEN '' ELSE ',' END || expr;
        -- Wariant bogaty: także pola opcjonalne (puste) i kwoty zerowe dostają wartości, żeby kolumny list nie świeciły pustką.
        -- Co siódmy wiersz zostaje pusty (stan „brak danych” w komórce). Pola o znaczeniu formalnym (e-mail, adres, kod, status,
        -- typ, kolor, identyfikator) zostają nietknięte: wartość przykładowa nie przeszłaby ich reguł.
        rich_expr := CASE
          WHEN isfk OR col.attname ~* '(mail|url|link|href|phone|telefon|tel$|nip|regon|pesel|iban|konto|account|kod|code|json|slug|path|sciezka|status|type|typ$|kind|rodzaj|role|rola|color|kolor|uuid|_id$|hash|ip$|lang|locale|currency|waluta|unit|jednostka)' THEN expr
          WHEN col.typname IN ('text','varchar','bpchar','citext') THEN format(
            'CASE WHEN %1$I IS NULL THEN CASE WHEN $1%%7=0 THEN NULL WHEN $1%%5=0 THEN left(%2$L,%3$s) ELSE left(''Wartość przykładowa ''||$1::text,%3$s) END ELSE %4$s END',
            col.attname, long_text, CASE WHEN col.atttypmod>4 THEN col.atttypmod-4 ELSE 100000 END, expr)
          WHEN col.typname IN ('numeric','float4','float8') THEN format(
            'CASE WHEN %1$I IS NULL OR %1$I=0 THEN CASE WHEN $1%%7=0 THEN %1$I WHEN $1%%5=0 THEN 987654.32 ELSE $1*37.5 END ELSE %2$s END', col.attname, expr)
          ELSE expr END;
        rich := rich || CASE WHEN rich='' THEN '' ELSE ',' END || rich_expr;
        IF NOT isfk AND col.typname IN ('text','varchar','bpchar','citext') THEN
          extreme_pred := extreme_pred || CASE WHEN extreme_pred='' THEN '' ELSE ' OR ' END || format('%I::text = left(%L,%s)', col.attname, long_text, CASE WHEN col.atttypmod>4 THEN col.atttypmod-4 ELSE 100000 END);
        ELSIF NOT isfk AND col.typname IN ('numeric','float4','float8','int4','int8') THEN
          -- próg zamiast równości: float4 i numeric(p,1) zaokrąglają znacznik
          extreme_pred := extreme_pred || CASE WHEN extreme_pred='' THEN '' ELSE ' OR ' END || format('%I >= 987654', col.attname);
        END IF;
      END IF;
    END LOOP;
    IF cols='' THEN CONTINUE; END IF;
    failures:=0; n_varied:=0; n_copied:=0; n_failed:=0;
    FOR i IN 1..(:rows-present) LOOP
      inserted:=false;
      -- Trzy próby od najbogatszej: z polami opcjonalnymi, tylko pola obowiązkowe, kopia różniąca się kluczem.
      FOREACH expr IN ARRAY ARRAY[rich, varied, plain] LOOP
        BEGIN
          EXECUTE format('INSERT INTO %I.%I (%s) SELECT %s FROM %I.%I ORDER BY ctid LIMIT 1', t.nspname, t.relname, cols, expr, t.nspname, t.relname) USING i;
          GET DIAGNOSTICS n_rows = ROW_COUNT;
          -- wyzwalacz może po cichu odrzucić wiersz: liczy się tylko wiersz faktycznie wstawiony
          IF n_rows>0 THEN inserted:=true; IF expr=plain AND plain<>varied THEN n_copied:=n_copied+1; END IF; EXIT; END IF;
        EXCEPTION WHEN OTHERS THEN NULL;
        END;
      END LOOP;
      IF inserted THEN failures:=0;
      ELSE
        failures:=failures+1; n_failed:=n_failed+1;
        IF failures>=3 THEN RAISE NOTICE 'volume seed not applicable to %.%', t.nspname, t.relname; EXIT; END IF;
      END IF;
    END LOOP;
    -- Stan po zasiewie jest mierzony w tabeli, nie wyliczany; przejście 2 dopisuje do wyniku przejścia 1.
    EXECUTE format('SELECT count(*) FROM %I.%I', t.nspname, t.relname) INTO measured;
    n_extreme:=0;
    IF extreme_pred<>'' THEN EXECUTE format('SELECT count(*) FROM %I.%I WHERE %s', t.nspname, t.relname, extreme_pred) INTO n_extreme; END IF;
    SELECT coalesce(min(v.before),present), coalesce(sum(v.copied),0)+n_copied, coalesce(sum(v.failed),0)+n_failed INTO first_before, n_copied, n_failed FROM helix_volume v WHERE v.tbl=t.relname;
    DELETE FROM helix_volume WHERE tbl=t.relname;
    INSERT INTO helix_volume VALUES (t.relname, first_before, measured, n_extreme, n_copied, n_failed, NULL);
  END LOOP;
  END LOOP;
END $$;
SELECT coalesce(json_agg(row_to_json(v) ORDER BY v.tbl), '[]'::json) FROM helix_volume v;
