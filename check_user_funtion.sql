
DO $$
DECLARE
    -- ==========================================
    -- CONFIGURACIÓN DE PARÁMETROS
    -- ==========================================
    v_users_to_find  TEXT[] := ARRAY['jose', 'maria', 'admin_externo']; 
    v_db_conn_name   TEXT   := 'audit_conn';
    
    -- Variables de control
    v_regex_pattern  TEXT;
    v_db             TEXT;
    v_conn_str       TEXT;
    v_socket         TEXT;
    v_port           TEXT;
    v_error_msg      TEXT;
    v_created_dblink BOOLEAN := FALSE;
    
    -- Variables para resultados
    v_res_user       TEXT;
    v_res_func       TEXT;
    v_found_count    INTEGER := 0;
BEGIN
    -- 1. Preparar el patrón Regex (user1|user2|user3)
    v_regex_pattern := array_to_string(v_users_to_find, '|');
    
    SET client_min_messages = notice;
    RAISE NOTICE 'Iniciando escaneo perimetral. Patrón: (%)', v_regex_pattern;

    -- Gestión de extensión dblink
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'dblink') THEN
        CREATE EXTENSION dblink;
        v_created_dblink := TRUE;
        RAISE NOTICE '>> Extensión dblink activada para la sesión.';
    END IF;

    -- Localizar socket y puerto para conexión interna
    SELECT replace(setting, ' ', '') INTO v_socket FROM pg_settings WHERE name = 'unix_socket_directories';
    SELECT setting INTO v_port FROM pg_settings WHERE name = 'port';

    -- 2. Iterar por todas las DBs que permiten conexiones
    FOR v_db IN 
        SELECT datname FROM pg_database 
        WHERE datallowconn 
          AND NOT datistemplate 
          AND datname NOT IN ('template1', 'template0')
    LOOP
        v_conn_str := format('dbname=%L host=%s port=%s user=postgres', v_db, v_socket, v_port);
        
        BEGIN
            PERFORM dblink_connect(v_db_conn_name, v_conn_str);

            -- 3. Consulta remota usando el operador ~*
            -- Buscamos en pg_proc.prosrc (código fuente)
            FOR v_res_user, v_res_func IN 
                SELECT t.u_match, t.f_name FROM dblink(v_db_conn_name, 
                    format($QUERY$
                        SELECT 
                            (regexp_matches(p.prosrc, %L, 'i'))[1], -- Extrae cuál usuario coincidió
                            n.nspname || '.' || p.proname           -- Esquema.Función
                        FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE p.prosrc ~* %L                        -- FILTRO CON REGEX CASE-INSENSITIVE
                          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                    $QUERY$, v_regex_pattern, v_regex_pattern)
                ) AS t(u_match TEXT, f_name TEXT)
            LOOP
                RAISE NOTICE '[DB: %] Coincidencia: El usuario "%" aparece en: %', v_db, v_res_user, v_res_func;
                v_found_count := v_found_count + 1;
            END LOOP;

            PERFORM dblink_disconnect(v_db_conn_name);

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
            RAISE WARNING 'Error al conectar/consultar DB %: %', v_db, v_error_msg;
            IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
                PERFORM dblink_disconnect(v_db_conn_name);
            END IF;
        END;
    END LOOP;

    -- 4. Finalización
    RAISE NOTICE '------------------------------------------------------';
    RAISE NOTICE 'RESUMEN: Se encontraron % menciones en total.', v_found_count;
    RAISE NOTICE '------------------------------------------------------';

    IF v_created_dblink THEN
        DROP EXTENSION dblink;
    END IF;

END $$;




/*

create database test101;
create database test102;
create database test103;


\c test101

-- 1. Creamos un esquema de pruebas para no ensuciar el public
CREATE SCHEMA IF NOT EXISTS test_auditoria;

-- 2. Función con el nombre de usuario en un comentario
CREATE OR REPLACE FUNCTION test_auditoria.proc_mantenimiento_v1()
RETURNS void AS $$
BEGIN
    -- Revisado por el usuario jose el 2023-10-01
    PERFORM 1;
END;
$$ LANGUAGE plpgsql;


\c test102
CREATE SCHEMA IF NOT EXISTS test_auditoria;
-- 3. Función con el nombre de usuario en una cadena de texto (Variable)
CREATE OR REPLACE FUNCTION test_auditoria.get_config_maria()
RETURNS text AS $$
DECLARE
    v_encargado TEXT := 'maria';
BEGIN
    RETURN 'Configuración de ' || v_encargado;
END;
$$ LANGUAGE plpgsql;

-- 4. Función con el nombre de usuario dentro de un RAISE NOTICE
CREATE OR REPLACE FUNCTION test_auditoria.alerta_seguridad()
RETURNS void AS $$
BEGIN
    RAISE NOTICE 'Acceso denegado para el perfil admin_externo';
END;
$$ LANGUAGE plpgsql;


\c test103
CREATE SCHEMA IF NOT EXISTS test_auditoria;
-- 5. Función que NO debería aparecer (no contiene nombres de la lista)
CREATE OR REPLACE FUNCTION test_auditoria.suma_simple(a int, b int)
RETURNS int AS $$
BEGIN
    RETURN a + b;
END;
$$ LANGUAGE plpgsql; -- O el lenguaje que uses

\c postgres

*/

-----------------
