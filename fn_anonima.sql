DO $$
DECLARE
    -- ==========================================
    -- CONFIGURACIÓN DE PARÁMETROS
    -- ==========================================
    v_users_to_revoke TEXT[]  := ARRAY['jose', 'usuario_inexistente','maria']; -- Usuarios objetivo
    v_drop_user_final BOOLEAN := true;         -- ¿Eliminar usuario al final?
    
    -- Variables de control
    v_user           TEXT;
    v_db             TEXT;
    v_schema         TEXT;
    v_sql            TEXT;
    v_conn_str       TEXT;
    v_socket         TEXT;
    v_port           TEXT;
    v_db_conn_name   TEXT := 'remote_conn';
    v_error_msg      TEXT;
    v_created_dblink BOOLEAN := FALSE;          -- Flag para gestión de extensión
    v_users_valid    TEXT[]  := ARRAY[]::TEXT[]; -- Lista filtrada de usuarios que sí existen
BEGIN
    -- 1. Configurar nivel de verbosidad
    SET client_min_messages = notice;
    RAISE NOTICE 'Iniciando proceso de revocación global...';

    -- ==========================================
    -- FASE: VALIDACIÓN PREVIA DE USUARIOS
    -- ==========================================
    FOREACH v_user IN ARRAY v_users_to_revoke LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) THEN
            v_users_valid := array_append(v_users_valid, v_user);
            RAISE NOTICE '>> [VALIDACIÓN] Usuario % verificado y listo.', v_user;
        ELSE
            RAISE NOTICE '>> [VALIDACIÓN] Usuario % NO EXISTE. Se omitirá del proceso.', v_user;
        END IF;
    END LOOP;

    -- Si no hay usuarios válidos, terminamos
    IF array_length(v_users_valid, 1) IS NULL THEN
        RAISE NOTICE '------------------------------------------------------';
        RAISE NOTICE 'ABORTANDO: No se encontraron usuarios válidos para procesar.';
        RAISE NOTICE '------------------------------------------------------';
        RETURN;
    END IF;

    -- Gestión de extensión dblink
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'dblink') THEN
        CREATE EXTENSION dblink;
        v_created_dblink := TRUE;
        RAISE NOTICE '>> Extensión dblink creada temporalmente.';
    END IF;

    -- Obtener datos de red
    SELECT replace(setting, ' ', '') INTO v_socket FROM pg_settings WHERE name = 'unix_socket_directories';
    SELECT setting INTO v_port FROM pg_settings WHERE name = 'port';

    -- 2. Iterar por cada usuario VALIDADO
    FOREACH v_user IN ARRAY v_users_valid LOOP
        
        RAISE NOTICE '------------------------------------------------------';
        RAISE NOTICE 'PROCESANDO USUARIO: %', v_user;
        RAISE NOTICE '------------------------------------------------------';

        -- 3. Iterar por todas las Bases de Datos
        FOR v_db IN 
            SELECT datname FROM pg_database 
            WHERE datallowconn AND datname NOT IN ('template1', 'template0')
        LOOP
            RAISE NOTICE '>> Entrando a Base de Datos: %', v_db;
            
            v_conn_str := format('dbname=%L host=%s port=%s user=postgres', v_db, v_socket, v_port);
            
            BEGIN
                PERFORM dblink_connect(v_db_conn_name, v_conn_str);

                -- Comandos nivel Base de Datos
                v_sql := format('REASSIGN OWNED BY %I TO postgres', v_user);
                PERFORM dblink_exec(v_db_conn_name, v_sql);
                RAISE NOTICE '   [OK] EXEC: %...', left(v_sql, 30);

                v_sql := format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I', v_db, v_user);
                PERFORM dblink_exec(v_db_conn_name, v_sql);
                RAISE NOTICE '   [OK] EXEC: %...', left(v_sql, 30);

                -- 4. Iterar por todos los Esquemas
                FOR v_schema IN 
                    SELECT s_name FROM dblink(v_db_conn_name, 
                        'SELECT nspname FROM pg_catalog.pg_namespace 
                         WHERE nspname NOT IN (''information_schema'', ''pg_catalog'', ''datadog'') 
                         AND nspname NOT LIKE ''pg_temp%%'' 
                         AND nspname NOT LIKE ''pg_toast%%'''
                    ) AS t(s_name TEXT)
                LOOP
                    RAISE NOTICE '   -> Esquema: %', v_schema;
                    
                    DECLARE
                        v_cmds TEXT[] := ARRAY[
                            format('REVOKE ALL ON SCHEMA %I FROM %I', v_schema, v_user),
                            format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM %I', v_schema, v_user),
                            format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM %I', v_schema, v_user),
                            format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA %I FROM %I', v_schema, v_user),
                            format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM %I', v_schema, v_user),
                            format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM %I', v_schema, v_user)
                        ];
                        v_current_cmd TEXT;
                    BEGIN
                        FOREACH v_current_cmd IN ARRAY v_cmds LOOP
                            PERFORM dblink_exec(v_db_conn_name, v_current_cmd);
                            RAISE NOTICE '      [OK] %...', left(v_current_cmd, 40);
                        END LOOP;
                    END;
                END LOOP;

                PERFORM dblink_disconnect(v_db_conn_name);

            EXCEPTION WHEN OTHERS THEN
                GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
                RAISE WARNING 'Error procesando DB %: %', v_db, v_error_msg;
                IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
                    PERFORM dblink_disconnect(v_db_conn_name);
                END IF;
            END;
        END LOOP;

        -- 5. Eliminar el rol y VALIDAR
        IF v_drop_user_final THEN
            RAISE NOTICE '>> Intentando eliminar rol % del cluster...', v_user;
            BEGIN
                EXECUTE format('DROP ROLE %I', v_user);
                
                -- VALIDACIÓN POST-DROP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) THEN
                    RAISE NOTICE '>> [ERROR] El DROP ROLE % fue ejecutado pero el usuario SIGUE EXISTIENDO.', v_user;
                ELSE
                    RAISE NOTICE '   [OK] Rol % eliminado exitosamente.', v_user;
                END IF;
            EXCEPTION WHEN OTHERS THEN
                GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
                RAISE NOTICE '>> [FALLO] No se pudo eliminar el usuario %: %', v_user, v_error_msg;
            END;
        ELSE
            RAISE NOTICE '>> El rol % se mantiene según configuración.', v_user;
        END IF;

    END LOOP;

    -- Limpieza de dblink
    IF v_created_dblink THEN
        DROP EXTENSION dblink;
        RAISE NOTICE '>> Extensión dblink eliminada.';
    END IF;

    RAISE NOTICE '------------------------------------------------------';
    RAISE NOTICE 'PROCESO FINALIZADO';
    RAISE NOTICE '------------------------------------------------------';

EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
    IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
        PERFORM dblink_disconnect(v_db_conn_name);
    END IF;
    RAISE EXCEPTION 'Error crítico: %', v_error_msg;
END $$;
