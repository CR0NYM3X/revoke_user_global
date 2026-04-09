
DO $$
DECLARE
    -- ==========================================
    -- CONFIGURACIÓN DE PARÁMETROS
    -- ==========================================
    v_users_to_revoke TEXT[]  := ARRAY['jose', 'usuario_inexistente','maria', 'jose']; 
    v_nologin_final   BOOLEAN := TRUE;          -- ¿Aplicar NOLOGIN al finalizar?
    v_execute_revokes BOOLEAN := FALSE;          -- ¿Ejecutar revocación de privilegios (REVOKE/REASSIGN)?
    
    v_drop_user_final BOOLEAN := FALSE;         -- ¿Eliminar usuario al final?

    v_disable_hba     BOOLEAN := TRUE;          -- ¿Modificar pg_hba.conf de forma automática?
        v_backup_hba  BOOLEAN := TRUE;          -- ¿Quieres hacer Backup de pg_hba.conf?
        v_folio       TEXT    := '123456';      -- Agregar folio para auditoria de pg_hba
    v_reload          BOOLEAN := FALSE;         -- Hacer reload 

    v_detalle_notice BOOLEAN := FALSE;           -- Te imprime a detalle cada revoke ejecutado

    -- Variables de control
    v_user           TEXT;
    v_db             TEXT;
    v_schema         TEXT;
    v_sql            TEXT;
    v_conn_str       TEXT;
    v_socket         TEXT;
    v_port           TEXT;
    v_hba_path       TEXT;
    v_sys_cmd        TEXT;
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
    -- Filtrar usuarios únicos y existentes
    FOR v_user IN 
        SELECT DISTINCT unnest(v_users_to_revoke) 
    LOOP
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

    -- Localizar ruta del pg_hba.conf
    SELECT current_setting('data_directory') || '/pg_hba.conf' INTO v_hba_path;

    -- 2. Respaldo previo de pg_hba.conf (Solo si la opción está activada)
    IF v_disable_hba AND v_backup_hba THEN
        BEGIN
            v_sys_cmd := format('cp %s %s_backup_%s%s', v_hba_path, v_hba_path, TO_CHAR(NOW(), 'YYYYMMDD'), '_folio_' || v_folio);
            EXECUTE format('COPY (SELECT 1) TO PROGRAM %L', v_sys_cmd);
            RAISE NOTICE '>> [HBA] Respaldo creado exitosamente.';
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION '>> [HBA] No se pudo crear el respaldo. Verifique permisos de usuario postgres en OS.';
        END;
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

    -- 3. Iterar por cada usuario VALIDADO
    FOREACH v_user IN ARRAY v_users_valid LOOP
        
        RAISE NOTICE '------------------------------------------------------';
        RAISE NOTICE 'PROCESANDO USUARIO: %', v_user;
        RAISE NOTICE '------------------------------------------------------';

        -- Bloque de Revocación de privilegios (Opcional)
        IF v_execute_revokes THEN
            -- Iterar por todas las Bases de Datos
            FOR v_db IN 
                SELECT datname FROM pg_database 
                WHERE datallowconn AND datname NOT IN ('template1', 'template0')
            LOOP
                RAISE NOTICE '>> Entrando a Base de Datos: %', v_db;
                v_conn_str := format('dbname=%L host=%s port=%s user=postgres', v_db, v_socket, v_port);
                
                BEGIN
                    PERFORM dblink_connect(v_db_conn_name, v_conn_str);

                    -- Comandos nivel Base de Datos
                    PERFORM dblink_exec(v_db_conn_name, format('REASSIGN OWNED BY %I TO postgres', v_user));
                    PERFORM dblink_exec(v_db_conn_name, format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I', v_db, v_user));

                    -- Iterar por todos los Esquemas
                    FOR v_schema IN 
                        SELECT s_name FROM dblink(v_db_conn_name, 
                            'SELECT nspname FROM pg_catalog.pg_namespace 
                             WHERE nspname NOT IN (''information_schema'', ''pg_catalog'', ''datadog'') 
                             AND nspname NOT LIKE ''pg_temp%%'' 
                             AND nspname NOT LIKE ''pg_toast%%'''
                        ) AS t(s_name TEXT)
                    LOOP
                        IF v_detalle_notice THEN  RAISE NOTICE '   -> Esquema: %', v_schema; END IF;

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
                                IF v_detalle_notice THEN RAISE NOTICE '      [OK] %...', left(v_current_cmd, 40); END IF;
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
        ELSE
            RAISE NOTICE '>> [INFO] Se omite revocación de privilegios según v_execute_revokes.';
        END IF;

        -- 4. Modificación de pg_hba.conf para el usuario actual
        IF v_disable_hba THEN
            BEGIN
                v_sys_cmd := format(
                    'awk -v user="%s" -v dt="%s" ''{if ($1 !~ /^#/ && $3 == user) {print "# " $0 " # Deshabilitado  %s - fecha:  " dt} else {print $0}}'' %s > %s.tmp && mv %s.tmp %s',
                    v_user, TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI'), 'por el folio: ' || v_folio , v_hba_path, v_hba_path, v_hba_path, v_hba_path
                );
                EXECUTE format('COPY (SELECT 1) TO PROGRAM %L', v_sys_cmd);
                RAISE NOTICE '   [OK] pg_hba.conf actualizado para el usuario %.', v_user;
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING '   [FALLO] No se pudo modificar pg_hba.conf para %. Verifique awk/permisos.', v_user;
            END;
        END IF;

        -- 5. Fase Final: NOLOGIN y DROP
        IF v_nologin_final THEN
            BEGIN
                EXECUTE format('ALTER ROLE %I NOLOGIN', v_user);
                RAISE NOTICE '   [OK] NOLOGIN aplicado a %.', v_user;
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE '   [FALLO] No se pudo aplicar NOLOGIN a %.', v_user;
            END;
        END IF;

        IF v_drop_user_final THEN
            BEGIN
                EXECUTE format('DROP ROLE %I', v_user);
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) THEN
                    RAISE NOTICE '>> [ERROR] El usuario % SIGUE EXISTIENDO tras DROP.', v_user;
                ELSE
                    RAISE NOTICE '   [OK] Rol % eliminado.', v_user;
                END IF;
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE '>> [FALLO] DROP ROLE %: %', v_user, SQLERRM;
            END;
        END IF;

    END LOOP;

    -- Recarga de configuración si se modificó el HBA
    IF v_reload THEN
        PERFORM pg_reload_conf();
        RAISE NOTICE '>> [SISTEMA] Configuración recargada (pg_reload_conf).';
    END IF;

    -- Limpieza de dblink
    IF v_created_dblink THEN
        DROP EXTENSION dblink;
        RAISE NOTICE '>> Extensión dblink eliminada.';
    END IF;

    RAISE NOTICE '------------------------------------------------------';
    RAISE NOTICE 'PROCESO COMPLETADO EXITOSAMENTE';
    RAISE NOTICE '------------------------------------------------------';

EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
    IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
        PERFORM dblink_disconnect(v_db_conn_name);
    END IF;
    RAISE EXCEPTION 'Error crítico: %', v_error_msg;
END $$;
