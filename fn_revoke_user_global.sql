
-- create user jose ;
-- grant all privileges on all tables in schema public to jose;

/*
 @Function: fn_revoke_user_global
 @Creation Date: 23/01/2026
 @Description: Revocación granular multi-base de datos con ejecución de comandos por lotes 
               y registro detallado por cada sentencia individual.
 @Parameters:
   - @p_user_name (TEXT[]): Array Usuarios objetivo.
   - @p_db_name (TEXT[]): Array de DBs objetivo (NULL para todas).
   - @p_drop_user_final (BOOLEAN): Eliminar rol al finalizar.
   - @p_level_detail (INTEGER): 1 (Status), 2 (General), 3 (Verbose).
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 23/01/2026
 @Change: Implementación de ejecución granular por comandos y logging dinámico.
 @Author: CR0NYM3X
*/


-- DROP  FUNCTION fn_revoke_user_global(TEXT[],TEXT[],BOOLEAN , INTEGER); 
CREATE OR REPLACE FUNCTION fn_revoke_user_global(
    p_user_name        TEXT[],
    p_db_name          TEXT[]  DEFAULT ARRAY[NULL],
    p_drop_user_final  BOOLEAN DEFAULT TRUE,
    p_level_detail     INTEGER DEFAULT 2
)
RETURNS TABLE(
        db_name     TEXT,
        user_name   TEXT,
        fase        TEXT,
        status      TEXT,
        exec_cmd    TEXT,
        msg         TEXT,
        start_time  TIMESTAMPTZ,
        end_time    TIMESTAMPTZ 
    )
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = 'public , pg_temp , pg_catalog'
AS $func$
DECLARE
    -- Variables de Control y Estética
    v_insert_table  TEXT := 'INSERT INTO audit_report(db_name, user_name, fase, status, exec_cmd, msg, start_time) VALUES (%L, %L, %L, %L, %L, %L, %L)';
    v_fase_start    TIMESTAMPTZ;
    v_start_proc    TIMESTAMPTZ := clock_timestamp();
    
    -- Variables de Operación
    v_db_current    TEXT;
    v_user_target   TEXT;
    v_cmd_current   TEXT;
    v_socket        TEXT;
    v_port          TEXT;
    v_conn_str      TEXT;
    v_sql_final     TEXT;
    v_users_valid   TEXT[] := ARRAY[]::TEXT[]; -- Lista de usuarios filtrada
    v_error_count   INTEGER := 0; -- Contador de errores detectados
	v_flag_extension BOOLEAN := FALSE;

    -- Listado Granular de Comandos (Plantillas)
    -- %1$I = Usuario, %2$I = Base de Datos
    v_revoke_commands TEXT[] := ARRAY[
        'REASSIGN OWNED BY %1$I TO postgres',
        'ALTER ROLE %1$I NOINHERIT',
        'REVOKE ALL PRIVILEGES ON DATABASE %2$I FROM %1$I',
        'REVOKE ALL ON SCHEMA public FROM %1$I',
        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %1$I',
        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %1$I',
        'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM %1$I',
        'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %1$I',
        'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %1$I'
    ];

    -- Diagnóstico
    ex_msg TEXT;
BEGIN
    -- 1. PREPARACIÓN
    DROP TABLE IF EXISTS audit_report;
    CREATE TEMP TABLE audit_report (
        id          SERIAL,
        db_name     TEXT,
        user_name   TEXT,
        fase        TEXT,
        status      TEXT,
        exec_cmd    TEXT,
        msg         TEXT,
        start_time  TIMESTAMPTZ,
        end_time    TIMESTAMPTZ DEFAULT clock_timestamp()
    );

    -- 2. FASE: VALIDACIÓN DE USUARIOS (NUEVA)
    v_fase_start := clock_timestamp();
    FOREACH v_user_target IN ARRAY p_user_name LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user_target) THEN
            
			IF (v_user_target LIKE '9%') THEN
				v_users_valid := array_append(v_users_valid, v_user_target);
			ELSE
				RAISE NOTICE '[VALIDACIÓN] Usuario no valido encontrado: %', v_user_target;
                EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'VALIDATION_USER', 'failed', 'CHECK_USER', 'Usuario existente pero no cumple con las especificaciones', v_fase_start);
			END IF;
			

            IF p_level_detail >= 2 THEN
                RAISE NOTICE '[VALIDACIÓN] Usuario encontrado: %', v_user_target;
                EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'VALIDATION_USER', 'successful', 'CHECK_USER', 'Usuario existente y listo para proceso', v_fase_start);
            END IF;
        ELSE
            RAISE NOTICE '[VALIDACIÓN] Usuario NO EXISTE: %', v_user_target;
            EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'VALIDATION_USER', 'failed', 'CHECK_USER', 'El usuario no existe en el sistema', v_fase_start);
        END IF;
    END LOOP;

    -- Validar si hay trabajo que hacer
    IF array_length(v_users_valid, 1) IS NULL THEN
        RAISE NOTICE '---------------------------------------------------';
        RAISE NOTICE 'FINALIZADO: Ninguno de los usuarios proporcionados existe.';
        RAISE NOTICE '---------------------------------------------------';
        EXECUTE FORMAT(v_insert_table, 'CLUSTER', 'N/A', 'FINAL_VERDICT', 'failed', 'ABORT_PROC', 'No hay usuarios válidos para procesar. Proceso abortado.', v_fase_start);
        -- RETURN;
         RETURN QUERY SELECT a.db_name,a.user_name,a.fase,a.status,a.exec_cmd,a.msg,a.start_time,a.end_time FROM audit_report as a /* where a.fase = 'FINAL_VERDICT'*/ ORDER BY a.id;
		 RETURN;
    END IF;


    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'dblink') THEN
        CREATE EXTENSION dblink SCHEMA public;
		v_flag_extension := TRUE;
    END IF;

    SELECT replace(setting, ' ', '') INTO v_socket FROM pg_settings WHERE name = 'unix_socket_directories';
    SELECT setting INTO v_port FROM pg_settings WHERE name = 'port';

    -- 2. ITERACIÓN POR BASE DE DATOS
    FOR v_db_current IN 
        SELECT datname FROM pg_database 
        WHERE datallowconn AND datname NOT IN ('template1', 'template0')
        AND (p_db_name IS NULL OR p_db_name = ARRAY[NULL]::TEXT[] OR datname = ANY(p_db_name))
    LOOP
        v_fase_start := clock_timestamp();
        v_conn_str := format('dbname=%L host=%s port=%s user=postgres', v_db_current, v_socket, v_port);
        
        BEGIN
            -- Log Conexión
            IF p_level_detail = 3 THEN 
                RAISE NOTICE ' -> Conectando a base de datos: %', v_db_current; 
                EXECUTE FORMAT(v_insert_table, v_db_current, '', 'DB_CONNECT', 'successful', 'dblink_connect', 'Conectandose a la base de datos', v_fase_start);
            END IF;

            PERFORM public.dblink_connect('conn_revoke', v_conn_str);

            -- 3. ITERACIÓN POR USUARIO
            FOREACH v_user_target IN ARRAY v_users_valid LOOP
                --IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user_target) THEN
                    
                    v_sql_final := NULL;
                    -- 4. EJECUCIÓN GRANULAR DE COMANDOS
                    FOREACH v_cmd_current IN ARRAY v_revoke_commands LOOP
                        -- DECLARE
                            -- v_sql_final TEXT := format(v_cmd_current, v_user_target, v_db_current);
                        BEGIN
                            v_sql_final := format(v_cmd_current, v_user_target, v_db_current);
                            v_fase_start := clock_timestamp();
                            
                            -- Ejecución vía dblink_exec para capturar éxito/fallo individual
                            PERFORM public.dblink_exec('conn_revoke', v_sql_final);

                            IF p_level_detail = 3 THEN
                                RAISE NOTICE '    [OK] %', v_sql_final;
                                EXECUTE FORMAT(v_insert_table, v_db_current, v_user_target, 'REVOKE_USER', 'successful', v_sql_final, 'Ejecutado correctamente', v_fase_start);
                            END IF;

                        EXCEPTION WHEN OTHERS THEN
                            GET STACKED DIAGNOSTICS ex_msg = MESSAGE_TEXT;
                            EXECUTE FORMAT(v_insert_table, v_db_current, v_user_target, 'REVOKE_USER', 'failed', v_sql_final, ex_msg, v_fase_start);
                            RAISE WARNING '    [FALLO] DB: % | CMD: % | Error: %', v_db_current, v_sql_final, ex_msg;
                        END;
                    END LOOP;

                --ELSE 
                --    IF p_level_detail = 3 THEN
                --        RAISE NOTICE '    [ERROR] %', v_sql_final;
                --        EXECUTE FORMAT(v_insert_table, v_db_current, v_user_target, 'REVOKE_USER', 'failed', v_sql_final, 'No existe el usuario ' || v_user_target , v_fase_start);
                --    END IF;
                --END IF;
            END LOOP;

            PERFORM public.dblink_disconnect('conn_revoke');
			
		

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS ex_msg = MESSAGE_TEXT;
            EXECUTE FORMAT(v_insert_table, v_db_current, '', 'DB_CONNECT', 'failed', 'CONNECTION', ex_msg, v_fase_start);
            IF public.dblink_get_connections() @> '{conn_revoke}' THEN PERFORM public.dblink_disconnect('conn_revoke'); END IF;
        END;

		IF (v_flag_extension) THEN 
			DROP EXTENSION dblink;
		END IF;

    END LOOP;

    SELECT COUNT(*) INTO v_error_count FROM audit_report as b WHERE b.status = 'failed' AND b.fase in('DB_CONNECT','REVOKE_USER');
    v_fase_start := clock_timestamp();

    -- 5. FASE FINAL: DROP USER
    IF p_drop_user_final THEN
        FOREACH v_user_target IN ARRAY v_users_valid LOOP
            v_fase_start := clock_timestamp();
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user_target) THEN
                    EXECUTE format('DROP USER %I', v_user_target);
                    RAISE NOTICE ' -> Eliminación de usuario'; 
                    EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'DROP_USER', 'successful', 'DROP USER', 'Usuario eliminado', v_fase_start);
                    RAISE NOTICE '    [OK] DROP USER %L', v_user_target;
                    EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'FINAL_VERDICT', 'successful', 'DROP USER', 
                    'Proceso completado con ' || v_error_count || ' errores granulares.', v_fase_start);
                END IF;


            EXCEPTION WHEN OTHERS THEN
                GET STACKED DIAGNOSTICS ex_msg = MESSAGE_TEXT;
                EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'DROP_USER', 'failed', 'REVOKE USER + DROP USER', ex_msg, v_fase_start);
                EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'FINAL_VERDICT', 'failed', 'REVOKE USER + DROP USER', 
                'Proceso completado con ' || v_error_count || ' errores granulares.', v_fase_start);                
            END;
        END LOOP;
    ELSE
        -- No se pidió DROP, pero notificamos si los REVOKE fallaron
        IF v_error_count > 0 THEN
            RAISE NOTICE 'ALERTA: Se detectaron % errores en la fase de revocación.', v_error_count;
            EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'FINAL_VERDICT', 'failed', 'REVOKE USER', 
                           'Proceso completado con ' || v_error_count || ' errores granulares.', v_fase_start);
        ELSE
            EXECUTE FORMAT(v_insert_table, 'CLUSTER', v_user_target, 'FINAL_VERDICT', 'successful', 'REVOKE USER', 
                           'Revocación completada sin errores detectados.', v_fase_start);
        END IF;        
    END IF;

    -- CIERRE Y NOTIFICACIÓN
    IF p_level_detail >= 1 THEN
        RAISE NOTICE '---------------------------------------------------';
        RAISE NOTICE 'PROCESO FINALIZADO. REVISE audit_report PARA DETALLES.';
        RAISE NOTICE '---------------------------------------------------';
    END IF;
     -- INSERT INTO audit_report (db_name, user_name, fase, status, exec_cmd, msg, start_time) VALUES (current_database(), current_user, 'INICIO', 'SUCCESS', 'SELECT * FROM...', 'Proceso completado', now());
     RETURN QUERY SELECT a.db_name,a.user_name,a.fase,a.status,a.exec_cmd,a.msg,a.start_time,a.end_time FROM audit_report as a /* where a.fase = 'FINAL_VERDICT'*/ ORDER BY a.id;
	
END;
$func$;

revoke EXECUTE on function fn_revoke_user_global(TEXT[],TEXT[],BOOLEAN , INTEGER) from PUBLIC;
-- grant EXECUTE on function fn_revoke_user_global(TEXT[],TEXT[],BOOLEAN , INTEGER) to   userpermisos;



---------------- COMMENT ----------------
COMMENT ON FUNCTION fn_revoke_user_global(TEXT[], TEXT[], BOOLEAN, INTEGER) IS
'Suite de seguridad para revocación masiva de accesos.
- Parámetros: Usuarios, Bases de Datos, Drop final, Nivel Detalle.
- Retorno: void (Genera tabla temporal audit_report).
- Volatilidad: VOLATILE.
- Seguridad: SECURITY DEFINER (requiere permisos de superusuario para dblink y drop role).
- Notas: Crea extensión dblink si no existe.';


-- Ejemplo Nivel 3 (Detallado)
-- SELECT fn_revoke_user_global(
--     p_user_name       => ARRAY['jose', 'temp_app_user'],
--     p_db_name         => ARRAY[NULL],
--     p_drop_user_final => TRUE,
--     p_level_detail    => 3
-- );

-- Ver reporte generado
-- truncate table audit_report RESTART IDENTITY ;
-- SELECT * FROM audit_report ORDER BY id;
