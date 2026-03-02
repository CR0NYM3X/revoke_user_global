
# 🛡️ PostgreSQL Global Access & Revoke Security Suite

Esta herramienta es un **motor de revocación granular y purga de identidades** para entornos PostgreSQL. Permite gestionar la salida de usuarios o cambios de permisos a nivel cluster, barriendo todas las bases de datos de forma automática mediante `dblink` y generando una auditoría detallada en tiempo real.

## 🚀 Características Principales

* **Ejecución Multi-DB:** Conecta automáticamente a todas las bases de datos del cluster (o a una lista específica) para limpiar privilegios.
* **Granularidad Total:** Revoca todos los permisos de cada base de datos.
* **Validación Previa:** Filtra usuarios inexistentes antes de iniciar el proceso para optimizar recursos.
* **Resiliencia (Fault Tolerance):** Si un comando falla (ej. un esquema no existe), el script captura la excepción, la loguea y **continúa** con el resto del proceso.
* **Auditoría Detallada:** Genera una tabla temporal `audit_report` con el estatus de cada comando ejecutado, tiempos de inicio/fin y mensajes de error del motor.
* **Niveles de Detalle:** Tres niveles de Verbosity (1: Resumen, 2: General, 3: Debug detallado).

---

## 🛠️ Requisitos

* **Extensión:** `dblink` instalada en el esquema `public`.
* **Permisos:** El usuario que ejecute la función debe tener privilegios de Superusuario o `CREATEROLE` para manipular otros roles y realizar `DROP USER`.
* **PostgreSQL:** Versión 12 o superior recomendada.

---

## 📖 Modo de Uso

### 1. Instalación

Carga el script en tu base de datos administrativa (usualmente `postgres`).

### 2. Ejecución

La función recibe cuatro parámetros:

1. `p_user_name` (TEXT[]): Array de usuarios a procesar.
2. `p_db_name` (TEXT[]): Array de bases de datos (Usa `ARRAY[NULL]` para procesar todas).
3. `p_drop_user_final` (BOOLEAN): `TRUE` para borrar el usuario, `FALSE` para solo quitar permisos.
4. `p_level_detail` (INTEGER): Nivel de log (1, 2 o 3).

**Ejemplo de Purga Total:**

```sql
SELECT fn_revoke_user_global(
    p_user_name       => ARRAY['empleado_v01', 'temp_app_user'],
    p_db_name         => ARRAY[NULL], 
    p_drop_user_final => TRUE,
    p_level_detail    => 3
);

```

### 3. Ver Reporte de Auditoría

Después de ejecutar, consulta los resultados en la misma sesión:

```sql
SELECT * FROM audit_report ORDER BY id;

```

 

## 📊 Estructura del Reporte (`audit_report`)

| Columna | Descripción |
| --- | --- |
| `fase` | `VALIDATION_USER`, `DB_CONNECT`, `REVOKE_USER`, `DROP_USER`, `FINAL_VERDICT`. |
| `status` | `successful` o `failed`. |
| `exec_cmd` | El comando SQL exacto que se intentó ejecutar. |
| `msg` | Respuesta directa del motor PostgreSQL (Mensaje de éxito o error detallado). |

---

## 🛡️ Seguridad

La función está definida como `SECURITY DEFINER` y tiene un `search_path` restringido para evitar ataques de búsqueda de esquemas. Se recomienda revocar el permiso de ejecución a `PUBLIC` y otorgarlo solo a roles de administración.

 
  
 
 # 🛠  Casos de Prueba Incluidos (Test Matrix)
Para asegurar que la función no "rompa" nada y se comporte de forma predecible, se ejecutaron los siguientes casos de uso:

#### 1. Gestión de Identidades (Filtro de Usuarios)

* **Prueba de "Usuarios Fantasma":** Le pasamos puros nombres de usuarios que no existen.
* *Qué pasó:* El script detectó que no había nadie en `pg_roles`, saltó la fase de conexión a las DBs y terminó limpio, avisando que no había nada que procesar.

* **Mix de Usuarios (Existentes + Inexistentes):** Mandamos una lista combinada (ej. 'admin_viejo' que sí está y 'user_test' que no).
* *Qué pasó:* Filtró los que no existen, los mandó al log de errores y siguió el proceso de revocación únicamente con los usuarios válidos.

#### 2. Flujos de Ejecución (Permisos vs. Borrado)

* **Solo Limpieza (Soft Revoke):** Se ejecutó con `p_drop_user_final => FALSE`.
* *Qué pasó:* El script entró a todas las DBs, quitó permisos, reasignó dueños y al final dejó al usuario vivo pero "desarmado".

* **Purga Total (Hard Revoke + Drop):** Se ejecutó con `p_drop_user_final => TRUE`.
* *Qué pasó:* Hizo todo el barrido de permisos y, una vez que el usuario quedó sin dependencias, le tiró el `DROP USER` sin errores de "role is being used".

#### 3. Control de Errores (Sintaxis y Resiliencia)

* **Inyección de Error de Sintaxis (Revoke Corrupto):** Modificamos un comando del array (ej. pusimos `REVOKEE` en vez de `REVOKE`) para forzar el fallo.
* *Escenario A (Solo Permisos):* El script falló en ese comando específico, lo guardó en la tabla de auditoría con el mensaje de error de Postgres y **siguió con los demás comandos**. No se detuvo.
* *Escenario B (Permisos + Borrado):* Igual que el anterior, pero al final el veredicto detectó que hubo fallos en los revokes y nos avisó que el proceso fue "exitoso con advertencias".

 
