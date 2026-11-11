-- =====================================================================
-- ChonTry — Migración 002: corrección de hallazgos de la Clase 3
--
--   H2  Inyección de comandos en el switch / filtro de captura
--       → listas blancas en puerto_switch, interfaz_captura, filtro_bpf,
--         fabricante, huella SSH y credencial_ref         (ASVS V5 5.3)
--   H3  Email en la auditoría y actor falsificable
--       → se excluye el email; el actor es el login real de BD
--                                                     (ASVS V7 7.1.1)
--   H8  Escalada de rol desde la consola
--       → la autorización la aplica PostgreSQL, no el cliente:
--         login de BD por persona, rol chontry_admin, RLS en usuarios
--         y sesiones, aprobación de contenciones solo por admin
--                                         (ASVS V4, SSDF PW.9)
--
-- Igual que la 001: sentencias separadas por "--@@", una transacción.
-- =====================================================================

-- ---------------------------------------------------------------------
-- H2 · Listas blancas para todo valor que termina en un comando
-- ---------------------------------------------------------------------
-- Nombre de interfaz de switch: Gi1/0/1, GigabitEthernet1/0/24, Te1/1/1.100, A1, 24
-- Sin espacios, saltos de línea ni metacaracteres: nada que la CLI pueda leer como otro comando.
create or replace function chontry.es_interfaz_switch(p text) returns boolean
language sql immutable as $$
    select p ~ '^([A-Za-z][A-Za-z-]{0,24})?[0-9]{1,4}(/[0-9]{1,4}){0,3}(\.[0-9]{1,4})?$'
$$
--@@
alter table chontry.activos      add constraint ck_activos_puerto      check (chontry.es_interfaz_switch(puerto_switch))
--@@
alter table chontry.contenciones add constraint ck_contenciones_puerto check (chontry.es_interfaz_switch(puerto_switch))
--@@
alter table chontry.switches     add constraint ck_switches_span       check (chontry.es_interfaz_switch(puerto_span))
--@@
-- Interfaz de captura: nombre Linux (máx. 15, IFNAMSIZ) o dispositivo Npcap de Windows
alter table chontry.sensores add constraint ck_sensores_interfaz
    check (interfaz_captura ~ '^([A-Za-z0-9._-]{1,15}|\\Device\\NPF_\{[0-9A-Fa-f-]{36}\})$')
--@@
-- Filtro BPF: solo los caracteres de la sintaxis de pcap-filter.
-- Se excluyen ; | & ` $ comillas, barra invertida y saltos de línea (se usan and/or/not).
alter table chontry.sensores add constraint ck_sensores_bpf
    check (filtro_bpf ~ '^[A-Za-z0-9 ().:/!=<>\[\]-]{1,512}$')
--@@
-- Fabricante: solo los device_type de Netmiko que ChonTry soporta
alter table chontry.switches add constraint ck_switches_fabricante
    check (fabricante in ('cisco_ios', 'cisco_nxos', 'hp_procurve', 'aruba_os', 'juniper_junos', 'mikrotik_routeros'))
--@@
alter table chontry.switches add constraint ck_switches_huella
    check (huella_ssh_host ~ '^SHA256:[A-Za-z0-9+/]{43}$')
--@@
alter table chontry.switches add constraint ck_switches_credencial_ref
    check (credencial_ref ~ '^[a-z0-9._-]{3,64}$')
--@@

-- ---------------------------------------------------------------------
-- H3 · Auditoría sin email y con actor no falsificable
-- ---------------------------------------------------------------------
-- El actor ahora es session_user (el login real de PostgreSQL), que el
-- cliente no puede cambiar. Lo que diga la app queda solo como dato extra.
create or replace function chontry.fn_registrar_cambio() returns trigger
language plpgsql security definer set search_path = chontry, pg_temp as $$
declare
    -- Nunca a la auditoría: secretos ni datos personales (ASVS V7 7.1.1)
    v_excluir text[] := array['password_hash', 'mfa_secreto_cifrado', 'email', 'token_hash'];
    v_antes   jsonb := case when tg_op <> 'INSERT' then to_jsonb(old) - v_excluir end;
    v_despues jsonb := case when tg_op <> 'DELETE' then to_jsonb(new) - v_excluir end;
    v_tipo    chontry.actor_tipo;
begin
    v_tipo := case
        when pg_has_role(session_user, 'chontry_sensor', 'MEMBER') then 'sensor'
        when pg_has_role(session_user, 'chontry_consola', 'MEMBER')
          or pg_has_role(session_user, 'chontry_auditor', 'MEMBER') then 'usuario'
        else 'sistema'
    end;
    insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
    values (
        v_tipo,
        session_user,
        tg_op,
        tg_table_name,
        coalesce(v_despues, v_antes) ->> coalesce(nullif(tg_argv[0], ''), 'id'),
        jsonb_strip_nulls(jsonb_build_object(
            'antes', v_antes,
            'despues', v_despues,
            'actor_app', nullif(current_setting('chontry.actor_id', true), '')
        ))
    );
    return coalesce(new, old);
end $$
--@@

-- ---------------------------------------------------------------------
-- H8 · Autorización aplicada por la base de datos
-- ---------------------------------------------------------------------
-- La consola es un cliente de escritorio que se conecta directo a la BD:
-- para ella "el servidor" es PostgreSQL. Si la autorización solo vive en la
-- app, es validación del lado del cliente. Cada persona tiene su propio
-- login de BD, miembro de chontry_consola (analista) o chontry_admin.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'chontry_admin') then
        create role chontry_admin nologin;
    end if;
end $$
--@@
grant chontry_consola to chontry_admin
--@@
-- Vínculo entre la cuenta de la app y el login de BD
alter table chontry.usuarios add column rol_bd text unique check (rol_bd ~ '^ct_[a-z0-9_]{3,40}$')
--@@

-- Lo que solo puede hacer un admin se le quita al analista
revoke insert, update on chontry.usuarios, chontry.segmentos_red, chontry.switches, chontry.sensores,
                         chontry.reglas_deteccion, chontry.lista_blanca, chontry.configuracion,
                         chontry.activos from chontry_consola
--@@
revoke delete on chontry.lista_blanca from chontry_consola
--@@
grant insert, update on chontry.usuarios, chontry.segmentos_red, chontry.switches, chontry.sensores,
                        chontry.reglas_deteccion, chontry.lista_blanca, chontry.configuracion,
                        chontry.activos to chontry_admin
--@@
grant delete on chontry.lista_blanca, chontry.usuarios to chontry_admin
--@@
-- El analista solo documenta activos; marcar "protegido" o cambiar criticidad es de admin
grant update (hostname, notas) on chontry.activos to chontry_consola
--@@
-- Nadie lee hashes de contraseña, secretos MFA ni emails de otros usuarios
revoke select on chontry.usuarios from chontry_consola, chontry_auditor
--@@
grant select (id, usuario, nombre_completo, rol, activo, bloqueado_hasta, debe_cambiar_clave,
              ultimo_login, creado_en, actualizado_en, rol_bd)
    on chontry.usuarios to chontry_consola, chontry_auditor
--@@
-- El analista solo puede cambiar sus propios datos personales y su contraseña.
-- rol, activo, intentos_fallidos y bloqueado_hasta no están en la lista.
grant update (nombre_completo, email, password_hash, mfa_secreto_cifrado, debe_cambiar_clave)
    on chontry.usuarios to chontry_consola
--@@
alter table chontry.usuarios enable row level security
--@@
create policy p_usuarios_lectura on chontry.usuarios for select
    to chontry_consola, chontry_auditor using (true)
--@@
create policy p_usuarios_propio on chontry.usuarios for update
    to chontry_consola using (rol_bd = current_user) with check (rol_bd = current_user)
--@@
create policy p_usuarios_admin on chontry.usuarios for all
    to chontry_admin using (true) with check (true)
--@@
-- Sesiones: cada quien ve y cierra solo las suyas (evita crear una sesión a nombre de otro)
alter table chontry.sesiones enable row level security
--@@
create policy p_sesiones_propias on chontry.sesiones for all to chontry_consola
    using (usuario_id in (select u.id from chontry.usuarios u where u.rol_bd = current_user))
    with check (usuario_id in (select u.id from chontry.usuarios u where u.rol_bd = current_user))
--@@
create policy p_sesiones_admin on chontry.sesiones for all to chontry_admin using (true) with check (true)
--@@
create policy p_sesiones_auditor on chontry.sesiones for select to chontry_auditor using (true)
--@@

-- Credenciales propias para el login de la app (Argon2id + TOTP), solo de quien está conectado
create or replace function chontry.mis_credenciales()
returns table (id uuid, usuario text, rol chontry.rol_usuario, password_hash text,
               mfa_secreto_cifrado bytea, activo boolean, bloqueado_hasta timestamptz,
               debe_cambiar_clave boolean)
language sql stable security definer set search_path = chontry, pg_temp as $$
    select u.id, u.usuario, u.rol, u.password_hash, u.mfa_secreto_cifrado,
           u.activo, u.bloqueado_hasta, u.debe_cambiar_clave
    from chontry.usuarios u
    where u.rol_bd = session_user
$$
--@@
-- Contador de intentos y bloqueo: el analista no puede tocarlo directamente
create or replace function chontry.registrar_login(p_exito boolean) returns boolean
language plpgsql security definer set search_path = chontry, pg_temp as $$
declare
    v_max     integer;
    v_minutos integer;
    v_u       chontry.usuarios;
begin
    select coalesce((valor #>> '{}')::integer, 5)  into v_max     from chontry.configuracion where clave = 'auth.max_intentos';
    select coalesce((valor #>> '{}')::integer, 15) into v_minutos from chontry.configuracion where clave = 'auth.bloqueo_minutos';
    select * into v_u from chontry.usuarios where rol_bd = session_user for update;
    if not found or not v_u.activo then
        return false;
    end if;
    if v_u.bloqueado_hasta is not null and v_u.bloqueado_hasta > now() then
        return false;                                   -- bloqueado: ni siquiera se evalúa el éxito
    end if;
    if p_exito then
        update chontry.usuarios
           set intentos_fallidos = 0, bloqueado_hasta = null, ultimo_login = now()
         where id = v_u.id;
        return true;
    end if;
    update chontry.usuarios
       set intentos_fallidos = v_u.intentos_fallidos + 1,
           bloqueado_hasta = case when v_u.intentos_fallidos + 1 >= coalesce(v_max, 5)
                                  then now() + make_interval(mins => coalesce(v_minutos, 15)) end
     where id = v_u.id;
    return false;
end $$
--@@

-- Contenciones: el analista propone, solo el admin aprueba o rechaza.
-- El sensor ejecuta, pero no puede aprobar ni aplicar una propuesta manual.
create or replace function chontry.fn_contenciones_autorizar() returns trigger
language plpgsql set search_path = chontry, pg_temp as $$
declare
    v_owner name;
begin
    select tableowner into v_owner from pg_tables where schemaname = 'chontry' and tablename = 'contenciones';
    if pg_has_role(current_user, 'chontry_admin', 'MEMBER') or pg_has_role(current_user, v_owner, 'MEMBER') then
        return new;
    end if;

    if pg_has_role(current_user, 'chontry_sensor', 'MEMBER') then
        if new.estado in ('aprobada', 'rechazada') then
            raise exception 'El sensor no puede aprobar ni rechazar contenciones' using errcode = 'insufficient_privilege';
        end if;
        if tg_op = 'INSERT' and new.estado <> 'propuesta' and new.modo <> 'automatica' then
            raise exception 'El sensor solo aplica sin aprobación las contenciones automáticas' using errcode = 'insufficient_privilege';
        end if;
        if tg_op = 'UPDATE' and old.estado = 'propuesta' and new.estado <> 'propuesta' and old.modo <> 'automatica' then
            raise exception 'Una contención manual requiere aprobación de un administrador' using errcode = 'insufficient_privilege';
        end if;
        return new;
    end if;

    -- Analista
    if tg_op = 'INSERT' and (new.estado <> 'propuesta' or new.aprobado_por is not null) then
        raise exception 'Un analista solo puede proponer contenciones' using errcode = 'insufficient_privilege';
    end if;
    if tg_op = 'UPDATE' and (new.estado, new.aprobado_por, new.activo_id, new.switch_id, new.puerto_switch, new.vlan_destino, new.expira_en)
                is distinct from
                (old.estado, old.aprobado_por, old.activo_id, old.switch_id, old.puerto_switch, old.vlan_destino, old.expira_en) then
        raise exception 'Un analista no puede aprobar ni modificar una contención' using errcode = 'insufficient_privilege';
    end if;
    return new;
end $$
--@@
create trigger tg_contenciones_autorizar before insert or update on chontry.contenciones
    for each row execute function chontry.fn_contenciones_autorizar()
--@@

-- Las funciones no se ejecutan por PUBLIC; solo quien las necesita
revoke execute on all functions in schema chontry from public
--@@
grant execute on function chontry.mis_credenciales(), chontry.registrar_login(boolean) to chontry_consola
--@@
grant execute on function chontry.verificar_auditoria() to chontry_consola, chontry_auditor
--@@
grant execute on function chontry.fn_auditoria_hash(chontry.auditoria) to chontry_auditor, chontry_consola
