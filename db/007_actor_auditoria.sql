-- =====================================================================
-- ChonTry — Migración 007: actor correcto en la auditoría
-- pg_has_role() es verdadero para el superusuario y puede serlo para el
-- dueño de la BD con cualquier rol; por eso sus acciones (migraciones,
-- instalación) aparecían como "sensor". Primero se identifica al dueño o
-- superusuario como "sistema" y luego se revisan los grupos.
-- (Hallado al probar el sensor en el laboratorio, 2026-11-10.)
-- =====================================================================

create or replace function chontry.fn_registrar_cambio() returns trigger
language plpgsql security definer set search_path = chontry, pg_temp as $$
declare
    -- Nunca a la auditoría: secretos ni datos personales (ASVS V7 7.1.1)
    -- ni el contenido cifrado de las evidencias (ya tiene su SHA-256; solo inflaría la auditoría)
    v_excluir text[] := array['password_hash', 'mfa_secreto_cifrado', 'email', 'token_hash', 'contenido_cifrado', 'nonce'];
    v_antes   jsonb := case when tg_op <> 'INSERT' then to_jsonb(old) - v_excluir end;
    v_despues jsonb := case when tg_op <> 'DELETE' then to_jsonb(new) - v_excluir end;
    v_tipo    chontry.actor_tipo;
begin
    v_tipo := case
        when (select r.rolsuper from pg_roles r where r.rolname = session_user)
          or session_user = (select t.tableowner from pg_tables t
                              where t.schemaname = 'chontry' and t.tablename = 'auditoria') then 'sistema'
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

-- Nunca aislar el puerto SPAN (dejaría ciego al sensor). Se valida en la BD
-- además de en el sensor y la consola (defensa en profundidad).
create or replace function chontry.fn_contenciones_puerto_seguro() returns trigger
language plpgsql set search_path = chontry, pg_temp as $$
begin
    if exists (select 1 from chontry.switches s
                where s.id = new.switch_id and s.puerto_span is not null and s.puerto_span = new.puerto_switch) then
        raise exception 'El puerto % es el puerto SPAN del sensor: no se puede aislar', new.puerto_switch
            using errcode = 'check_violation';
    end if;
    return new;
end $$
--@@
create trigger tg_contenciones_puerto_seguro before insert or update of puerto_switch, switch_id on chontry.contenciones
    for each row execute function chontry.fn_contenciones_puerto_seguro()
--@@

-- El auditor también genera reportes y deja constancia en la auditoría de lo
-- que consulta (exportar evidencias, iniciar y cerrar sesión).
grant insert on chontry.reportes, chontry.auditoria to chontry_auditor
--@@
grant usage on all sequences in schema chontry to chontry_auditor

--@@

-- Segundo factor de un solo uso (ASVS 2.8.4): se guarda el último paso de
-- tiempo TOTP aceptado y no se acepta uno igual o anterior (evita repetir un
-- código interceptado dentro de su ventana de 30-90 s).
alter table chontry.usuarios add column if not exists mfa_ultimo_paso bigint not null default 0
--@@
create or replace function chontry.consumir_totp(p_paso bigint) returns boolean
language plpgsql security definer set search_path = chontry, pg_temp as $$
begin
    update chontry.usuarios set mfa_ultimo_paso = p_paso
     where rol_bd = session_user and mfa_ultimo_paso < p_paso;
    return found;
end $$
--@@
revoke execute on function chontry.consumir_totp(bigint) from public
--@@
grant execute on function chontry.consumir_totp(bigint) to chontry_consola, chontry_auditor
