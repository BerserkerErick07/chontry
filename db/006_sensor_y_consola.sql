-- =====================================================================
-- ChonTry — Migración 006: soporte para el sensor real y la consola
--
--  * uid generado por el sensor en alertas y contenciones: permite que el
--    sensor trabaje sin conexión (buffer local) y sincronice después sin
--    duplicar registros.
--  * destinos agregados de una alerta (inet[]).
--  * una contención "por_revertir" sigue contando como activa.
--  * el sensor solo ejecuta transiciones válidas de una contención.
--  * configuración nueva: modo de ejecución, MFA obligatorio, heartbeat.
-- =====================================================================

alter table chontry.alertas add column if not exists uid uuid not null default gen_random_uuid()
--@@
alter table chontry.alertas add constraint uq_alertas_uid unique (uid)
--@@
alter table chontry.alertas add column if not exists destinos inet[] not null default '{}'
--@@
alter table chontry.contenciones add column if not exists uid uuid not null default gen_random_uuid()
--@@
alter table chontry.contenciones add constraint uq_contenciones_uid unique (uid)
--@@
drop index if exists chontry.ux_contencion_activa
--@@
create unique index ux_contencion_activa on chontry.contenciones(activo_id)
    where estado in ('propuesta', 'aprobada', 'aplicada', 'por_revertir')
--@@
grant update (puertos_destino, destinos) on chontry.alertas to chontry_sensor
--@@

-- El sensor ejecuta en el switch; solo puede hacer estas transiciones:
--   aprobada     -> aplicada | fallida      (contención aprobada por un admin)
--   por_revertir -> revertida               (liberación pedida por un admin)
--   aplicada     -> expirada                (venció el TTL)
--   insertar una contención automática ya aplicada o fallida
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
        if tg_op = 'INSERT' then
            if new.estado <> 'propuesta' and not (new.modo = 'automatica' and new.estado in ('aplicada', 'fallida')) then
                raise exception 'El sensor solo aplica sin aprobación las contenciones automáticas'
                    using errcode = 'insufficient_privilege';
            end if;
            return new;
        end if;
        if new.estado is distinct from old.estado and not (
               (old.estado = 'aprobada' and new.estado in ('aplicada', 'fallida'))
            or (old.estado = 'por_revertir' and new.estado = 'revertida')
            or (old.estado = 'aplicada' and new.estado = 'expirada')) then
            raise exception 'Transición de contención no permitida para el sensor: % -> %', old.estado, new.estado
                using errcode = 'insufficient_privilege';
        end if;
        return new;
    end if;

    -- Analista: solo propone
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

-- El auditor también entra a la consola (solo lectura): necesita su propio
-- login, sus sesiones y poder cambiar su contraseña y su segundo factor.
grant execute on function chontry.mis_credenciales(), chontry.registrar_login(boolean) to chontry_auditor
--@@
grant insert, update on chontry.sesiones to chontry_auditor
--@@
create policy p_sesiones_auditor_propias on chontry.sesiones for all to chontry_auditor
    using (usuario_id in (select u.id from chontry.usuarios u where u.rol_bd = current_user))
    with check (usuario_id in (select u.id from chontry.usuarios u where u.rol_bd = current_user))
--@@
grant update (password_hash, mfa_secreto_cifrado, debe_cambiar_clave) on chontry.usuarios to chontry_auditor
--@@
create policy p_usuarios_auditor_propio on chontry.usuarios for update
    to chontry_auditor using (rol_bd = current_user) with check (rol_bd = current_user)
--@@

insert into chontry.configuracion (clave, valor, descripcion) values
('contencion.modo_ejecucion', '"simulado"', 'simulado = el sensor registra los comandos sin conectarse al switch; real = los envía por SSH (Netmiko)'),
('auth.mfa_obligatorio', 'true', 'Exige segundo factor (TOTP) a todos los usuarios de la consola'),
('sensor.heartbeat_seg', '30', 'Cada cuántos segundos reporta el sensor que sigue vivo'),
('sensor.metricas_seg', '10', 'Cada cuántos segundos envía el sensor las métricas de tráfico')
on conflict (clave) do nothing
--@@

-- Sin servidores DHCP autorizados la regla no puede distinguir uno falso: se
-- deja el gateway de ejemplo; el administrador debe ajustarlo a su red.
update chontry.reglas_deteccion
   set parametros = '{"servidores_autorizados": ["10.10.20.1"]}'
 where codigo = 'CT-DHCP-001' and parametros = '{"servidores_autorizados": []}'
