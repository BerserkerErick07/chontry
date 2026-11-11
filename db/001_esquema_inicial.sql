-- =====================================================================
-- ChonTry — Migración 001: esquema inicial (PostgreSQL 15+ / Neon)
-- Equipo LOS CHONTOS
--
-- Cada sentencia va separada por una línea "--@@" para poder ejecutarla
-- por la API HTTP de Neon (una sentencia por consulta, todo en una transacción).
--
-- Trazabilidad:
--   ISO/IEC 27033-2   diseño de seguridad de red (segmentación, VLAN de cuarentena)
--   NIST SSDF PW.1/PW.5  diseño seguro y codificación segura (mínimo privilegio en BD)
--   NIST SSDF PS.2/PO.5  integridad de registros y entornos protegidos
--   OWASP ASVS 5.0 V6  autenticación (argon2id, bloqueo, MFA)
--   OWASP ASVS 5.0 V8  autorización (roles admin/analista/auditor + roles de BD)
--   OWASP ASVS 5.0 V11 criptografía (evidencias AES-256-GCM cifradas en el cliente)
--   OWASP ASVS 5.0 V16 registro de seguridad (auditoría append-only encadenada con SHA-256)
-- =====================================================================

create schema if not exists chontry
--@@
revoke all on schema chontry from public
--@@

-- ---------------------------------------------------------------------
-- Tipos
-- ---------------------------------------------------------------------
create type chontry.rol_usuario as enum ('admin', 'analista', 'auditor')
--@@
create type chontry.severidad as enum ('info', 'baja', 'media', 'alta', 'critica')
--@@
create type chontry.estado_alerta as enum ('nueva', 'en_revision', 'contenida', 'falso_positivo', 'cerrada')
--@@
create type chontry.estado_contencion as enum ('propuesta', 'aprobada', 'aplicada', 'fallida', 'rechazada', 'revertida', 'expirada')
--@@
create type chontry.modo_contencion as enum ('automatica', 'manual')
--@@
create type chontry.accion_regla as enum ('alertar', 'proponer_contencion', 'contener')
--@@
create type chontry.tipo_segmento as enum ('gestion', 'usuarios', 'servidores', 'invitados', 'cuarentena', 'otro')
--@@
create type chontry.estado_sensor as enum ('activo', 'degradado', 'detenido', 'desconocido')
--@@
create type chontry.actor_tipo as enum ('usuario', 'sensor', 'sistema')
--@@

-- ---------------------------------------------------------------------
-- Usuarios de la consola de escritorio y sus sesiones
-- ---------------------------------------------------------------------
create table chontry.usuarios (
    id                   uuid primary key default gen_random_uuid(),
    usuario              text not null unique check (usuario ~ '^[a-z0-9._-]{3,32}$'),
    nombre_completo      text not null check (length(nombre_completo) between 3 and 120),
    email                text unique check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
    password_hash        text not null check (password_hash like '$argon2id$%'),
    rol                  chontry.rol_usuario not null default 'analista',
    mfa_secreto_cifrado  bytea,
    activo               boolean not null default true,
    intentos_fallidos    smallint not null default 0 check (intentos_fallidos >= 0),
    bloqueado_hasta      timestamptz,
    debe_cambiar_clave   boolean not null default true,
    ultimo_login         timestamptz,
    creado_en            timestamptz not null default now(),
    actualizado_en       timestamptz not null default now()
)
--@@
create table chontry.sesiones (
    id            uuid primary key default gen_random_uuid(),
    usuario_id    uuid not null references chontry.usuarios(id) on delete cascade,
    token_hash    bytea not null unique,           -- SHA-256 del token; el token nunca se guarda
    equipo        text,
    ip_cliente    inet,
    creada_en     timestamptz not null default now(),
    expira_en     timestamptz not null,
    revocada_en   timestamptz,
    check (expira_en > creada_en)
)
--@@
create index ix_sesiones_usuario on chontry.sesiones(usuario_id) where revocada_en is null
--@@

-- ---------------------------------------------------------------------
-- Inventario de red
-- ---------------------------------------------------------------------
create table chontry.segmentos_red (
    id          integer generated always as identity primary key,
    nombre      text not null unique,
    red         cidr not null unique,
    vlan_id     smallint not null unique check (vlan_id between 1 and 4094),
    tipo        chontry.tipo_segmento not null,
    descripcion text,
    creado_en   timestamptz not null default now()
)
--@@
create table chontry.switches (
    id                 integer generated always as identity primary key,
    nombre             text not null unique,
    ip_gestion         inet not null unique,
    fabricante         text not null,                 -- cisco_ios, hp_procurve, aruba_os... (tipo Netmiko)
    modelo             text,
    puerto_ssh         integer not null default 22 check (puerto_ssh between 1 and 65535),
    credencial_ref     text not null,                 -- nombre de la entrada en el keyring del SO; NUNCA la contraseña
    huella_ssh_host    text,                          -- huella fijada (pinning) para evitar MITM en Paramiko/Netmiko
    vlan_cuarentena    smallint not null default 999 check (vlan_cuarentena between 1 and 4094),
    puerto_span        text,
    habilitado         boolean not null default true,
    creado_en          timestamptz not null default now()
)
--@@
create table chontry.sensores (
    id                 uuid primary key default gen_random_uuid(),
    nombre             text not null unique,
    interfaz_captura   text not null,
    filtro_bpf         text,
    ubicacion          text,
    switch_id          integer references chontry.switches(id),
    version            text,
    huella_certificado text,
    estado             chontry.estado_sensor not null default 'desconocido',
    ultimo_heartbeat   timestamptz,
    creado_en          timestamptz not null default now()
)
--@@
create table chontry.activos (
    id              bigint generated always as identity primary key,
    mac             macaddr not null unique,
    ip              inet,
    hostname        text,
    fabricante_nic  text,                             -- derivado del OUI
    segmento_id     integer references chontry.segmentos_red(id),
    switch_id       integer references chontry.switches(id),
    puerto_switch   text,
    vlan_actual     smallint check (vlan_actual between 1 and 4094),
    criticidad      smallint not null default 2 check (criticidad between 1 and 5),
    protegido       boolean not null default false,   -- gateway, DNS, AD...: jamás se contiene automáticamente
    notas           text,
    primera_vez     timestamptz not null default now(),
    ultima_vez      timestamptz not null default now()
)
--@@
create index ix_activos_ip on chontry.activos(ip)
--@@

-- ---------------------------------------------------------------------
-- Motor de detección: reglas y lista blanca
-- ---------------------------------------------------------------------
create table chontry.reglas_deteccion (
    id              integer generated always as identity primary key,
    codigo          text not null unique check (codigo ~ '^CT-[A-Z]{2,6}-[0-9]{3}$'),
    nombre          text not null,
    descripcion     text not null,
    categoria       text not null,                    -- reconocimiento, movimiento_lateral, suplantacion...
    parametros      jsonb not null default '{}'::jsonb,
    severidad_base  chontry.severidad not null,
    accion          chontry.accion_regla not null default 'alertar',
    mitre_tecnica   text,
    habilitada      boolean not null default true,
    version         integer not null default 1,
    actualizado_en  timestamptz not null default now()
)
--@@
create table chontry.lista_blanca (
    id          integer generated always as identity primary key,
    red         cidr,
    mac         macaddr,
    regla_id    integer references chontry.reglas_deteccion(id) on delete cascade,  -- null = todas las reglas
    motivo      text not null check (length(motivo) >= 10),
    creado_por  uuid references chontry.usuarios(id),
    creado_en   timestamptz not null default now(),
    expira_en   timestamptz,
    check (red is not null or mac is not null)
)
--@@
create index ix_lista_blanca_red on chontry.lista_blanca using gist (red inet_ops)
--@@

-- ---------------------------------------------------------------------
-- Alertas, evidencias y contenciones
-- ---------------------------------------------------------------------
create table chontry.alertas (
    id                 bigint generated always as identity primary key,
    sensor_id          uuid not null references chontry.sensores(id),
    regla_id           integer not null references chontry.reglas_deteccion(id),
    severidad          chontry.severidad not null,
    puntaje            smallint not null check (puntaje between 0 and 100),
    estado             chontry.estado_alerta not null default 'nueva',
    ip_origen          inet not null,
    mac_origen         macaddr,
    activo_origen_id   bigint references chontry.activos(id),
    ip_destino         inet,
    puertos_destino    integer[],
    protocolo          text,
    resumen            text not null,
    detalle            jsonb not null default '{}'::jsonb,
    conteo_eventos     integer not null default 1 check (conteo_eventos > 0),
    primera_deteccion  timestamptz not null,
    ultima_deteccion   timestamptz not null,
    asignada_a         uuid references chontry.usuarios(id),
    notas_analista     text,
    creado_en          timestamptz not null default now(),
    check (ultima_deteccion >= primera_deteccion)
)
--@@
create index ix_alertas_estado on chontry.alertas(estado, severidad) where estado in ('nueva', 'en_revision')
--@@
create index ix_alertas_fecha on chontry.alertas(primera_deteccion desc)
--@@
create index ix_alertas_ip_origen on chontry.alertas(ip_origen)
--@@
create table chontry.evidencias (
    id                bigint generated always as identity primary key,
    alerta_id         bigint not null references chontry.alertas(id),
    tipo              text not null check (tipo in ('pcap', 'json', 'texto')),
    contenido_cifrado bytea not null,                 -- AES-256-GCM, cifrado en el sensor antes de subir
    nonce             bytea not null check (length(nonce) = 12),
    id_clave          text not null,                  -- versión de la clave (rotación)
    sha256_claro      bytea not null check (length(sha256_claro) = 32),  -- cadena de custodia
    tamano_bytes      integer not null check (tamano_bytes >= 0),
    creado_en         timestamptz not null default now()
)
--@@
create index ix_evidencias_alerta on chontry.evidencias(alerta_id)
--@@
create table chontry.contenciones (
    id              bigint generated always as identity primary key,
    alerta_id       bigint references chontry.alertas(id),
    activo_id       bigint not null references chontry.activos(id),
    switch_id       integer not null references chontry.switches(id),
    puerto_switch   text not null,
    vlan_origen     smallint not null check (vlan_origen between 1 and 4094),
    vlan_destino    smallint not null check (vlan_destino between 1 and 4094),
    modo            chontry.modo_contencion not null,
    estado          chontry.estado_contencion not null default 'propuesta',
    motivo          text not null,
    solicitado_por  uuid references chontry.usuarios(id),   -- null = el motor
    aprobado_por    uuid references chontry.usuarios(id),
    aplicada_en     timestamptz,
    expira_en       timestamptz,                             -- TTL: se revierte sola si nadie la confirma
    revertida_en    timestamptz,
    revertida_por   uuid references chontry.usuarios(id),
    salida_comando  text,
    error           text,
    creado_en       timestamptz not null default now(),
    check (vlan_origen <> vlan_destino)
)
--@@
create unique index ux_contencion_activa on chontry.contenciones(activo_id) where estado in ('propuesta', 'aprobada', 'aplicada')
--@@
create index ix_contenciones_estado on chontry.contenciones(estado)
--@@

-- ---------------------------------------------------------------------
-- Telemetría del sensor, reportes y configuración
-- ---------------------------------------------------------------------
create table chontry.metricas_sensor (
    sensor_id            uuid not null references chontry.sensores(id),
    ts                   timestamptz not null,
    paquetes_por_seg     integer not null check (paquetes_por_seg >= 0),
    bits_por_seg         bigint not null check (bits_por_seg >= 0),
    paquetes_descartados integer not null default 0,
    hosts_activos        integer not null default 0,
    cpu_pct              real,
    mem_mb               real,
    primary key (sensor_id, ts)
)
--@@
create table chontry.reportes (
    id            bigint generated always as identity primary key,
    tipo          text not null,                     -- alertas, contenciones, auditoria, ejecutivo
    desde         timestamptz not null,
    hasta         timestamptz not null,
    formato       text not null check (formato in ('pdf', 'csv', 'json', 'html')),
    sha256        bytea not null check (length(sha256) = 32),
    generado_por  uuid not null references chontry.usuarios(id),
    creado_en     timestamptz not null default now(),
    check (hasta > desde)
)
--@@
create table chontry.configuracion (
    clave           text primary key check (clave ~ '^[a-z0-9_.]+$'),
    valor           jsonb not null,
    descripcion     text,
    actualizado_por uuid references chontry.usuarios(id),
    actualizado_en  timestamptz not null default now()
)
--@@

-- ---------------------------------------------------------------------
-- Auditoría append-only con cadena de hashes (tamper-evident)
-- ---------------------------------------------------------------------
create sequence chontry.auditoria_id_seq
--@@
create table chontry.auditoria (
    id          bigint primary key,                  -- lo asigna el trigger bajo bloqueo
    ts          timestamptz not null,
    actor_tipo  chontry.actor_tipo not null,
    actor_id    text not null,
    accion      text not null,
    entidad     text not null,
    entidad_id  text,
    detalle     jsonb not null default '{}'::jsonb,
    hash_prev   bytea not null,
    hash        bytea not null unique
)
--@@
create index ix_auditoria_entidad on chontry.auditoria(entidad, entidad_id)
--@@
create or replace function chontry.fn_auditoria_hash(a chontry.auditoria) returns bytea
language sql immutable as $$
    select sha256(a.hash_prev || convert_to(concat_ws('|',
        a.id::text,
        to_char(a.ts at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
        a.actor_tipo::text, a.actor_id, a.accion, a.entidad,
        coalesce(a.entidad_id, ''), a.detalle::text), 'UTF8'))
$$
--@@
create or replace function chontry.fn_auditoria_encadenar() returns trigger
language plpgsql security definer set search_path = chontry, pg_temp as $$
begin
    -- Serializa las inserciones para que la cadena sea lineal.
    perform pg_advisory_xact_lock(hashtext('chontry.auditoria'));
    new.id := nextval('chontry.auditoria_id_seq');
    new.ts := clock_timestamp();
    select a.hash into new.hash_prev from chontry.auditoria a order by a.id desc limit 1;
    new.hash_prev := coalesce(new.hash_prev, '\x00'::bytea);   -- bloque génesis
    new.hash := chontry.fn_auditoria_hash(new);
    return new;
end $$
--@@
create trigger tg_auditoria_encadenar before insert on chontry.auditoria
    for each row execute function chontry.fn_auditoria_encadenar()
--@@
create or replace function chontry.fn_solo_anexar() returns trigger
language plpgsql as $$
begin
    raise exception 'La tabla %.% es de solo anexado (append-only): % no permitido',
        tg_table_schema, tg_table_name, tg_op using errcode = 'insufficient_privilege';
end $$
--@@
create trigger tg_auditoria_inmutable before update or delete on chontry.auditoria
    for each row execute function chontry.fn_solo_anexar()
--@@
create trigger tg_auditoria_no_truncate before truncate on chontry.auditoria
    for each statement execute function chontry.fn_solo_anexar()
--@@
create trigger tg_evidencias_inmutable before update or delete on chontry.evidencias
    for each row execute function chontry.fn_solo_anexar()
--@@
create trigger tg_evidencias_no_truncate before truncate on chontry.evidencias
    for each statement execute function chontry.fn_solo_anexar()
--@@
create or replace function chontry.verificar_auditoria()
returns table (id bigint, problema text)
language plpgsql stable security definer set search_path = chontry, pg_temp as $$
declare
    r chontry.auditoria;
    prev bytea := '\x00'::bytea;
begin
    for r in select * from chontry.auditoria order by auditoria.id loop
        if r.hash_prev <> prev then
            id := r.id; problema := 'hash_prev no coincide con el registro anterior (registro borrado o insertado)'; return next;
        end if;
        if r.hash <> chontry.fn_auditoria_hash(r) then
            id := r.id; problema := 'hash no coincide con el contenido (registro modificado)'; return next;
        end if;
        prev := r.hash;
    end loop;
end $$
--@@

-- ---------------------------------------------------------------------
-- Alertas: campos forenses inmutables; no se borran, se cierran
-- ---------------------------------------------------------------------
create or replace function chontry.fn_alertas_proteger() returns trigger
language plpgsql as $$
begin
    if tg_op = 'DELETE' then
        raise exception 'Las alertas no se eliminan; cambie su estado a cerrada o falso_positivo'
            using errcode = 'insufficient_privilege';
    end if;
    if (new.sensor_id, new.regla_id, new.ip_origen, new.mac_origen, new.ip_destino,
        new.primera_deteccion, new.detalle, new.creado_en)
       is distinct from
       (old.sensor_id, old.regla_id, old.ip_origen, old.mac_origen, old.ip_destino,
        old.primera_deteccion, old.detalle, old.creado_en) then
        raise exception 'Los campos forenses de la alerta % son inmutables', old.id
            using errcode = 'insufficient_privilege';
    end if;
    return new;
end $$
--@@
create trigger tg_alertas_proteger before update or delete on chontry.alertas
    for each row execute function chontry.fn_alertas_proteger()
--@@

-- ---------------------------------------------------------------------
-- Registro automático de cambios en la auditoría
-- La app fija el actor con:  set local chontry.actor_tipo = 'usuario';
--                            set local chontry.actor_id   = '<uuid>';
-- ---------------------------------------------------------------------
create or replace function chontry.fn_registrar_cambio() returns trigger
language plpgsql security definer set search_path = chontry, pg_temp as $$
declare
    v_antes   jsonb := case when tg_op <> 'INSERT' then to_jsonb(old) - 'password_hash' - 'mfa_secreto_cifrado' end;
    v_despues jsonb := case when tg_op <> 'DELETE' then to_jsonb(new) - 'password_hash' - 'mfa_secreto_cifrado' end;
begin
    insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
    values (
        coalesce(nullif(current_setting('chontry.actor_tipo', true), ''), 'sistema')::chontry.actor_tipo,
        coalesce(nullif(current_setting('chontry.actor_id', true), ''), session_user),
        tg_op,
        tg_table_name,
        coalesce(v_despues, v_antes) ->> coalesce(nullif(tg_argv[0], ''), 'id'),
        jsonb_strip_nulls(jsonb_build_object('antes', v_antes, 'despues', v_despues))
    );
    return coalesce(new, old);
end $$
--@@
create trigger tg_aud_usuarios after insert or update or delete on chontry.usuarios
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_alertas after insert or update on chontry.alertas
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_contenciones after insert or update or delete on chontry.contenciones
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_reglas after insert or update or delete on chontry.reglas_deteccion
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_lista_blanca after insert or update or delete on chontry.lista_blanca
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_switches after insert or update or delete on chontry.switches
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_configuracion after insert or update or delete on chontry.configuracion
    for each row execute function chontry.fn_registrar_cambio('clave')
--@@
create trigger tg_aud_evidencias after insert on chontry.evidencias
    for each row execute function chontry.fn_registrar_cambio()
--@@
create trigger tg_aud_reportes after insert on chontry.reportes
    for each row execute function chontry.fn_registrar_cambio()
--@@

-- updated_at
create or replace function chontry.fn_tocar_actualizado() returns trigger
language plpgsql as $$
begin
    new.actualizado_en := now();
    return new;
end $$
--@@
create trigger tg_usuarios_actualizado before update on chontry.usuarios
    for each row execute function chontry.fn_tocar_actualizado()
--@@
create trigger tg_reglas_actualizado before update on chontry.reglas_deteccion
    for each row execute function chontry.fn_tocar_actualizado()
--@@
create trigger tg_config_actualizado before update on chontry.configuracion
    for each row execute function chontry.fn_tocar_actualizado()
--@@

-- ---------------------------------------------------------------------
-- Vistas para la consola
-- ---------------------------------------------------------------------
create view chontry.v_alertas_abiertas with (security_invoker = true) as
select a.id, a.severidad, a.puntaje, a.estado, a.ip_origen, a.mac_origen, ac.hostname,
       r.codigo as regla, r.nombre as regla_nombre, a.resumen, a.conteo_eventos,
       a.primera_deteccion, a.ultima_deteccion, u.usuario as asignada_a
from chontry.alertas a
join chontry.reglas_deteccion r on r.id = a.regla_id
left join chontry.activos ac on ac.id = a.activo_origen_id
left join chontry.usuarios u on u.id = a.asignada_a
where a.estado in ('nueva', 'en_revision')
--@@
create view chontry.v_resumen_24h with (security_invoker = true) as
select severidad, count(*) as total,
       count(*) filter (where estado in ('nueva', 'en_revision')) as abiertas
from chontry.alertas
where primera_deteccion >= now() - interval '24 hours'
group by severidad
--@@
create view chontry.v_cuarentena_activa with (security_invoker = true) as
select c.id, ac.ip, ac.mac, ac.hostname, s.nombre as switch, c.puerto_switch,
       c.vlan_origen, c.vlan_destino, c.modo, c.estado, c.aplicada_en, c.expira_en, c.alerta_id
from chontry.contenciones c
join chontry.activos ac on ac.id = c.activo_id
join chontry.switches s on s.id = c.switch_id
where c.estado in ('propuesta', 'aprobada', 'aplicada')
--@@
create view chontry.v_estado_sensores with (security_invoker = true) as
select s.id, s.nombre, s.estado, s.ultimo_heartbeat,
       (s.ultimo_heartbeat < now() - interval '2 minutes') as sin_reporte,
       m.paquetes_por_seg, m.bits_por_seg, m.paquetes_descartados
from chontry.sensores s
left join lateral (
    select * from chontry.metricas_sensor ms where ms.sensor_id = s.id order by ts desc limit 1
) m on true
--@@

-- ---------------------------------------------------------------------
-- Roles de base de datos (mínimo privilegio). Son NOLOGIN: se crean
-- usuarios con login en la consola de Neon y se les otorga el rol.
-- ---------------------------------------------------------------------
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'chontry_sensor')  then create role chontry_sensor  nologin; end if;
    if not exists (select 1 from pg_roles where rolname = 'chontry_consola') then create role chontry_consola nologin; end if;
    if not exists (select 1 from pg_roles where rolname = 'chontry_auditor') then create role chontry_auditor nologin; end if;
end $$
--@@
grant usage on schema chontry to chontry_sensor, chontry_consola, chontry_auditor
--@@
-- Auditor: solo lectura
grant select on all tables in schema chontry to chontry_auditor
--@@
grant execute on function chontry.verificar_auditoria() to chontry_auditor, chontry_consola
--@@
-- Sensor: escribe detecciones, nunca lee usuarios ni modifica reglas
grant select on chontry.reglas_deteccion, chontry.lista_blanca, chontry.segmentos_red,
                chontry.switches, chontry.configuracion, chontry.activos, chontry.alertas,
                chontry.contenciones to chontry_sensor
--@@
grant insert on chontry.alertas, chontry.evidencias, chontry.metricas_sensor,
                chontry.activos, chontry.contenciones, chontry.auditoria to chontry_sensor
--@@
grant update (conteo_eventos, ultima_deteccion, puntaje, severidad, estado) on chontry.alertas to chontry_sensor
--@@
grant update (ip, hostname, fabricante_nic, segmento_id, switch_id, puerto_switch, vlan_actual, ultima_vez) on chontry.activos to chontry_sensor
--@@
grant update (estado, aplicada_en, revertida_en, salida_comando, error) on chontry.contenciones to chontry_sensor
--@@
grant select, update (estado, ultimo_heartbeat, version) on chontry.sensores to chontry_sensor
--@@
-- Consola de escritorio
grant select on all tables in schema chontry to chontry_consola
--@@
grant insert, update on chontry.usuarios, chontry.sesiones, chontry.segmentos_red, chontry.switches,
                        chontry.sensores, chontry.activos, chontry.reglas_deteccion, chontry.lista_blanca,
                        chontry.contenciones, chontry.configuracion to chontry_consola
--@@
grant delete on chontry.lista_blanca, chontry.sesiones to chontry_consola
--@@
grant update (estado, asignada_a, notas_analista) on chontry.alertas to chontry_consola
--@@
grant insert on chontry.reportes, chontry.auditoria to chontry_consola
--@@
grant usage on all sequences in schema chontry to chontry_sensor, chontry_consola
--@@

-- ---------------------------------------------------------------------
-- Datos iniciales
-- ---------------------------------------------------------------------
insert into chontry.reglas_deteccion (codigo, nombre, descripcion, categoria, parametros, severidad_base, accion, mitre_tecnica) values
('CT-SCAN-001', 'Escaneo de puertos vertical',
 'Un host envía SYN (o conexiones sin completar) a muchos puertos distintos de un mismo destino en poco tiempo.',
 'reconocimiento', '{"puertos_distintos": 20, "ventana_seg": 10}', 'media', 'proponer_contencion', 'T1046'),
('CT-SCAN-002', 'Barrido de hosts (ping/ARP sweep)',
 'Un host contacta muchas IP distintas del segmento (ICMP echo o ARP who-has) en poco tiempo.',
 'reconocimiento', '{"hosts_distintos": 30, "ventana_seg": 30}', 'media', 'proponer_contencion', 'T1018'),
('CT-SCAN-003', 'Escaneo sigiloso (NULL/FIN/Xmas)',
 'Paquetes TCP con combinaciones de flags anómalas típicas de nmap -sN/-sF/-sX.',
 'reconocimiento', '{"paquetes": 5, "ventana_seg": 10}', 'alta', 'contener', 'T1046'),
('CT-LAT-001', 'Movimiento lateral por servicios de administración',
 'Un host de usuarios inicia conexiones SMB/RDP/WinRM/SSH hacia varios hosts internos.',
 'movimiento_lateral', '{"puertos": [445, 3389, 5985, 5986, 22], "destinos_distintos": 5, "ventana_seg": 300}', 'alta', 'contener', 'T1021'),
('CT-AUTH-001', 'Fuerza bruta contra servicio interno',
 'Muchas conexiones cortas repetidas al mismo servicio de autenticación de un destino.',
 'credenciales', '{"puertos": [22, 3389, 445, 21], "conexiones": 30, "ventana_seg": 60}', 'alta', 'proponer_contencion', 'T1110'),
('CT-SPOOF-001', 'Suplantación ARP (ARP spoofing)',
 'Una IP cambia de MAC o una MAC responde ARP por varias IP, especialmente la del gateway.',
 'suplantacion', '{"cambios_mac": 2, "ventana_seg": 60}', 'critica', 'contener', 'T1557.002'),
('CT-DHCP-001', 'Servidor DHCP no autorizado',
 'Se observan DHCPOFFER desde un host que no está registrado como servidor DHCP legítimo.',
 'suplantacion', '{"servidores_autorizados": []}', 'critica', 'contener', 'T1557.003')
--@@
insert into chontry.segmentos_red (nombre, red, vlan_id, tipo, descripcion) values
('Gestión',    '10.10.10.0/24', 10,  'gestion',    'Ejemplo: red de administración de switches y del sensor'),
('Usuarios',   '10.10.20.0/24', 20,  'usuarios',   'Ejemplo: laboratorios y estaciones de estudiantes'),
('Servidores', '10.10.30.0/24', 30,  'servidores', 'Ejemplo: servidores internos'),
('Cuarentena', '10.10.99.0/24', 999, 'cuarentena', 'VLAN de aislamiento: sin salida salvo hacia el portal de remediación')
--@@
insert into chontry.configuracion (clave, valor, descripcion) values
('contencion.modo_por_defecto', '"aprobacion"', 'aprobacion = el motor propone y un admin aprueba; automatica = solo para reglas con accion=contener'),
('contencion.ttl_minutos', '60', 'Minutos tras los que una contención automática se revierte si nadie la confirma'),
('contencion.max_por_hora', '5', 'Tope de contenciones automáticas por hora (evita que un atacante provoque un DoS haciéndose pasar por otros)'),
('deteccion.agregacion_seg', '300', 'Ventana en la que eventos repetidos del mismo origen y regla se agregan a la misma alerta'),
('retencion.alertas_dias', '365', 'Días de retención de alertas y evidencias'),
('retencion.metricas_dias', '30', 'Días de retención de métricas del sensor'),
('sesion.duracion_minutos', '480', 'Duración máxima de una sesión de la consola'),
('sesion.inactividad_minutos', '15', 'Cierre de sesión por inactividad'),
('auth.max_intentos', '5', 'Intentos fallidos antes del bloqueo temporal'),
('auth.bloqueo_minutos', '15', 'Duración del bloqueo temporal')
