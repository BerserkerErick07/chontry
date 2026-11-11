-- Pruebas de las migraciones 002-004 (Clase 3). Se ejecutan como dueño de la BD.
-- Antes: crear roles NOLOGIN ct_prueba_analista/admin/sensor, darles chontry_consola/chontry_admin/chontry_sensor
-- y otorgarlos al dueño. Todo termina en RAISE EXCEPTION, así que la transacción se revierte y no deja datos.
-- Resultado del 2026-11-03: 22/22 pruebas como se esperaba.

do $$
declare
    r text := E'\n';
    v_sw int; v_act bigint; v_c bigint; v_analista uuid; v_admin uuid; v_n int; v_det text;
begin
    -- Datos de prueba (como dueño)
    insert into chontry.usuarios (usuario, nombre_completo, email, password_hash, rol, rol_bd)
    values ('prueba.analista', 'Analista Prueba', 'analista@prueba.co', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA', 'analista', 'ct_prueba_analista')
    returning id into v_analista;
    insert into chontry.usuarios (usuario, nombre_completo, email, password_hash, rol, rol_bd)
    values ('prueba.admin', 'Admin Prueba', 'admin@prueba.co', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA', 'admin', 'ct_prueba_admin')
    returning id into v_admin;
    insert into chontry.switches (nombre, ip_gestion, fabricante, credencial_ref, puerto_span)
    values ('sw-prueba', '10.10.10.2', 'cisco_ios', 'sw-prueba', 'Gi1/0/48') returning id into v_sw;
    insert into chontry.activos (mac, ip, switch_id, puerto_switch, vlan_actual)
    values ('00:11:22:33:44:55', '10.10.20.50', v_sw, 'Gi1/0/5', 20) returning id into v_act;

    -- H2 · Inyección
    begin
        insert into chontry.activos (mac, puerto_switch) values ('00:11:22:33:44:56', E'Gi1/0/1\nreload');
        r := r || E'H2-1 puerto con salto de linea + comando: NO BLOQUEADO\n';
    exception when check_violation then r := r || E'H2-1 puerto con salto de linea + comando: bloqueado\n'; end;
    begin
        insert into chontry.activos (mac, puerto_switch) values ('00:11:22:33:44:57', 'Gi1/0/1 ; reload');
        r := r || E'H2-2 puerto con ; reload: NO BLOQUEADO\n';
    exception when check_violation then r := r || E'H2-2 puerto con ; reload: bloqueado\n'; end;
    begin
        insert into chontry.switches (nombre, ip_gestion, fabricante, credencial_ref) values ('x', '10.0.0.9', 'cisco_ios; reload', 'abc');
        r := r || E'H2-3 fabricante inventado: NO BLOQUEADO\n';
    exception when check_violation then r := r || E'H2-3 fabricante inventado: bloqueado\n'; end;
    begin
        insert into chontry.sensores (nombre, interfaz_captura, filtro_bpf) values ('s1', 'eth0', 'tcp; rm -rf /');
        r := r || E'H2-4 filtro BPF con ; rm -rf: NO BLOQUEADO\n';
    exception when check_violation then r := r || E'H2-4 filtro BPF con ; rm -rf: bloqueado\n'; end;
    begin
        insert into chontry.sensores (nombre, interfaz_captura, filtro_bpf) values ('s2', 'eth0 && reboot', 'tcp');
        r := r || E'H2-5 interfaz con && reboot: NO BLOQUEADO\n';
    exception when check_violation then r := r || E'H2-5 interfaz con && reboot: bloqueado\n'; end;
    begin
        insert into chontry.sensores (nombre, interfaz_captura, filtro_bpf)
        values ('s3', '\Device\NPF_{12345678-1234-1234-1234-123456789ABC}', 'not port 22 and (tcp or udp)');
        insert into chontry.activos (mac, puerto_switch) values ('00:11:22:33:44:58', 'GigabitEthernet1/0/24');
        r := r || E'H2-6 valores legitimos (Npcap, BPF valido, GigabitEthernet1/0/24): aceptados\n';
    exception when others then r := r || 'H2-6 valores legitimos: RECHAZADOS ' || sqlerrm || E'\n'; end;

    -- H3 · Email fuera de la auditoría
    select detalle::text into v_det from chontry.auditoria where entidad = 'usuarios' order by id desc limit 1;
    r := r || 'H3-1 email en la auditoria: ' || case when v_det like '%@prueba.co%' then 'PRESENTE' else 'ausente' end || E'\n';
    select count(*) into v_n from chontry.auditoria where entidad = 'usuarios' and detalle::text like '%password_hash%';
    r := r || 'H3-2 password_hash en la auditoria: ' || case when v_n > 0 then 'PRESENTE' else 'ausente' end || E'\n';
    select count(*) into v_n from chontry.verificar_auditoria();
    r := r || 'H3-3 fallos en la cadena de auditoria: ' || v_n || E'\n';

    -- H8 · Como analista
    execute 'set local role ct_prueba_analista';
    begin
        update chontry.usuarios set rol = 'admin' where id = v_analista;
        r := r || E'H8-1 analista se sube a admin: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-1 analista se sube a admin: denegado\n'; end;
    begin
        update chontry.usuarios set bloqueado_hasta = null, intentos_fallidos = 0 where id = v_analista;
        r := r || E'H8-2 analista se quita el bloqueo: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-2 analista se quita el bloqueo: denegado\n'; end;
    begin
        perform password_hash from chontry.usuarios;
        r := r || E'H8-3 analista lee hashes de contrasena: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-3 analista lee hashes de contrasena: denegado\n'; end;
    update chontry.usuarios set nombre_completo = 'Hackeado' where id = v_admin;
    get diagnostics v_n = row_count;
    r := r || 'H8-4 analista edita la cuenta del admin: ' || v_n || E' filas (RLS)\n';
    update chontry.usuarios set nombre_completo = 'Analista Editado' where id = v_analista;
    get diagnostics v_n = row_count;
    r := r || 'H8-5 analista edita su propia cuenta: ' || v_n || E' fila\n';
    begin
        insert into chontry.lista_blanca (red, motivo) values ('10.10.20.50/32', 'me pongo en lista blanca');
        r := r || E'H8-6 analista se agrega a la lista blanca: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-6 analista se agrega a la lista blanca: denegado\n'; end;
    begin
        update chontry.activos set protegido = true where id = v_act;
        r := r || E'H8-7 analista marca un activo como protegido: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-7 analista marca un activo como protegido: denegado\n'; end;
    begin
        insert into chontry.contenciones (activo_id, switch_id, puerto_switch, vlan_origen, vlan_destino, modo, estado, motivo)
        values (v_act, v_sw, 'Gi1/0/5', 20, 999, 'manual', 'aprobada', 'prueba');
        r := r || E'H8-8 analista crea contencion ya aprobada: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-8 analista crea contencion ya aprobada: denegado\n'; end;
    insert into chontry.contenciones (activo_id, switch_id, puerto_switch, vlan_origen, vlan_destino, modo, estado, motivo)
    values (v_act, v_sw, 'Gi1/0/5', 20, 999, 'manual', 'propuesta', 'escaneo de puertos') returning id into v_c;
    r := r || E'H8-9 analista propone contencion: permitido\n';
    begin
        update chontry.contenciones set estado = 'aprobada' where id = v_c;
        r := r || E'H8-10 analista aprueba su propuesta: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-10 analista aprueba su propuesta: denegado\n'; end;

    -- Como sensor
    execute 'reset role';
    execute 'set local role ct_prueba_sensor';
    begin
        update chontry.contenciones set estado = 'aplicada' where id = v_c;
        r := r || E'H8-11 sensor aplica una propuesta manual sin aprobar: PERMITIDO\n';
    exception when insufficient_privilege then r := r || E'H8-11 sensor aplica una propuesta manual sin aprobar: denegado\n'; end;

    -- Como admin
    execute 'reset role';
    execute 'set local role ct_prueba_admin';
    update chontry.contenciones set estado = 'aprobada', aprobado_por = v_admin where id = v_c;
    get diagnostics v_n = row_count;
    r := r || 'H8-12 admin aprueba la contencion: ' || v_n || E' fila\n';

    -- Sensor ya puede aplicarla
    execute 'reset role';
    execute 'set local role ct_prueba_sensor';
    update chontry.contenciones set estado = 'aplicada', aplicada_en = now() where id = v_c;
    get diagnostics v_n = row_count;
    r := r || 'H8-13 sensor aplica la contencion aprobada: ' || v_n || E' fila\n';
    execute 'reset role';

    raise exception 'RESULTADOS (se revierte todo):%', r;
end $$
