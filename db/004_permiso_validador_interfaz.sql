-- =====================================================================
-- ChonTry — Migración 004: permiso sobre el validador de interfaces
-- La 002 revocó EXECUTE a PUBLIC en todas las funciones del esquema.
-- Los CHECK que llaman a es_interfaz_switch() se evalúan con los permisos
-- de quien inserta, así que el sensor y la consola necesitan EXECUTE.
-- (Hallado en las pruebas de la 002: "permission denied for function").
-- =====================================================================

grant execute on function chontry.es_interfaz_switch(text) to chontry_sensor, chontry_consola
