-- =====================================================================
-- ChonTry — Migración 003: corrige ck_sensores_bpf de la 002
-- Las expresiones regulares de PostgreSQL admiten como máximo {n,255};
-- {1,512} hacía fallar cualquier INSERT con filtro BPF. La longitud
-- máxima se valida aparte con length().
-- =====================================================================

alter table chontry.sensores drop constraint ck_sensores_bpf
--@@
alter table chontry.sensores add constraint ck_sensores_bpf
    check (filtro_bpf ~ '^[A-Za-z0-9 ().:/!=<>\[\]-]+$' and length(filtro_bpf) <= 512)
