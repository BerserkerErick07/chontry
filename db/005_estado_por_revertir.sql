-- =====================================================================
-- ChonTry — Migración 005: estado "por_revertir" de una contención
-- El administrador pide liberar un host; el sensor (que tiene las
-- credenciales del switch) ejecuta la reversión y marca "revertida".
-- Va sola en su migración: PostgreSQL no deja usar un valor nuevo de
-- un enum en la misma transacción que lo crea.
-- =====================================================================

alter type chontry.estado_contencion add value if not exists 'por_revertir' after 'aplicada'
