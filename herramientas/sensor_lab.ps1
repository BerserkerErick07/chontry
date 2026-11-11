# Inicia el sensor del LABORATORIO en vivo (lo llama laboratorio.bat como administrador).
# La interfaz de captura se toma de CHONTRY_LAB_INTERFAZ en .env.lab.
$raiz = Split-Path -Parent $PSScriptRoot
Set-Location $raiz
$Host.UI.RawUI.WindowTitle = "ChonTry - sensor"
$env:CHONTRY_ENV = ".env.lab"
$linea = Select-String -Path ".env.lab" -Pattern "^CHONTRY_LAB_INTERFAZ=" | Select-Object -First 1
if (-not $linea) {
    Write-Host "Falta CHONTRY_LAB_INTERFAZ en .env.lab (vea docs/guia_uso_real.md)"
    return
}
$interfaz = $linea.Line.Split("=", 2)[1].Trim()
& ".\.venv\Scripts\python.exe" -m sensor --interfaz $interfaz --filtro "not port 443"
