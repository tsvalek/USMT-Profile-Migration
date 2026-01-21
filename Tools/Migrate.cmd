@echo off
setlocal EnableDelayedExpansion

:: ============================================================
::  USMT Profile Migration Tool - Entry Point
::  Zapuskaet PowerShell skript s neobhodimymi pravami
:: ============================================================

title USMT Profile Migration Tool

:: Proverka prav administratora
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ================================================================
    echo   OSHIBKA: Trebuyutsya prava administratora!
    echo.
    echo   Pozhaluysta, zapustite etot skript ot imeni administratora:
    echo   Pravyy klik - "Zapusk ot imeni administratora"
    echo ================================================================
    echo.
    pause
    exit /b 1
)

:: Opredelyaem put' k skriptu
set "SCRIPT_DIR=%~dp0"

:: Udalyaem trailing backslash esli est'
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "PS_SCRIPT=%SCRIPT_DIR%\Migrate.ps1"

:: Proveryaem nalichie PowerShell skripta
if not exist "%PS_SCRIPT%" (
    echo.
    echo ================================================================
    echo   OSHIBKA: Fayl Migrate.ps1 ne nayden!
    echo.
    echo   Ubedit'es, chto fayl nahoditsya v toy zhe papke:
    echo   %SCRIPT_DIR%
    echo ================================================================
    echo.
    pause
    exit /b 1
)

:: Podklyuchaem setevoy disk esli eto UNC put'
set "NEED_POPD=0"
echo %SCRIPT_DIR% | findstr /b "\\\\" >nul
if %errorLevel% equ 0 (
    pushd "%SCRIPT_DIR%"
    if errorlevel 1 (
        echo.
        echo ================================================================
        echo   OSHIBKA: Ne udalos' podklyuchit' setevuyu papku
        echo   %SCRIPT_DIR%
        echo ================================================================
        echo.
        pause
        exit /b 1
    )
    set "NEED_POPD=1"
    set "PS_SCRIPT=Migrate.ps1"
)

:: Zapuskaem PowerShell skript s obhodom Execution Policy
echo Zapusk instrumenta migracii...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

:: Sohranyaem kod vozvrata
set "EXIT_CODE=%ERRORLEVEL%"

:: Vozvrashhaemsya iz pushd esli ispol'zovali
if "%NEED_POPD%"=="1" popd

:: Esli byla oshibka PowerShell
if %EXIT_CODE% neq 0 (
    echo.
    echo Skript zavershilsya s kodom oshibki: %EXIT_CODE%
    pause
)

exit /b %EXIT_CODE%
