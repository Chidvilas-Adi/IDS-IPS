@echo off
setlocal enabledelayedexpansion
title DB-IDS/IPS Attack & Stress Suite (Laptop B)
color 0A

:: Default Target IP of Laptop A
set TARGET_IP=10.30.201.26

:MENU
cls
echo ================================================================
echo    DB-IDS/IPS ATTACK & STRESS TEST LAUNCHER (LAPTOP B)
echo ================================================================
echo Current Target IP: %TARGET_IP%
echo ----------------------------------------------------------------
echo   [1] Run Full Automated Attack Suite (All Tests Sequentially)
echo   [2] Test DPI: SQL Injection (UNION SELECT / OR 1=1)
echo   [3] Test DPI: Log4Shell RCE Header (CVE-2021-44228)
echo   [4] Test DPI: EICAR Standard Test Signature
echo   [5] Test Correlation: Horizontal Port Sweep Scan (20 Ports)
echo   [6] Test Correlation: SSH Brute Force (Trigger Playbook #1)
echo   [7] Stress Test: High-Volume UDP Packet Flood (16 Threads)
echo   [8] Stress Test: High-Rate TCP Connection Flood
echo   [9] Benign Traffic: Generate Normal Web Activity for Dashboard
echo   [C] Change Target IP (Current: %TARGET_IP%)
echo   [Q] Quit
echo ================================================================
set /p CHOICE="Select an option (1-9, C, Q): "

if /i "%CHOICE%"=="1" goto RUN_ALL
if /i "%CHOICE%"=="2" goto RUN_SQLI
if /i "%CHOICE%"=="3" goto RUN_LOG4SHELL
if /i "%CHOICE%"=="4" goto RUN_EICAR
if /i "%CHOICE%"=="5" goto RUN_PORTSCAN
if /i "%CHOICE%"=="6" goto RUN_SSHBRUTE
if /i "%CHOICE%"=="7" goto RUN_STRESS_UDP
if /i "%CHOICE%"=="8" goto RUN_STRESS_TCP
if /i "%CHOICE%"=="9" goto RUN_BENIGN
if /i "%CHOICE%"=="C" goto CHANGE_IP
if /i "%CHOICE%"=="Q" goto EXIT
goto MENU

:RUN_ALL
cls
echo [*] Running full attack suite against %TARGET_IP%...
python attack_simulator.py --target %TARGET_IP% --mode all
pause
goto MENU

:RUN_SQLI
cls
echo [*] Sending SQL Injection exploit packets to %TARGET_IP%...
python attack_simulator.py --target %TARGET_IP% --mode sqli
pause
goto MENU

:RUN_LOG4SHELL
cls
echo [*] Sending Log4Shell exploit payload to %TARGET_IP%...
python attack_simulator.py --target %TARGET_IP% --mode log4shell
pause
goto MENU

:RUN_EICAR
cls
echo [*] Sending EICAR antivirus test signature to %TARGET_IP%...
python attack_simulator.py --target %TARGET_IP% --mode eicar
pause
goto MENU

:RUN_PORTSCAN
cls
echo [*] Executing 20-port sweep scan against %TARGET_IP%...
python attack_simulator.py --target %TARGET_IP% --mode portscan
pause
goto MENU

:RUN_SSHBRUTE
cls
echo [*] Firing rapid SSH connection burst to %TARGET_IP%:22...
python attack_simulator.py --target %TARGET_IP% --mode sshbrute
pause
goto MENU

:RUN_STRESS_UDP
cls
echo [*] Starting high-volume UDP flood (16 threads, 10 seconds)...
python stress_test.py --target %TARGET_IP% --proto UDP --threads 16 --duration 10
pause
goto MENU

:RUN_STRESS_TCP
cls
echo [*] Starting high-rate TCP connection flood (16 threads, 10 seconds)...
python stress_test.py --target %TARGET_IP% --proto TCP --threads 16 --duration 10
pause
goto MENU

:RUN_BENIGN
cls
echo [*] Generating benign browsing activity...
python attack_simulator.py --target %TARGET_IP% --mode benign
pause
goto MENU

:CHANGE_IP
cls
echo Current Target IP: %TARGET_IP%
set /p TARGET_IP="Enter new Target IP (Laptop A): "
echo [+] Updated target to %TARGET_IP%
timeout /t 2 >nul
goto MENU

:EXIT
echo Exiting...
exit /b 0
