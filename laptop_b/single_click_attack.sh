#!/usr/bin/env bash
# ================================================================
# DB-IDS/IPS ATTACK & STRESS TEST LAUNCHER (LAPTOP B) - Linux / Mac
# ================================================================

TARGET_IP="10.30.201.26"
TARGET_PORT="5000"

while true; do
    clear
    echo "================================================================"
    echo "   DB-IDS/IPS ATTACK & STRESS TEST LAUNCHER (LAPTOP B)"
    echo "================================================================"
    echo "Current Target: $TARGET_IP:$TARGET_PORT"
    echo "----------------------------------------------------------------"
    echo "  [1] Run Full Automated Attack Suite (All Tests Sequentially)"
    echo "  [2] Test DPI: SQL Injection (UNION SELECT / OR 1=1)"
    echo "  [3] Test DPI: Log4Shell RCE Header (CVE-2021-44228)"
    echo "  [4] Test DPI: EICAR Standard Test Signature"
    echo "  [5] Test Correlation: Horizontal Port Sweep Scan (20 Ports)"
    echo "  [6] Test Correlation: SSH Brute Force (Trigger Playbook #1)"
    echo "  [7] Stress Test: High-Volume UDP Packet Flood (16 Threads)"
    echo "  [8] Stress Test: High-Rate TCP Connection Flood"
    echo "  [9] Benign Traffic: Generate Normal Web Activity for Dashboard"
    echo "  [C] Change Target IP or Port"
    echo "  [Q] Quit"
    echo "================================================================"
    read -p "Select an option: " CHOICE

    case "$CHOICE" in
        1) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode all ;;
        2) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode sqli ;;
        3) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode log4shell ;;
        4) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode eicar ;;
        5) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode portscan ;;
        6) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode sshbrute ;;
        7) python3 stress_test.py --target "$TARGET_IP" --port "$TARGET_PORT" --proto UDP --threads 16 --duration 10 ;;
        8) python3 stress_test.py --target "$TARGET_IP" --port "$TARGET_PORT" --proto TCP --threads 16 --duration 10 ;;
        9) python3 attack_simulator.py --target "$TARGET_IP" --port "$TARGET_PORT" --mode benign ;;
        [cC]) 
            read -p "Enter new Target IP: " TARGET_IP
            read -p "Enter new Target Port (default 5000): " TARGET_PORT
            ;;
        [qQ]) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    echo ""
    read -p "Press Enter to return to menu..."
done
