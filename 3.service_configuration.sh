#!/bin/bash

#Script shell 
#Linux hardening system services
#by : hatim trzt
#
source ./rules_template/svc_config_functions.sh

while true; do
    clear  

    # 
    echo -e "\e[93m[>]\e[00m System Services Hardening \e[93m[<]\e[00m"
    echo "1. PAM policy"
    echo "2. Google-Authentificator (on login and ssh)"
    echo "3. SSH server config"
    echo "4. Log server policies"
    echo "5. Network services"
    echo "6. Password expiration rules"
    echo "7. Iptables recommanded rules"
    echo "8. Recommended sysctl network settings"
    echo "9. Check open/listen ports and sockets"
    echo "10. Securing PHP/apache"
    echo "11. Disable system accounts login"
    echo "-------------------"
    echo "97. Check installed packages"
    echo "98. Update system"
    echo "99. Apply All"
    echo "0. Exit"
    
    # 
    read -p  "> Enter your choice (0-99): " choice

    case $choice in
        1)
            password_pam
            ;;
        2)
            google_2fa
            ;;
        3)
            set_sshd
            ;;
        4)
            logconfig_auditd
            ;;
        5)
            disable_services  
            ;;
        6)
            passwd_logindefs
            ;;
        7)
            rules_iptables
            ;;
        8)
            sysctl_network_param
            ;;
        9)
            netstat -antlp  
            ss -antlp 
            ;;  
        10)
            secure_php_apache
            ;;
        11)
            disable_sys_acc
            ;;           
        97)
            apt-cache pkgnames
            done_pause
            ;;
        98)
            update_system
            done_pause
            ;;
        99)
            password_pam
            google_2fa
            set_sshd
            logconfig_auditd
            disable_services  
            passwd_logindefs
            rules_iptables
            sysctl_network_param
            secure_php_apache
            disable_sys_acc
            ;;
        0)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please enter a valid number ."
            ;;
    esac

    # Pause 
    read -p "Press Enter to continue..."
done


