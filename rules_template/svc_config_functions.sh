#!/bin/bash

restart_service(){
    #if systemctl exist (in kali and newer distro)
    if command -v systemctl &>/dev/null; then
        service_name=$1
        sudo systemctl restart "$service_name"
    #if not (old distro ubuntu)
    else
        service_name=$2
        sudo service "$service_name" restart
    fi
}

done_pause(){
    echo "Done !!"
    read -p "Press Enter to continue..." 
}
username=$(whoami)

password_pam() {
    #backup
    cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
    cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
    cp /etc/pam.d/login /etc/pam.d/login.bak
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
    #
    echo -e "Adding templates"
    cat ./rules_template/common-auth > /etc/pam.d/common-auth
    cat ./rules_template/common-password > /etc/pam.d/common-password
    #
    echo -e "Setting hash password rules"
    local var1="sha512 shadow nullok rounds=65536 try_first_pass use_authtok"
    sed -i.bak "s/pam_unix.so.*/pam_unix.so $var1/" /etc/pam.d/common-password
    #
    echo -e "Setting password complexity rules : "
    echo -e "rules used : (minlen=12 minclass=3 dcredit=0 ucredit=0 lcredit=0 ocredit=0 maxrepeat=1 difok=3 enforce_for_root dictpath)"
    local var2="minlen=12 minclass=3 dcredit=0 ucredit=0 lcredit=0 ocredit=0 maxrepeat=1 difok=3 enforce_for_root dictpath"
    sed -i.bak "s/pam_pwquality.so.*/pam_pwquality.so $var2/" /etc/pam.d/common-password
    #
    echo -e "Setting block on max retry (for login and ssh) rules"
    local var3="auth required pam_faillock.so deny=3 unlock_time=300"
    echo $var3 >> /etc/pam.d/sshd
    echo $var3 >> /etc/pam.d/login
    echo $var3 >> /etc/pam.d/common-auth
    #
    
    done_pause
}

google_2fa() {
    #
    echo -e "Installing google-authentificator"
    sudo apt-get install libpam-google-authenticator
    echo -e "Setting google authentificator on login and ssh"
    local var1="auth required pam_google_authenticator.so nullok"
    echo $var1 >> /etc/pam.d/lightdm
    echo $var1 >> /etc/pam.d/ssh
    echo -e "Setting your google-auth token :"
    google-authentificator
    done_pause
}

set_sshd(){
    #
    echo -e "Setting ssh server recommended config"
    cat ./rules_template/sshd_config > /etc/ssh/sshd_config
    #
    echo -e "Setting allowed users"
    echo -e "AllowUsers $username" >> /etc/ssh/sshd_config
    #
    while true; do
        read -p "Enter a username (or press Enter to exit): " in

        # Check if the input is empty
        if [ -z "$in" ]; then
            break
        fi

        # Check if the user exists
        if id "$in" &>/dev/null; then
            echo -e "AllowUsers $in" >> /etc/ssh/sshd_config
            echo "User '$in' allowed."
        else
            echo "User '$in' does not exist."
        fi
    done

    echo "Restarting SSH service"
    #restart
    restart_service sshd ssh
    done_pause
}


logconfig_auditd(){
  #
  echo -e "Installing auditd"
  echo ""
  apt install auditd
  #
  echo ""
  echo "Enabling auditing for processes that start prior to auditd"
  echo ""
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub
  #
  echo ""
  echo "Configuring Auditd Rules"
  spinner

  cp templates/audit.rules /etc/audit/rules.d/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/rules.d/audit.rules

  echo " " >> /etc/audit/rules.d/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/rules.d/audit.rules
  echo "-e 2" >>/etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  restart_service auditd.service auditd

  echo "Done"
  done_pause
}

passwd_logindefs(){
    #PASS_MAX_DAYS	90
    #PASS_MIN_DAYS	7
    #PASS_WARN_AGE	7
    var1=90
    var2=7
    var3=7
    read -p "Password Max days (default=90): " var1
    if [ -z "$var1" ];then
    var1=90
    fi
    read -p "Password Min days (default=7): " var2
    if [ -z "$var2" ];then
    var2=7
    fi
    read -p "Password Warn Age (default=7): " var3
    if [ -z "$var3" ];then
    var3=7
    fi
    sed -i.bak "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS	$var1/" /etc/login.defs
    sed -i.bak "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS	$var2/" /etc/login.defs
    sed -i.bak "s/PASS_WARN_AGE.*/PASS_WARN_AGE	$var3/" /etc/login.defs
    done_pause
}

disable_services(){
    # service names
    services=("bluetooth" "avahi-daemon" "cups" "vncserver-x11-serviced" "xrdp" "vsftpd" "nfs-kernel-server" "cups-browsed" "ModemManager")
    echo -e "Disabling the following services : ${services[@]}"
    # 
    for svc in "${services[@]}"; do
        sudo systemctl stop "$svc"
        sudo systemctl disable "$svc"
    done
    #
    echo "Disabling the following net protocols (reason : uncommon protocols) : dccp sctp rds tipc "
    {
    echo "install dccp /bin/true" 
    echo "install sctp /bin/true" 
    echo "install rds /bin/true" 
    echo "install tipc /bin/true" 
    } >> /etc/modprobe.d/myrules.conf

    done_pause
}

rules_iptables(){

    echo -n " Setting Iptables Rules..."

    sh rules_template/iptables.sh
    cp rules_template/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh


}


sysctl_network_param(){

    echo "Setting sysctl kernem parameters : "
    #1
    echo "Set : \"net.ipv4.ip_forward = 0\""   

    sysctl -w net.ipv4.ip_forward=0
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

    #2
    echo "Set : \"net.ipv4.conf.all.send_redirects = 0\""  
    echo "Set : \"net.ipv4.conf.default.send_redirects = 0\""  

    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

    #3
    echo "Set : \"net.ipv4.conf.all.accept_redirects = 0\"" 
    echo "Set : \"net.ipv4.conf.default.accept_redirects = 0\""

    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    
    #4
    echo "Set : \"net.ipv4.icmp_ignore_bogus_error_responses = 1\""

    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

    # Apply the changes 
    sysctl -p

}


secure_php_apache(){
    #
    echo  "Installing and Configuring PHP"
    apt install -y apache2
    apt install -y php php-cli php-pear php-mysql python-mysqldb libapache2-mod-php7.2
    #
    echo " Replacing php.ini with recommended parameters"
    cp rules_template/php /etc/php/7.2/apache2/php.ini
    cp rules_template/php /etc/php/7.2/cli/php.ini
    #
    echo " Replacing apache2.conf with recommended parameters"
    cp templates/apache /etc/apache2/apache2.conf
    #
    echo " Restricting Access to Apache Config Files......"
    chmod 750 /etc/apache2/conf* >/dev/null 2>&1
    chmod 511 /usr/sbin/apache2 >/dev/null 2>&1
    chmod 750 /var/log/apache2/ >/dev/null 2>&1
    chmod 640 /etc/apache2/conf-available/* >/dev/null 2>&1
    chmod 640 /etc/apache2/conf-enabled/* >/dev/null 2>&1
    chmod 640 /etc/apache2/apache2.conf >/dev/null 2>&1
    #
    echo " Restarting service apache2"
    service apache2 restart
    done_pause
}

disable_sys_acc(){
    #sys accounts
    SYSTEM_ACCOUNTS=("sync" "halt" "shutdown" "daemon" "bin")
    #get list of all users
    for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do
    if [ $user != "root" ] 
    then 
    usermod -L $user 
    else
        for x in "${SYSTEM_ACCOUNTS[@]}"; do
            if [ "$x" == "$user" ]; then
                usermod -s /usr/sbin/nologin $user 
                break
            fi 
    done
    fi
done



}









check_root() {
if [ $EUID -ne 0 ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
fi
}
update_system(){
   clear
   echo -e "Updating the System..........."
   echo ""
   apt update
   apt upgrade -y
   apt dist-upgrade -y
   echo "Done "
   read -p "Press Enter to continue..." 
}