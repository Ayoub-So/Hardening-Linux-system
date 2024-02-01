#!/bin/bash
#ayoub
# ################################################################ACOUNT##########################################
#*********************************************USER ACCOUNT
#check if only root can access boot dirictory
echo -e "\e[34m____________CHECk IF ONLY ROOT CAN ACCESS BOOT DIRICTORY !!______________\e[0m"
perm=$(ls -l / | grep boot | tr -s ' ' | cut -d ' ' -f1 | cut -c 8-)
if [ $perm != '---' ]
then
	echo -e "\e[31mthe /boot directory has non root access !\e[0m"
else
	echo -e "\e[32m ok only root can access boot dirictory\e[0m"
fi

echo " press enter to continue .."
read
# CHECK FOR ACCOUNT INACTIVE MORE THAN 90 DAYS 
truncate -s 0 login_90
echo -e "\e[34m____________is recommanded to remove users who have not been logged in more than 90  DAYS !!______________\e[0m"
touch ./login_90
touch ./file 
max_days=90 # here you can specify the number of days for inactivity 
lastlog -b $max_days | tr -s ' ' ' ' > ./file
infile=./file
while read -r login _ last_log
do
last_log=$(echo $last_log | tr -s ' ' '_')
if [ $last_log != "logged_in**" ] && [ $last_log != "From_Latest" ]
then
echo "this user with login $login is inactive for more than 90 Days";
echo "$login" >> ./login_90

 fi
done < "$infile"

if [ -s ./login_90 ]
then
        echo -e "\e[31m logins for account inactive accounts for more than 90 DAYS are stored in ./login_90\e[0m";
else
        echo -e "\e[32m No account is inactive for more than 90 DAYS\e[0m";
fi 
rm -rf ./file

echo " press enter to continue .."
read

echo -e "\e[34m____________CHECk IF pam_crack.so module is used for checking password strength !!______________\e[0m"
modu=$(cat /etc/pam.d/common-password | grep pam_cracklib.so)
if [ -n $mod ]
then
echo -e "\e[32mthe pam_cracklib.so module is implimented \e[0"
else
echo "pam_cracklib.so module should used in /etc/pam.d/commom-password"
fi

echo " Press enter to continue .."
read
#**************************************************************Administartion Acounts
echo -e "\e[34m____________CHECk IF SSH session parameters ClientAliveInterval & ClientAliveCountMax !!______________\e[0m"

interval=$(cat /etc/ssh/sshd_config | grep "ClientAliveInterval")
max=$(cat /etc/ssh/sshd_config | grep "ClientAliveCountMax" )
iscommented=$(echo "$interval" | cut -d ' ' -f 1)
iscommented2=$(echo "$max" | cut -d ' ' -f 1)

if [ $iscommented = "#ClientAliveInterval" ]
then
echo -e "please uncomment \e[35mClientAliveInterval\e[0m in /etc/ssh/sshd-config";fi
if [ $iscommented2 = "#ClientAliveCountMax" ]
then
echo -e "please uncomment \e[35mClientAliveCountMax\e[0m etc/ssh/sshd-config";fi
if [ $(echo "$interval" | cut -d ' ' -f 2) -gt 60 ]
then
        echo -e "please the recommanded value for ClientAliveInterval is 60 or less"
fi
if [ $(echo "$max" | cut -d ' ' -f 2) -gt 3 ]
then
echo "please the recommanded vlaue for ClientAliveCountMax is 3 or less"
fi


echo " Press enter to continue .."
read

echo -e "\e[34m____________CHECk IF SSH root login is permitted !!______________\e[0m"
value=$(cat /etc/ssh/sshd_config | grep PermitRootLogin | head -n 1 | cut -d ' ' -f 2)

if [ $value != "no" ]
then
echo -e "\e[31mplease set no for PermitRootLogin directive in /etc/ssh/sshd_config/n Current value is $value\e[0m"
else
echo -e "\e[32mPermitRootLogin is configured safely\e[0m"
fi

################################### SERVICE ACCOUNTS ############################
echo " Press enter to continue .."
read
echo -e "\e[34m____________CHECk IF SERVICE ACCOOUNTS ARE DISABLED !!______________\e[0m"

service_accounts=("www-data" "mysql" "nagios" "sshd" "dnsmasq" "nobady")
is_account_disabled() {
    local account=$1
    # Check if the account has "/sbin/nologin" or "/bin/false" as its shell
    if grep -E "^$account:.*(/sbin/nologin|/bin/false)" /etc/passwd > /dev/null; then
        echo "$account is disabled."
    else
        echo -e "\e[31m$account is enabled or has an interactive shell.\e[0m"
    fi
}

for account in "${service_accounts[@]}";do 

        is_account_disabled $account
done


############################## ACCESS CONTROL ############################
echo " Press enter to continue .."
read
echo -e "\e[34m____________CHECk SYSTEM UMASK !!______________\e[0m"
if [ $(umask) -ne 0077 ]
then
echo -e "please change umask,the current value is $(umask) the recommended value is \e[35m0077\e[0m"
read -p "Do you want to modify umask value for the entire system to 0077 ?(y/n)" ans
if [ $(echo $ans | tr -s ' ' '_') = 'y' ] 2> /dev/null
then
echo "umask 0077" | sudo tee -a /etc/profile
fi
fi

echo " Press enter to continue .."
read
echo -e "\e[34m____________CHECK IF MANDATORY ACCESS CONTROL IS ENABLED !!______________\e[0m"

if systemctl is-active --quiet apparmor; then
    echo -e "\e[32mAppArmor is enabled\e[0m"
    # Check the status of AppArmor
    #aa-status
elif [ -e /etc/selinux/config ]; then
    # Check if SELinux is enabled
    if grep  -q '^SELINUX=enforcing' /etc/selinux/config; then
        echo "SELinux is enabled and enforcing"
    elif grep -q '^SELINUX=permissive' /etc/selinux/config; then
        echo "SELinux is enabled and in permissive mode"
    else
        echo "SELinux is enabled, but its status is unknown"
    fi
else
    echo "Neither AppArmor nor SELinux is enabled"
fi

##########################################  CHECK SUDO CONFIG  ################################
echo " Press enter to continue .."
read
echo -e "\e[34m____________SECURITY CHECK FOR BAD PRACTICES IN SUDO CONFIG  !!______________\e[0m"


if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

echo "Checking for insecure sudo practices..."

# Check if there are any users with UID 0 other than root
root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')
if [ -n "$root_users" ]; then
    echo -e "\e[31mWARNING:\e[0m Users with UID 0 other than root: $root_users"
fi

# Check for users in the sudo group
sudo_group_users=$(getent group sudo | cut -d: -f4)
if [ -n "$sudo_group_users" ]; then
    echo -e "\e[31mWARNING:\e[0m Users in the sudo group: $sudo_group_users"
fi

# Check for sudoers file permissions
sudoers_permissions=$(stat -c %a /etc/sudoers)
if [ "$sudoers_permissions" -ne 440 ]; then
    echo -e "\e[31mWARNING:\e[0m Insecure permissions on /etc/sudoers. It should be 440."
fi

# Check for NOPASSWD in sudoers file
if grep -qE 'NOPASSWD' /etc/sudoers; then
    echo -e "\e[31mWARNING:\e[0m NOPASSWD is configured in /etc/sudoers. Password prompt is recommended for security."
fi

echo "Security check completed."
##########################################  CHECK SUDO CONFIG  ################################
echo " Press enter to continue .."
read
echo -e "\e[34m____________Checking SELinux status...  !!______________\e[0m"


# Check if SELinux is installed
if [ -x "$(command -v getenforce)" ]; then
    selinux_status=$(getenforce)

    if [ "$selinux_status" == "Enforcing" ]; then
        echo "SELinux is already in enforcing mode."
    elif [ "$selinux_status" == "Permissive" ]; then
        echo "\e[31mWARNING:\e[0m SELinux is in permissive mode. Consider setting it to enforcing."
    else
        echo "SELinux is not in enforcing or permissive mode."
    fi
else
    echo "SELinux tools are not installed. Install the 'policycoreutils' package."
fi

# Check if SELinux is enabled in the configuration
if grep -q '^SELINUX=enforcing' /etc/selinux/config; then
    echo "SELinux is set to enforcing in the configuration."
elif grep -q '^SELINUX=permissive' /etc/selinux/config; then
    echo -e "\e[31mWARNING:\e[0m SELinux is set to permissive in the configuration. Consider setting it to enforcing."
else
    echo "SELinux is not configured to be enforcing or permissive in /etc/selinux/config."
fi

echo -e "SELinux hardening check completed."

echo -e "\e[34m_______________check for files with nouser or nogroup ____________\e[0m"
echo "looking for files with nouser or nogroup..."
find / -type f \( -nouser -o -nogroup \) -ls

echo -e "\e[34m_______________check for directories that can be modified by all and without sticky bit____________\e[0m"
touch ./dir_modi_all_without_stickybit
find / -type d \( -perm -0002 -a \! -perm -1000 \) -ls | tee ./dir_modi_all_without_stickybit 
nbr=$(cat ./dir_modi_all_without_stickybit | wc -l)
if [ $nbr -ne 0 ]
then
echo -e "\e[31mWarning :\e[0m you have $nbr directories can be modified by all and without sticky bit"
fi
