#!/bin/bash
##################################################################################################################################
#                                           This script is written by Pierre Gode                                                #
#      This program is open source; you can redistribute it and/or modify it under the terms of the GNU General Public           #
#                     This is an normal bash script and can be executed with sh EX: ( sudo sh ADconnection.sh )                  #
# Generic user setup is: administrator, domain admins, groupnamesudores= groupname=hostname + sudoers on group name in AD groups #
#       Supported OS's: Ubuntu 14-18 + mate,Debian ,Cent OS,Rasbian ,Fedora.Linux Mint and Kali ( autodetect function ) 	 #
#This script is a long series of small updates and not well planned, the script works as expected, but this is not beautiful code #
#           Maybe someday I re-do the script and make it "good code" but overall it has minimal shellcheck issues               #
##################################################################################################################################
#known bugs: Sometimes the script bugs after AD administrator tries to authenticate, temporary solution is running the script again
# a couple of times. if it still is not working see line 24-25
#known bugs: see line 27-37
#known bugs:sometimes domain discovery fails, it can help canceling the script and re-running it, if not verify dns setting on client,
#and on DC.
# see lines 355-371 for more advanced or specific setups of SSSD
#more Distros will be added during 2019
#support added for ubutnu 19.04 2019-11-11

# ~~~~~~~~~~  Environment Setup ~~~~~~~~~~ #
err() {
    echo -e -e "${COL_YELLOW}[$(date +'%Y-%m-%dT%H:%M:%S%z')] ${UNDERLINE}${COL_RED}ERR${COL_RESET}:  $@" >&2
}

# Colors
ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
COL_GREEN=$ESC_SEQ"32;01m"
COL_YELLOW=$ESC_SEQ"33;01m"
COL_BLUE=$ESC_SEQ"34;01m"
COL_MAGENTA=$ESC_SEQ"35;01m"
COL_CYAN=$ESC_SEQ"36;01m"
BG_GREY=$ESC_SEQ"6;01m"
UNDERLINE=$ESC_SEQ"4;01m"

NORMAL=$(printf "\033[m")
MENU=$COL_CYAN
NUMBER=$COL_YELLOW    #
RED_TEXT=$COL_RED     #Red
INTRO_TEXT=$COL_GREEN #Green
END=$COL_RESET        #reset

# ~~~~~~~~~~  Environment Setup ~~~~~~~~~~ #

################################ fix errors # funktion not called ################
fixerrors() {
    #this funktion is not called in the script : to activate, uncomment line 37 #fixerrors
    #This funktion installs additional packages due to known issues with Joining and the join hangs after the admin auth
    sudo add-apt-repository ppa:xtrusia/packagekit-fix
    sudo apt-get update
    sudo apt-get install packagekit
    MENU_FN
}
#fixerrors
#Realmdupdate11

####################### final auth ##################################################################
#this section will do the last part, configure sssd, ssh, login session sam files and sudoers#
fi_auth() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    echo -e "############################"
    echo -e "Configurating files.."
    echo -e "Verifying the setup"
    sudo systemctl enable sssd
    sudo systemctl start sssd
    states="null"
    states1="null"
    grouPs="null"
    therealm="null"
    cauth="null"
    #clear
    read -r -p "${RED_TEXT}Do you wish to enable SSH login.group.allowed${END}${NUMBER}(y/n)?${END}" yn
    case $yn in
    [Yy]*)
        sudo echo -e "Checking if there is any previous configuration"
        if [ -f /etc/ssh/login.group.allowed ] </dev/null >/dev/null 2>&1; then
            echo -e "Files seems already to be modified, skipping..."
        else
            echo -e "NOTICE! /etc/ssh/login.group.allowed will be created. make sure yor local user is in it you you could be banned from login"
            echo -e "auth required pam_listfile.so onerr=fail item=group sense=allow file=/etc/ssh/login.group.allowed" | sudo tee -a /etc/pam.d/common-auth
            sudo touch /etc/ssh/login.group.allowed
            admins=$(grep home /etc/passwd | grep bash | cut -d ':' -f1)
            echo -e ""
            echo -e ""
            read -r -p "Is your current administrator = '$admins' ? (y/n)?" yn
            case $yn in
            [Yy]*) sudo echo -e "$admins" | sudo tee -a /etc/ssh/login.group.allowed ;;
            [Nn]*)
                echo -e "please type name of current administrator"
                read -r -p MYADMIN
                sudo echo -e "$MYADMIN" | sudo tee -a /etc/ssh/login.group.allowed
                ;;
            *) echo -e "Please answer yes or no." ;;
            esac
            sudo echo -e "$NetBios\\$myhost""sudoers""" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "$NetBios\\domain^admins" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "root" | sudo tee -a /etc/ssh/login.group.allowed
            echo -e "enabled SSH-allow"
        fi
        ;;
    [Nn]*)
        echo -e "Disabled SSH login.group.allowed"
        states1="12"
        ;;
    *) echo -e "Please answer yes or no." ;;
    esac
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------------"
    echo -e ""
    read -r -p "${RED_TEXT}Do you wish to give users on this machine sudo rights?${END}${NUMBER}(y/n)?${END}" yn
    case $yn in
    [Yy]*)
        sudo echo -e "Checking if there is any previous configuration"
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e ""
            echo -e "The Sudoers file seems already to be modified, skipping..."
            echo -e ""
        else
            read -r -p "${RED_TEXT}Do you wish to DISABLE password prompt for users in terminal?${END}${NUMBER}(y/n)?${END}" yn
            case $yn in
            [Yy]*)
                sudo echo -e "administrator ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;

            [Nn]*)
                sudo echo -e "administrator ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;
            *) echo -e "Please answer yes or no." ;;
            esac
        fi
        ;;
    [Nn]*)
        sudo echo -e "administrator ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
        echo -e "Disabled sudo rights for users on this machine"
        echo -e ""
        echo -e ""
        states="12"
        ;;
    *)
        echo -e "Please answer yes or no."
        ;;
    esac
    homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
    if [ "$homedir" = "0022" ]; then
        echo -e "pam_mkhomedir.so configured"
        sleep 1
    else
        echo -e "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" | sudo tee -a /etc/pam.d/common-session
    fi
    Arm=$(sudo hostnamectl | grep Architecture | awk '{print $2}')
    if [ "$Arm" = "arm" ]; then
        sudo sh -c "echo -e 'greeter-show-manual-login=true' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu-mate.conf"
        sudo sh -c "echo -e 'allow-guest=false' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu-mate.conf"
    else
        logintrue=$(grep -i -m1 "login" /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf)
        if [ -f /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf ]; then
            if [ "$logintrue" = "greeter-show-manual-login=true" ]; then
                echo -e "50-ubuntu.conf is already configured.. skipping"
            else
                sudo sh -c "echo -e 'greeter-show-manual-login=true' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
                sudo sh -c "echo -e 'allow-guest=false' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
            fi
        else
            echo -e "No lightdm to configure"
        fi
    fi
    #clear
    sed -i -e 's/fallback_homedir = \/home\/%u@%d/#fallback_homedir = \/home\/%u@%d/g' /etc/sssd/sssd.conf
    sed -i -e 's/use_fully_qualified_names = True/use_fully_qualified_names = False/g' /etc/sssd/sssd.conf
    sed -i -e 's/access_provider = ad/access_provider = simple/g' /etc/sssd/sssd.conf
    sed -i -e 's/sudoers:        files sss/sudoers:        files/g' /etc/nsswitch.conf
    echo -e "override_homedir = /home/%d/%u" | sudo tee -a /etc/sssd/sssd.conf
    sudo sudo grep -i override /etc/sssd/sssd.conf
    sudo echo -e "[nss]
    filter_groups = root
    filter_users = root
    reconnection_retries = 3
    entry_cache_timeout = 600
    #entry_cache_user_timeout = 5400
    #entry_cache_group_timeout = 5400
    #cache_credentials = TRUE
    ### Added to help with group mapping
    ###ldap_use_tokengroups = False
    #ldap_schema = rfc2307bis
    #ldap_schema = rfc2307
    #ldap_schema = IPA
    #ldap_schema = AD
    #ldap_search_base = DC=$NetBios,DC=$coms
    #ldap_group_member = uniquemember
    #ad_enable_gc = False
    entry_cache_nowait_percentage = 75" | sudo tee -a /etc/sssd/sssd.conf
    #clear

    ################################# Check #######################################
    if ! sudo service sssd restart; then
        echo -e "sssd config.. ${RED_TEXT}FAIL${END}"
    else
        echo -e "sssd config.. ${INTRO_TEXT}OK${END}"
    fi
    if ! realm discover </dev/null >/dev/null 2>&1; then
        echo -e "Realm not installed"
    else
        therealm=$(realm discover "$DOMAIN" | grep -i configured: | cut -d ':' -f2 | sed -e 's/^[[:space:]]*//')
        if [ "$therealm" = "no" ]; then
            echo -e "Realm configured?.. ${RED_TEXT}FAIL${END}"
        else
            echo -e "Realm configured?.. ${INTRO_TEXT}OK${END}"
        fi
    fi
    if [ $states = 12 ]; then
        echo -e "Sudoers not configured... skipping"
    else
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking sudoers file..  ${INTRO_TEXT}OK${END}"
        else
            echo -e "Checking sudoers file..  ${RED_TEXT}FAIL${END}"
        fi
        grouPs=$(grep -i "$myhost" /etc/sudoers.d/sudoers | cut -d '%' -f2 | awk '{print $1}' | head -1)
        if [ "$grouPs" = "$myhost""sudoers" ]; then
            echo -e "Checking sudoers groups.. ${INTRO_TEXT}OK${END}"
        else
            echo -e "Checking sudoers groups.. ${RED_TEXT}FAIL${END}"
        fi
        homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
        if [ "$homedir" = "0022" ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking PAM session configuration.. ${INTRO_TEXT}OK${END}"
        else
            echo -e "Checking PAM session configuration.. ${RED_TEXT}FAIL${END}"
        fi
        if [ $states1 = 12 ]; then
            echo -e "Disabled SSH login.group.allowed"
        else
            cauth=$(grep required /etc/pam.d/common-auth | grep onerr | grep allow | cut -d '=' -f4 | awk '{print $1}')
            if [ "$cauth" = "allow" ] </dev/null >/dev/null 2>&1; then
                echo -e "Checking PAM auth configuration.. ${INTRO_TEXT}OK${END}"
            else
                echo -e "Checking PAM auth configuration.. ${RED_TEXT}FAIL${END}"
            fi
        fi
        #realm discover $DOMAIN
        if ! realm discover; then
            echo -e "realm not found"
        else
            if [ "$therealm" = "no" ]; then
                echo -e "${RED_TEXT}Join has Failed${END}"
            else
                lastverify=$(realm discover "$DOMAIN" | grep -m 1 "$DOMAIN")
                echo -e ""
                echo -e "${INTRO_TEXT}joined to $lastverify${END}"
                echo -e ""
                notify-send ADconnection "Joined $lastverify "
            fi
        fi
        echo -e "${INTRO_TEXT}Please reboot your machine and wait 3 min for Active Directory to sync before login${INTRO_TEXT}"
        exit
    fi
    echo -e "${INTRO_TEXT}Please reboot your machine and wait 3 min for Active Directory to sync before login${INTRO_TEXT}"
    exit
}

fi_auth_new() {
    echo -e "############################"
    echo -e "Configuring files.."
    echo -e "Verifying the setup"
    sudo systemctl enable sssd
    sudo systemctl start sssd
    states="null"
    states1="null"
    grouPs="null"
    therealm="null"
    cauth="null"
    #clear
    read -r -p "${RED_TEXT}Do you wish to enable SSH login.group.allowed${END}${NUMBER}(y/n)?${END}" yn
    case $yn in
    [Yy]*)
        echo -e "Checking if there is any previous configuration"
        if [ -f /etc/ssh/login.group.allowed ] </dev/null >/dev/null 2>&1; then
            echo -e "Files seems already to be modified, skipping..."
        else
            echo -e "NOTICE! /etc/ssh/login.group.allowed will be created. Make sure your local user is in it or you could be banned from login."
            echo -e "auth required pam_listfile.so onerr=fail item=group sense=allow file=/etc/ssh/login.group.allowed" | sudo tee -a /etc/pam.d/common-auth
            sudo touch /etc/ssh/login.group.allowed
            admins=$(grep home /etc/passwd | grep bash | cut -d ':' -f1)
            echo -e ""
            echo -e ""
            if [ ! -z "$admins" ]; then
                read -r -p "Is your current administrator = $admins ? (y/n)?" yn_a
                case $yn_a in
                [Yy]*) sudo echo -e "$admins" | sudo tee -a /etc/ssh/login.group.allowed ;;
                [Nn]*)
                    echo -e "Please type name of current administrator"
                    read -r -p MYADMIN
                    sudo echo -e "$MYADMIN" | sudo tee -a /etc/ssh/login.group.allowed
                    ;;
                *) echo -e "Please answer yes or no." ;;
                esac
            else
                echo -e "Please type name of current administrator"
                read -r -p MYADMIN
                sudo echo -e "$MYADMIN" | sudo tee -a /etc/ssh/login.group.allowed
            fi
            sudo echo -e "$Mysrvgroup" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "$NetBios\\$myhost""sudoers""" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "$NetBios\\domain^admins" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "root" | sudo tee -a /etc/ssh/login.group.allowed
            echo -e "enabled SSH-allow"
        fi
        ;;
    [Nn]*)
        echo -e "Disabled SSH login.group.allowed"
        states1="12"
        ;;
    *) echo -e "Please answer yes or no." ;;
    esac
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------------"
    echo -e ""
    read -r -p "${RED_TEXT}Do you wish to give users on this machine sudo rights?${END}${NUMBER}(y/n)?${END}" yn
    case $yn in
    [Yy]*)
        echo -e "Checking if there is any previous configuration"
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e ""
            echo -e "Sudoers file seems already to be modified, skipping..."
            echo -e ""
        else
            read -r -p "${RED_TEXT}Do you wish to DISABLE password prompt for users in terminal?${END}${NUMBER}(y/n)?${END}" yn
            case $yn in
            [Yy]*)
                sudo echo -e "administrator ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$Mysrvgroup""sudoers ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%domain\ users ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;

            [Nn]*)
                sudo echo -e "administrator ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$Mysrvgroup""sudoers ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%domain\ users ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;
            *) echo -e "Please answer yes or no." ;;
            esac
        fi
        ;;
    [Nn]*)
        echo -e "Disabled sudo rights for users on this machine"
        echo -e ""
        echo -e ""
        states="12"
        ;;
    *) echo -e 'Please answer yes or no.' ;;
    esac
    homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
    if [ "$homedir" = "0022" ]; then
        echo -e "pam_mkhomedir.so configured"
        sleep 1
    else
        echo -e "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" | sudo tee -a /etc/pam.d/common-session
    fi
    Arch=$(sudo hostnamectl | grep Architecture | awk '{print $2}')
    if [ "$Arch" = "arm" ]; then
        sudo sh -c "echo -e 'greeter-show-manual-login=true' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu-mate.conf"
        sudo sh -c "echo -e 'allow-guest=false' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu-mate.conf"
    else
        logintrue=$(grep -i -m1 "login" /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf)
        if [ -f /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf ]; then
            if [ "$logintrue" = "greeter-show-manual-login=true" ]; then
                echo -e "50-ubuntu.conf is already configured.. skipping"
            else
                sudo sh -c "echo -e 'greeter-show-manual-login=true' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
                sudo sh -c "echo -e 'allow-guest=false' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
            fi
        else
            echo -e "No lightdm to configure"
        fi
    fi

    ################################# Check #######################################
    if ! realm discover $DOMAIN; then
        echo -e "Realm not found"
    else
        therealm=$(realm list | grep -i realm-name | awk '{print $2}')
        if [ "$therealm" = "no" ] || [ -z "$therealm" ]; then
            echo -e Realm configured?.. "${RED_TEXT}FAIL${END}"
        else
            echo -e Realm configured?.. "${INTRO_TEXT}OK${END}"
        fi
    fi
    if [ $states = 12 ]; then
        echo -e "Sudoers not configured... skipping check"
    else
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e Checking sudoers file.. "${INTRO_TEXT}OK${END}"
        else
            echo -e checking sudoers file.. "${RED_TEXT}FAIL not configured${END}"
        fi
    fi
    grouPs=$(grep -i "$myhost" /etc/sudoers.d/sudoers | cut -d '%' -f2 | awk '{print $1}' | head -1)
    if [ "$grouPs" = "$myhost""sudoers" ]; then
        echo -e "Checking sudoers users.. ${INTRO_TEXT}OK${END}"
    else
        echo -e "Checking sudoers users.. ${RED_TEXT}FAIL${END}"
    fi
    homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
    if [ "$homedir" = "0022" ] </dev/null >/dev/null 2>&1; then
        echo -e "Checking PAM configuration.. ${INTRO_TEXT}OK${END}"
    else
        echo -e "Checking PAM configuration.. ${RED_TEXT}FAIL${END}"
    fi
    cauth=$(grep required /etc/pam.d/common-auth | grep onerr | grep allow | cut -d '=' -f4 | cut -d 'f' -f1)
    if [ "$cauth" = "allow" ] </dev/null >/dev/null 2>&1; then
        echo -e "Checking PAM auth configuration..${INTRO_TEXT}OK${END}"
    else
        echo -e "Checking PAM auth configuration..${RED_TEXT}SSH security not configured${END}"
    fi

    #sudo sed -Ei "s/fallback_homedir = \/home\/%u@%d/#&/g" /etc/sssd/sssd.conf
    #sudo sed -Ei "s/(use_fully_qualified_names =) True/\1 False/g" /etc/sssd/sssd.conf
    #sudo sed -Ei "s/(access_provider =) ad/\1 simple/g" /etc/sssd/sssd.conf
    sudo sed -Ei "s/(sudoers:)\s*(files) (sss)/\1        files/g" /etc/nsswitch.conf
    sudo echo -e "override_homedir = /home/%d/%u" | sudo tee -a /etc/sssd/sssd.conf
    sudo grep -i override /etc/sssd/sssd.conf
    #    sudo echo -e "[nss]
    #filter_groups = root
    #filter_users = root
    #reconnection_retries = 3" | sudo tee -a /etc/sssd/sssd.conf
    sudo service sssd restart
    realm discover -v "$DOMAIN"
    if ! realm discover $DOMAIN; then
        echo -e "Realm not found"
    else
        if [ "$therealm" = "no" ]; then
            echo -e "${RED_TEXT}Join has Failed${END}"
        else
            lastverify=$(realm discover "$DOMAIN" | grep -m 1 "$DOMAIN")
            echo -e ""
            echo -e "${INTRO_TEXT}joined to $lastverify${END}"
            echo -e ""
            #notify-send ADconnection "Joined $lastverify "
        fi
        echo -e "${INTRO_TEXT}Please reboot your machine and wait 3 min for Active Directory to sync before login${END}"
        exit
    fi
    echo -e "${INTRO_TEXT}Please reboot your machine and wait 3 min for Active Directory to sync before login${END}"
    exit
}

####################### final auth yum ##################################################################
#this section will do the last part, configure sssd, sam files and sudoers# same as final auth
#but without colors#
fi_auth_yum() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    sudo echo -e "############################"
    sudo echo -e "Configurating files.."
    sudo echo -e "Verifying the setup"
    sudo systemctl enable sssd
    sudo systemctl start sssd
    states="null"
    states1="null"
    grouPs="null"
    therealm="null"
    cauth="null"
    #clear
    read -r -p 'Do you wish to enable SSH login.group.allowed (y/n)?' yn
    case $yn in
    [Yy]*)
        sudo echo -e "Checking if there is any previous configuration"
        if [ -f /etc/ssh/login.group.allowed ] </dev/null >/dev/null 2>&1; then
            echo -e "Files seems already to be modified, skipping..."
        else
            echo -e "NOTICE! /etc/ssh/login.group.allowed will be created. make sure yor local user is in it you you could be banned from login"
            echo -e "auth required pam_listfile.so onerr=fail item=group sense=allow file=/etc/ssh/login.group.allowed" | sudo tee -a /etc/pam.d/sshd
            sudo touch /etc/ssh/login.group.allowed
            admins=$(grep home /etc/passwd | grep bash | cut -d ':' -f1)
            echo -e ""
            echo -e ""
            read -r -p "Is your current administrator = $admins ? (y/n)?" yn
            case $yn in
            [Yy]*) sudo echo -e "$admins" | sudo tee -a /etc/ssh/login.group.allowed ;;
            [Nn]*)
                echo -e "please type name of current administrator"
                read -r -p MYADMIN
                sudo echo -e "$MYADMIN" | sudo tee -a /etc/ssh/login.group.allowed
                ;;
            *) echo -e "Please answer yes or no." ;;
            esac
            sudo echo -e "$myhost""sudoers" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "domain^admins" | sudo tee -a /etc/ssh/login.group.allowed
            sudo echo -e "root" | sudo tee -a /etc/ssh/login.group.allowed
            echo -e "enabled SSH-allow"
        fi
        ;;
    [Nn]*)
        echo -e "Disabled SSH login.group.allowed"
        states1="12"
        ;;
    *) echo -e "Please answer yes or no." ;;
    esac
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------------"
    echo -e ""
    read -r -p 'Do you wish to give users on this machine sudo rights?(y/n)?' yn
    case $yn in
    [Yy]*)
        sudo echo -e "Checking if there is any previous configuration"
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e ""
            echo -e "The Sudoers file seems already to be modified, skipping..."
            echo -e ""
        else
            read -r -p 'Do you wish to DISABLE password promt for users in terminal? (y/n)?' yn
            case $yn in
            [Yy]*)
                sudo echo -e "administrator ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;

            [Nn]*)
                sudo echo -e "administrator ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%$myhost""sudoers ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/sudoers
                sudo echo -e "%DOMAIN\ admins ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.d/domain_admins
                #sudo realm permit --groups "$myhost""sudoers"
                ;;
            *) echo -e "Please answer yes or no." ;;
            esac
        fi
        ;;
    [Nn]*)
        echo -e "Disabled sudo rights for users on this machine"
        echo -e ""
        echo -e ""
        states="12"
        ;;
    *) echo -e 'Please answer yes or no.' ;;
    esac
    homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
    if [ "$homedir" = "0022" ]; then
        echo -e "pam_mkhomedir.so configured"
        sleep 1
    else
        echo -e "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" | sudo tee -a /etc/pam.d/common-session
    fi
    logintrue=$(grep -i -m1 "login" /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf)
    if [ -f /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf ]; then
        if [ "$logintrue" = "greeter-show-manual-login=true" ]; then
            echo -e "50-ubuntu.conf is already configured.. skipping"
        else
            sudo sh -c "echo -e 'greeter-show-manual-login=true' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
            sudo sh -c "echo -e 'allow-guest=false' | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
        fi
    else
        echo -e "No lightdm to configure"
    fi
    coms=$(echo -e "$DOMAIN" | cut -d '.' -f2)
    #clear
    sed -i -e 's/fallback_homedir = \/home\/%u@%d/#fallback_homedir = \/home\/%u@%d/g' /etc/sssd/sssd.conf
    sed -i -e 's/use_fully_qualified_names = True/use_fully_qualified_names = False/g' /etc/sssd/sssd.conf
    sed -i -e 's/access_provider = ad/access_provider = simple/g' /etc/sssd/sssd.conf
    sed -i -e 's/sudoers:        files sss/sudoers:        files/g' /etc/nsswitch.conf
    echo -e "override_homedir = /home/%d/%u" | sudo tee -a /etc/sssd/sssd.conf
    sudo grep -i override /etc/sssd/sssd.conf
    sudo echo -e "[nss]
    filter_groups = root
    filter_users = root
    reconnection_retries = 3
    entry_cache_timeout = 600
    #entry_cache_user_timeout = 5400
    #entry_cache_group_timeout = 5400
    #cache_credentials = TRUE
    ### Added to help with group mapping
    ###ldap_use_tokengroups = False
    #ldap_schema = rfc2307bis
    #ldap_schema = rfc2307
    #ldap_schema = IPA
    #ldap_schema = AD
    #ldap_search_base = DC=$NetBios,DC=$coms
    #ldap_group_member = uniquemember
    #ad_enable_gc = False
    entry_cache_nowait_percentage = 75" | sudo tee -a /etc/sssd/sssd.conf

    ####################### Check #########################
    if ! sudo service sssd restart; then
        echo -e "SSSD failed relading, please see journalctl -xe"
    fi
    if ! realm discover; then
        echo -e "no realm found"
    else
        therealm=$(realm discover "$DOMAIN" | grep -i configured: | cut -d ':' -f2 | sed -e 's/^[[:space:]]*//')
        if [ "$therealm" = "no" ]; then
            echo -e "Realm configured?.. FAIL"
        else
            echo -e "Realm configured?.. OK"
        fi
    fi
    if [ "$states" = "12" ]; then
        echo -e "Sudoers not configured... skipping"
    else
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking sudoers file.. OK"
        else
            echo -e "Checking sudoers file.. FAIL"
        fi
        grouPs=$(grep -i "$myhost" /etc/sudoers.d/sudoers | cut -d '%' -f2 | awk '{print $1}' | head -1)
        if [ "$grouPs" = "$myhost""sudoers" ]; then
            echo -e "Checking sudoers user groups.. OK"
        else
            echo -e "Checking sudoers user groups.. FAIL"
        fi
        homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
        if [ "$homedir" = "0022" ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking PAM configuration.. OK"
        else
            echo -e "Checking PAM configuration.. FAIL"
        fi
        if [ "$states1" = "12" ]; then
            echo -e "Disabled SSH login.group.allowed"
        else
            cauth=$(grep required /etc/pam.d/sshd | grep onerr | grep allow | cut -d '=' -f4 | awk '{print $1}')
            if [ "$cauth" = "allow" ] </dev/null >/dev/null 2>&1; then
                echo -e "Checking PAM auth configuration.. OK"
            else
                echo -e "Checking PAM auth configuration.. FAIL"
            fi
        fi
        #realm discover $DOMAIN
        if ! realm discover; then
            echo -e "realm not found"
        else
            if [ "$therealm" = "no" ]; then
                echo -e "Join has Failed"
            else
                lastverify=$(realm discover "$DOMAIN" | grep -m 1 "$DOMAIN")
                echo -e ""
                echo -e "joined to $lastverify"
                echo -e ""
                notify-send ADconnection "Joined $lastverify"
            fi
        fi
        echo -e "Please reboot your machine and wait 3 min for Active Directory to sync before login"
        exit
    fi
    echo -e "Please reboot your machine and wait 3 min for Active Directory to sync before login"
    exit
}

####################### Setup for Ubuntu 14,16 and 17 clients #######################################
#Runs ADjoin in debug mode. meaning it opens terminals following logs
linuxclientdebug() {
    desktop=$(sudo apt list --installed | grep -i desktop | grep -i ubuntu | cut -d '-' -f1 | grep -i desktop | head -1 | awk '{print$1}')
    gnome-terminal --geometry=130x20 -e "bash -c \"journalctl -fxe; exec bash\""
    gnome-terminal --geometry=130x20 -e "bash -c \"journalctl -fxe | grep -i -e closed -e Successfully -e 'Preauthentication failed' -e 'authenticate' -e 'Failed to join the domain'; exec bash\""
    linuxclient
}

################################## Join for linux clients ##########################################
linuxclient() {
    TheOS=$(hostnamectl | grep -i Operating | awk '{print $3}') </dev/null >/dev/null 2>&1
    MintOS=$(hostnamectl | grep -i Operating | awk '{print $4}') </dev/null >/dev/null 2>&1
    rasp=$(lsb_release -a | grep -i Distributor | awk '{print $3}') </dev/null >/dev/null 2>&1
    kalilinux=$(lsb_release -a | grep -i Distributor | awk '{print $3}') </dev/null >/dev/null 2>&1

    #### OS detection ####
    case $TheOS in
    Fedora)
        echo -e "${INTRO_TEXT}Fedora detected${END}"
        Fedora_fn
        ;;
    CentOS)
        echo -e "${INTRO_TEXT}Cent OS detected${END}"
        CentOS
        ;;
    Debian)
        echo -e "${INTRO_TEXT}Debian detected${END}"
        debianclient
        ;;
    Ubuntu)
        echo -e "${INTRO_TEXT}Ubuntu detected${END}"
        echo -e ""
        echo -e "Checking if it is a Desktop or server"
        desktop=$(sudo apt list --installed | grep -i desktop | grep -i ubuntu | cut -d '-' -f1 | grep -i desktop | head -1 | awk '{print$1}')
        if [ "$desktop" = "desktop" ] || [ -n "$XDG_CURRENT_DESKTOP" ] || [ -n "$XDG_DATA_DIRS" ]; then ### </dev/null >/dev/null 2>&1
            echo -e "Ubuntu Desktop environment detected"
            [[ -n $XDG_CURRENT_DESKTOP ]] && printf 'Desktop: %s\n' "$XDG_CURRENT_DESKTOP"
            [[ -n $GDMSESSION ]] && printf 'Session: %s\n' "$GDMSESSION"
            ubuntuDesktop
        else
            echo -e " This seems to be a server, switching to server mode"
            ubuntuServer
        fi
        ;;
    *) ## Check for Raspbian/Kali/Mint until unknown.
        case $rasp in
        Raspbian)
            echo -e "${INTRO_TEXT}Detecting Raspberry Pi${END}"
            raspberry
            ;;
        *)
            case $kalilinux in
            Kali)
                echo -e "${INTRO_TEXT}Detecting Kali linux${END}"
                kalijoin
                ;;
            *)
                case $MintOS in
                Mint)
                    echo -e "${INTRO_TEXT}Detecting Linux Mint${END}"
                    LinuxMint
                    ;;
                *) ## End of checks, Incompatible system.
                    echo -e "${RED_TEXT}No compatible System found${END}"
                    echo -e "Exiting..."
                    exit
                    ;;
                esac
                ;;
            esac
            ;;
        esac ;;
    esac
    #### OS detection ####  ----OLD
    #if [ "$TheOS" = "Fedora" ] </dev/null >/dev/null 2>&1; then
    #    echo -e "Fedora detected"
    #    Fedora_fn
    #else
    #if [ "$TheOS" = "CentOS" ] </dev/null >/dev/null 2>&1; then
    #        echo -e "Cent OS detected"
    #        CentOS
    #else
    #if [ "$TheOS" = "Debian" ] </dev/null >/dev/null 2>&1; then
    #        echo -e "Debian detected"
    #        debianclient
    #else
    #if [ "$TheOS" = "Ubuntu" ] </dev/null >/dev/null 2>&1; then
    #            echo -e "Ubuntu detected"
    #            echo -e ""
    #            echo -e "Checking if it is a Desktop or server"
    #            if [ -n "$XDG_CURRENT_DESKTOP" ]; then
    #            desktop=$XDG_CURRENT_DESKTOP
    #            else
    #                desktop=$(echo -e "$XDG_DATA_DIRS" | sed 's/.*\(xfce\|kde\|gnome\).*/\1/')
    #
    #
    #            fi
    #            desktop=${desktop,,} ## Convert to lowercase
    #            if [[ -z $desktop ]]; then
    #                echo -e Var is Zero length
    #            else
    #                echo -e Var is not Zero length, $desktop
    #                desktop=$(sudo apt list --installed | grep -i desktop | grep -i ubuntu | cut -d '-' -f1 | grep -i desktop | head -1 | awk '{print$1}') </dev/null >/dev/null 2>&1
    #                if [ "$desktop" = "desktop" ] </dev/null >/dev/null 2>&1; then
    #                    echo -e "Ubuntu Desktop environment detected"
    #                    #UbuntU
    #                fi
    #                else
    #                echo -e " this seems to be a server, swithching to server mode"
    #                #ubuntuserver14
    #            fi
    #else
    #if [ "$rasp" = "Raspbian" ] </dev/null >/dev/null 2>&1; then
    #                echo -e "${INTRO_TEXT}Detecting Raspberry Pi${END}"
    #                raspberry
    #else
    #if [ "$kalilinux" = "Kali" ] </dev/null >/dev/null 2>&1; then
    #                    echo -e "${INTRO_TEXT}Detecting Kali linux${END}"
    #                    kalijoin
    #else
    #if [ "$MintOS" = Mint ]; then
    #                        echo -e "Detecting Linux Mint"
    #                        LinuxMint
    #else
    #echo -e "No compatible System found"
    #                        exit
    #                    fi
    #                fi
    #            fi
    #        fi
    #    fi
    #fi
    #fi
}

################################ Ubuntu 14-18 ###########################################
ubuntuDesktop() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    #clear
    sudo echo -e "${NUMBER}Installing packages, do not abort!.......${END}"
    if ! sudo apt-get -qq install realmd adcli sssd ntp -y && sudo apt-get -qq install -f -y; then
        echo -e "${RED_TEXT}Failed installing packages, please resolve dpkg and try again ${END}"
        exit 1
    fi
    #clear
    if ! sudo dpkg -l | grep realmd; then
        #clear
        sudo echo -e "${RED_TEXT}Installing packages failed.. please check connection ,dpkg and apt-get update then try again.${END}"
    else
        #clear
        sudo echo -e "${INTRO_TEXT}packages installed${END}"
    fi
    echo -e "hostname is $myhost"
    echo -e "Looking for Realms.. please wait"
    DOMAIN=$(realm discover | grep -i realm.name | awk '{print $2}')
    if ! ping -c 2 "$DOMAIN" </dev/null >/dev/null 2>&1; then
        #clear
        echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below... ${END}"
        echo -e "Please enter the domain you wish to join:"
        read -r DOMAIN
    else
        #clear
        echo -e "${NUMBER}I searched for an available domain and found ${MENU}>>> $DOMAIN  <<<${END}${END}"
        read -r -p "Do you wish to use it (y/n)?" yn
        case $yn in
        [Yy]*) echo -e "" ;;

        [Nn]*)
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
            ;;
        *) echo -e 'Please answer yes or no.' ;;
        esac
    fi
    NetBios=$(echo -e "$DOMAIN" | cut -d '.' -f1)
    #clear
    var=$(lsb_release -a | grep -i release | awk '{print $2}' | cut -d '.' -f1)
    if [ "$var" -eq "14" ]; then
        echo -e "Installing additional dependencies"
        sudo apt-get -qq install -y realmd sssd sssd-tools samba-common krb5-user
        sudo apt-get -qq install -f -y
        #clear
        echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
        sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
        echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
        echo -e ""
        echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
        echo -e "${INTRO_TEXT}Please type Admin user:${END}"
        read -r ADMIN
        if ! sudo realm join -v -U "$ADMIN" "$DOMAIN" --install=/; then
            echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
            exit
        fi
    else
        if [ "$var" -eq "16" ]; then
            echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
            #clear
            sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
            echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
            echo -e ""
            echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
            echo -e "${INTRO_TEXT}Please type Admin user:${END}"
            read -r ADMIN
            if ! sudo realm join --verbose --user="$ADMIN" "$DOMAIN"; then
                echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
                exit
            fi
        else
            if [ "$var" -eq "17" ] || [ "$var" -eq "18" ] || [ "$var" -eq "19" ]; then
                echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
                sleep 1
                #clear
                if [ "$var" -eq "19" ]; then
                    echo -e""
                    echo -e "fixing krb5.keytab: Bad encryption type for ubuntu 19.10"
                    echo -e ""
                    sudo add-apt-repository ppa:aroth/ppa
                    sudo apt-get update
                    sudo apt-get -y --only-upgrade install adcli
                    echo -e ""
                    echo -e "If the script fails please run sudo apt-get upgrade to update adcli and run the script again"
                    echo -e ""
                fi
                sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
                echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
                echo -e ""
                echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
                echo -e "${INTRO_TEXT}Please type Admin user:${END}"
                read -r ADMIN
                if ! sudo realm join --verbose --user="$ADMIN" "$DOMAIN" --install=/; then
                    echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
                    exit
                fi
            else
                #clear
                sudo echo -e "${RED_TEXT}I am having issuers to detect your Ubuntu version${END}"
                exit
            fi
        fi
    fi
    fi_auth
}

####################### Setup for Ubuntu server #######################################
ubuntuServer() {
    export HOSTNAME
    set -x
    myhost=$(hostname | cut -d '.' -f1)
    dhcpDomain=$(hostname -d)

    echo -e "${RED_TEXT}Installing packages do not abort!.......${END}"
    sudo apt-get update -qq
    sudo apt-get install -y \
    krb5-user krb5-config \
    sssd sssd-tools libpam-sss \
    libnss-sss libsss-sudo \
    libsasl2-modules-gssapi-mit \
    realmd adcli policykit-1
    #clear
    if ! sudo dpkg -l | grep realmd; then
        #clear
        err "Installing packages failed.. please check connection and dpkg and try again."
        exit
    else
        #clear
        echo -e "${INTRO_TEXT}packages installed${END}"
    fi
    sleep 1
    if [ -z $DOMAIN ]; then
        DOMAIN=$(realm discover $dhcpDomain | grep -i realm-name | awk '{print $2}')
    fi
    if ! ping -c 1 "$DOMAIN"; then
        DOMAIN=$(realm discover -v $(cat /etc/resolv.conf | grep -i ^search | sed -Er "s/search |$dhcpDomain//g") | grep -i realm-name | awk '{print $2}')
        if ! ping -c 1 "$DOMAIN"; then
            #clear
            echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below... ${END}"
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
        else
            #clear
            echo -e "${NUMBER}I searched for an available domain and found ${MENU}>>> ${DOMAIN}  <<<${END}${END}"
            read -r -p "Do you wish to use it (y/n)?" yn
            case $yn in
            [Yy]*) echo -e "${INTRO_TEXT}Please log in with domain admin access to ${DOMAIN} to connect${END}" ;;

            [Nn]*)
                echo -e "Please enter the domain you wish to join:"
                read -r DOMAIN
                ;;
            *) echo -e 'Please answer [y]es or [n]o.' ;;
            esac
        fi
    fi
    domainUpper="${DOMAIN^^}"
    domainLower="${DOMAIN,,}"
    echo -e "${INTRO_TEXT}Realm: ${DOMAIN}${END}"
    echo -e "${NORMAL}${NORMAL}"
    echo -e "${INTRO_TEXT}Please type a Domain Admin user:${END}"
    read -r DomainADMIN
    #if ! sudo realm join -v -U "$DomainADMIN" "$DOMAIN" --install=/; then
    #    echo -e "${RED_TEXT}AD join failed. Please check your errors with ${INTRO_TEXT}journalctl -xe${END}"
    #    exit
    #fi
    read -p "Enter the desired full subdomain for this client:" clientSubDomain
    if ! grep -i $DOMAIN /etc/hosts; then #fix hosts file to have domain before joining
        if grep $(hostname -s) /etc/hosts; then
            grep $(hostname -s) /etc/hosts
            echo -e "Modifying..."
            sed -Ei "s/($(hostname -s))/\1.${domainLower} \1/g" /etc/hosts
            grep $(hostname -s) /etc/hosts
        elif ! grep "127.0.1.1" /etc/hosts; then
            echo -e "127.0.1.1         $(hostname -s).${clientSubDomain:-${domainLower}} $(hostname -s)" >>/etc/hosts
            grep "127.0.1.1" /etc/hosts
        fi
    fi
    printf "[global]\n\
workgroup = ${DOMAIN%.*}\n\
realm = ${DOMAIN}\n\
server string = %%h server\n\
security = ads\n\
client signing = yes\n\
client use spnego = yes\n\
kerberos method = secrets and keytab\n\
obey pam restrictions = yes\n\
client min protocol = SMB2\n\
usershare path = \n"
    if [ ! -f /etc/samba/smb.conf ]; then
        printf "${sambaConf}" >/etc/samba/smb.conf
    else
        if [ -s "/etc/samba/smb.conf" ]; then
            #sudo mkdir -p /etc/samba/conf.d
            echo -e "${COL_YELLOW}Existing Samba config found, backing up original before writing new config.${END}"
            sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
            printf "${sambaConf}" >/etc/samba/smb.conf
        fi
    fi

    echo -e "${COL_CYAN}Please type group name in AD for admins${END}"
    echo -e "${COL_YELLOW}Be sure to escape out all whitespaces, if applicable.${END}"
    read -r "Mysrvgroup"
    export Mysrvgroup

    kinit $DomainADMIN
    printf -v sssdConf "[sssd]\n\
services = nss, pam, pac, ssh\n\
config_file_version = 2\n\
domains = ${domainUpper}\n\
\n\
[domain/${domainUpper}]\n\
id_provider = ad\n\
access_provider = ad\n\
auth_provider = ad\n\
chpass_provider = ad\n\
ldap_idmap_autorid_compat = True\n\
enumerate = True\n\
use_fully_qualified_names = False\n\
ad_server = ${domainLower}\n\
ad_hostname = $(hostname -f)\n\
ad_domain = ${domainLower}\n\
dyndns_auth = none\n\
#debug_level = 8\n\
ldap_idmap_range_min = 20000\n\
\n\
[nss]\n\
filter_groups = root\n\
filter_users = root\n\
reconnection_retries = 3\n"

    #    echo -e "[sssd]
    #services = nss, pam, pac, ssh
    #config_file_version = 2
    #domains = ${domainUpper}
    #
    #[domain/${domainUpper}]
    #id_provider = ad
    #access_provider = ad
    #auth_provider = ad
    #chpass_provider = ad
    #ldap_idmap_autorid_compat = True
    #enumerate = True
    #use_fully_qualified_names = False
    #ldap_idmap_range_min = 20000"
    printf "${sssdConf}" >/etc/sssd/sssd.conf

    sudo chmod 0600 /etc/sssd/sssd.conf

    if ! sudo net ads join -k; then
        #if ! sudo realm join -v -U "$DomainADMIN" "$DOMAIN" --install=/; then
        err "AD join failed. Please check your errors with \"journalctl -xe\""
        read -n 1 -s -r -p "Press any key to continue..."
        echo ""
        exit
        #fi
    fi
    fi_auth_new
}

####################################### Kali ############################################
kalijoin() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    export whoami
    whoamis=$(whoami)
    admins=$(grep home /etc/passwd | grep bash | cut -d ':' -f1)
    sudo echo -e "${RED_TEXT}Installing packages do no abort!.......${END}"
    sudo apt-get -qq update
    sudo apt-get -qq install libsss-sudo -y
    sudo apt-get -qq install adcli -y
    sudo apt-get -qq install realmd adcli sssd -y
    sudo apt-get -qq install ntp -y
    sudo apt-get -qq install policykit-1 -y
    sudo mkdir -p /var/lib/samba/private
    sudo apt-get -qq install realmd adcli sssd -y
    sudo apt-get -qq install ntp -y
    sudo apt-get -qq install -f -y
    #clear
    if ! sudo dpkg -l | grep realmd; then
        #clear
        sudo echo -e "${RED_TEXT}Installing packages failed.. please check connection ,dpkg and apt-get update then try again.${END}"
        exit
    else
        #clear
        sudo echo -e "${INTRO_TEXT}packages installed${END}"
    fi
    echo -e "hostname is $myhost"
    DOMAIN=$(realm discover | grep -i realm.name | awk '{print $2}')
    if ! ping -c 2 "$DOMAIN" >/dev/null; then
        #clear
        echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below...${END}"
        echo -e "Please enter the domain you wish to join:"
        read -r DOMAIN
    else
        #clear
        echo -e "${NUMBER}I searched for an available domain and found $DOMAIN ${END}"
        read -r -p "Do you wish to use it (y/n)?" yn
        case $yn in
        [Yy]*) echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}" ;;

        [Nn]*)
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
            ;;
        *) echo -e 'Please answer yes or no.' ;;
        esac
    fi
    NetBios=$(echo -e "$DOMAIN" | cut -d '.' -f1)
    echo -e ""
    echo -e "${INTRO_TEXT}Please type Admin user:${END}"
    read -r ADMIN
    #clear
    sudo echo -e "${INTRO_TEXT}Realm= $DOMAIN${END}"
    sudo echo -e "${NORMAL}${NORMAL}"
    if ! sudo realm join --verbose --user="$ADMIN" "$DOMAIN" --install=/; then
        echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
        exit
    fi
    fi_auth
}

####################################### Debian ##########################################
debianclient() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    dhcpDomain=$(hostname -d)

    if dpkg -l | grep openmediavault; then
        apt-mark hold openmediavault
    fi

    if ! dkpg -l | grep sudo; then
        apt-get install sudo -y
    else

        echo -e ""
        export whoami
        whoamis=$(whoami)
        echo -e "$whoamis"
        admins=$(grep admin /etc/passwd | grep bash | cut -d ':' -f1)
        if [ ! -z "$admins" ]; then
            echo -e "$admins ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers.d/admin
        fi
    fi
    #clear
    sudo echo -e "${RED_TEXT}Installing packages do not abort!.......${END}"
    sudo apt-get -qq update
    sudo apt-get install -y \
    krb5-user krb5-config \
    sssd sssd-tools libpam-sss \
    libnss-sss libsss-sudo \
    libsasl2-modules-gssapi-mit \
    realmd adcli policykit-1
    sudo mkdir -p /var/lib/samba/private
    sudo apt-get install -f
    #clear
    if ! sudo dpkg -l | grep realmd; then
        #clear
        sudo echo -e "${RED_TEXT}Installing packages failed.. please check connection, dpkg and apt-get update then try again.${END}"
        exit
    else
        #clear
        sudo echo -e "${INTRO_TEXT}Packages installed${END}"
    fi

    if dpkg -l | grep openmediavault; then
        apt-mark unhold openmediavault
    fi
    echo -e "hostname is $myhost"
    sleep 1
    if [ -z $DOMAIN ]; then
        DOMAIN=$(realm discover $dhcpDomain | grep -i realm-name | awk '{print $2}')
    fi

    if ! ping -c 1 "$DOMAIN"; then
        DOMAIN=$(realm discover -v $(cat /etc/resolv.conf | grep -i ^search | sed -r 's/search //') | grep -i realm-name | awk '{print $2}')
        if ! ping -c 1 "$DOMAIN"; then
            #clear
            echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below... ${END}"
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
        else
            #clear
            echo -e "${NUMBER}I searched for an available domain and found ${MENU}>>> $DOMAIN  <<<${END}${END}"
            read -r -p "Do you wish to use it (y/n)?" yn
            case $yn in
            [Yy]*) echo -e "${INTRO_TEXT}Please log in with domain admin access to $DOMAIN to connect${END}" ;;

            [Nn]*)
                echo -e "Please enter the domain you wish to join:"
                read -r DOMAIN
                ;;
            *) echo -e 'Please answer yes or no.' ;;
            esac
        fi
    fi
    # NetBios=$(echo -e "$DOMAIN" | cut -d '.' -f1) needed?
    echo -e ""
    echo -e "${INTRO_TEXT}Please type a Domain Admin user:${END}"
    read -r DomainADMIN
    #clear
    echo -e "${INTRO_TEXT}Realm= $DOMAIN${END}"
    echo -e "${NORMAL}${NORMAL}"

    #if ! sudo realm join -v -U "$DomainADMIN" "$DOMAIN" --install=/; then
    if ! grep $(hostname -d) /etc/hosts; then #fix hosts file to have domain before joining
        if grep $(hostname -s) /etc/hosts; then
            grep $(hostname -s) /etc/hosts
            echo -e "Modifying..."
            sed -Ei "s/($(hostname -s))/\1.$(hostname -d) \1/g" /etc/hosts
            grep $(hostname -s) /etc/hosts
        else
            if ! grep "127.0.1.1" /etc/hosts; then
                echo -e "127.0.1.1         $(hostname -s).$(hostname -d) $(hostname -s)" >>/etc/hosts
                grep "127.0.1.1" /etc/hosts
            fi
        fi
    fi
    echo -e "${NORMAL}Please type group name in AD for admins${END}"
    echo -e "${NUMBER}Be sure to escape out all whitespaces, if applicable.${END}"
    read -r "Mysrvgroup"
    export Mysrvgroup

    kinit $DomainADMIN
    echo -e "[sssd]
        services = nss, pam, pac, ssh
        config_file_version = 2
        domains = ${DOMAIN^^}

        [domain/${DOMAIN^^}]
        id_provider = ad
        access_provider = ad
        auth_provider = ad
        chpass_provider = ad
        #ldap_schema = rfc2307bis
        #ldap_schema = ad
        ldap_idmap_autorid_compat = True
        # Enumeration is discouraged for performance reasons.
        # OMV needs True to show users in ui and acl
        enumerate = True
        use_fully_qualified_names = False
        # timeout (integer)     #### The default value for this parameter is 10 seconds.
        # This get the users in range to show in UI and ACL
        ldap_idmap_range_min = 20000
        # ldap_idmap_range_max = 60000    ### Does not seem to work
        #                                ### Causes not able to start
        # If unneeded users or other objects show.
        # Use \"dsquery user -name * \"  to see on windows with powershell
        #ldap_user_search_base = OU=SBSUsers,OU=Users,OU=MyBusiness,DC=example,DC=com
        # ldap_user_search_base = CN=Users,DC=example,DC=com
        # Use this if users are being logged in at /.  OMV does this. Otherwise not tested
        # This example specifies /home/DOMAIN-FQDN/user as \$HOME.  Use with pam_mkhomedir.so
        #override_homedir = /home/%u
        #ldap_user_email = email  # Could this fill the email field? might not be in this version
        #ldap_user_search_base = dc=example,dc=com
        #ldap_group_search_base = dc=example,dc=com
        #ldap_user_object_class = user
        #ldap_user_name = sAMAccountName
        #ldap_user_fullname = displayName                ### Seems to be maps to comment in OMV?
        #ldap_user_home_directory = unixHomeDirectory
        #ldap_user_principal = userPrincipalName
        #ldap_group_object_class = group
        #ldap_group_name = sAMAccountName                ### Seems to be maps to Name in OMV?
        # Unused options
        #ldap_idmap_default_domain = ${DOMAIN,,}
        #ldap_id_mapping = True
        #default_domain_suffix = ${DOMAIN,,}
        #ldap_access_order = expire
        #ldap_account_expire_policy = ad
        #ldap_force_upper_case_realm = true
        #ldap_user_search_base = dc=example,dc=com
        #ldap_group_search_base = dc=example,dc=com
        #ldap_user_object_class = user
        #ldap_user_name = sAMAccountName
        #ldap_user_fullname = displayName
        #ldap_user_home_directory = unixHomeDirectory
        #ldap_user_principal = userPrincipalName
        #ldap_group_object_class = group
        #ldap_group_name = sAMAccountName
        # ldap_id_mapping = True
        # Uncomment if the client machine hostname doesn't match the computer object on the DC.
        # ad_hostname = mymachine.${DOMAIN^^}
        # Uncomment if DNS SRV resolution is not working
        # ad_server = dc.mydomain.${DOMAIN,,}
        # Uncomment if the AD domain is named differently than the Samba domain
        # ad_domain = ${DOMAIN,,}
        # filter_groups =
        # For other options see \"man sssd.conf\"
        # https://jhrozek.wordpress.com/2015/03/11/anatomy-of-sssd-user-lookup/" >/etc/sssd/sssd.conf
    chmod 0600 /etc/sssd/sssd.conf
    if ! sudo net ads join -k; then
        #if ! sudo realm join -v -U "$DomainADMIN" "$DOMAIN" --install=/; then
        echo -e "${RED_TEXT}AD join failed. Please check your errors with ${INTRO_TEXT}journalctl -xe${END}"
        read -n 1 -s -r -p "Press any key to continue..."
        exit
        # fi
    fi
    fi_auth_new

}
####################################### Cent OS #########################################
CentOS() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    yum -y install realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools samba-common
    yum -y install ipa-client
    echo -e "Looking for domains..."
    DOMAIN=$(realm discover | grep -i realm-name | awk '{print $2}')
    if [ -n "$DOMAIN" ]; then
        if ! ping -c 1 "$DOMAIN"; then
            #clear
            echo -e "I searched for an available domain and found $DOMAIN but it is not responding to ping, please type your domain manually below... "
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
            echo -e "I Please enter AD admin user "
            read -r ADMIN
        else
            #clear
            echo -e "I searched for an available domain and found >>> $DOMAIN  <<<"
            read -r -p "Do you wish to use it (y/n)?" yn
            case $yn in
            [Yy]*)
                echo -e "Please log in with domain admin to $DOMAIN to connect"
                sudo echo -e "Please enter AD admin user:"
                read -r ADMIN
                ;;
            [Nn]*)
                echo -e "Please enter the domain you wish to join:"
                read -r DOMAIN
                sudo echo -e "Please enter AD admin user:"
                read -r ADMIN
                ;;
            *) echo -e 'Please answer yes or no.' ;;
            esac
        fi
    else
        #clear
        echo -e "I searched for an available domain and found nothing, please type your domain manually below... "
        echo -e "Please enter the domain you wish to join:"
        read -r DOMAIN
        echo -e "I Please enter AD admin user "
        read -r ADMIN
    fi
    sudo echo -e "Realm= $DOMAIN"
    sudo echo -e ""
    if ! sudo realm join -v -U "$ADMIN" "$DOMAIN" --install=/; then
        echo -e "AD join failed.please check your errors with journalctl -xe"
        exit
    fi
    fi_auth_yum
    exit
}

############################### Raspberry Pi ###################################
raspberry() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    sudo aptitude install ntp adcli sssd
    sudo mkdir -p /var/lib/samba/private
    sudo aptitude install libsss-sudo
    sudo systemctl enable sssd
    #clear
    DOMAIN=$(realm discover | grep -i realm-name | awk '{print $2}')
    echo -e ""
    echo -e "please type Domain admin"
    read -r ADMIN
    if ! sudo realm join -v -U "$ADMIN" "$DOMAIN" --install=/; then
        echo -e "AD join failed.please check your errors with journalctl -xe"
        exit
    fi
    sudo systemctl start sssd
    echo -e "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" | sudo tee -a /etc/pam.d/common-session
    sudo echo -e "pi ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
    sudo echo -e "%$myhost""sudoers ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/sudoers
    sed -i -e 's/fallback_homedir = \/home\/%u@%d/#fallback_homedir = \/home\/%u@%d/g' /etc/sssd/sssd.conf
    sed -i -e 's/use_fully_qualified_names = True/use_fully_qualified_names = False/g' /etc/sssd/sssd.conf
    sed -i -e 's/access_provider = ad/access_provider = simple/g' /etc/sssd/sssd.conf
    sed -i -e 's/sudoers:        files sss/sudoers:        files/g' /etc/nsswitch.conf
    echo -e "override_homedir = /home/%d/%u" | sudo tee -a /etc/sssd/sssd.conf
    sudo grep -i override /etc/sssd/sssd.conf
    sudo echo -e "[nss]
    filter_groups = root
    filter_users = root
    reconnection_retries = 3
    entry_cache_timeout = 600
    #entry_cache_user_timeout = 5400
    #entry_cache_group_timeout = 5400
    #cache_credentials = TRUE
    entry_cache_nowait_percentage = 75" | sudo tee -a /etc/sssd/sssd.conf
    sudo service sssd restart
    exit
}

############################### Fedora #########################################
Fedora_fn() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    yum -y install realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools samba-common
    DOMAIN=$(realm discover | grep -i realm-name | awk '{print $2}')
    if ! ping -c 1 "$DOMAIN"; then
        #clear
        echo -e "I searched for an available domain and found nothing, please type your domain manually below... "
        echo -e "Please enter the domain you wish to join:"
        read -r DOMAIN
        echo -e "I Please enter AD admin user "
        read -r ADMIN
    else
        #clear
        echo -e "I searched for an available domain and found >>> $DOMAIN  <<<"
        read -r -p "Do you wish to use it (y/n)?" yn
        case $yn in
        [Yy]*) echo -e "Please log in with domain admin to $DOMAIN to connect" ;;

        [Nn]*)
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
            ;;
        *) echo -e 'Please answer yes or no.' ;;
        esac
    fi
    #clear
    sudo echo -e "Please enter AD admin user:"
    read -r ADMIN
    sudo echo -e "Realm= $DOMAIN"
    sudo echo -e ""
    if ! sudo realm join -v -U "$ADMIN" "$DOMAIN" --install=/; then
        echo -e "AD join failed.please check your errors with journalctl -xe"
        exit
    fi
    fi_auth_yum
    exit
}

############################# Linux Mint #####################################
LinuxMint() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    sudo apt-get -qq install -y realmd sssd sssd-tools samba-common krb5-user
    sudo apt-get -qq install -f -y
    echo -e "hostname is $myhost"
    echo -e "Looking for Realms.. please wait"
    DOMAIN=$(realm discover | grep -i realm.name | awk '{print $2}')
    if ! ping -c 2 "$DOMAIN" >/dev/null; then
        #clear
        echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below... ${END}"
        echo -e "Please enter the domain you wish to join:"
        read -r DOMAIN
    else
        #clear
        echo -e "${NUMBER}I searched for an available domain and found ${MENU}>>> $DOMAIN  <<<${END}${END}"
        read -r -p "Do you wish to use it (y/n)?" yn
        case $yn in
        [Yy]*) echo -e "" ;;

        [Nn]*)
            echo -e "Please enter the domain you wish to join:"
            read -r DOMAIN
            ;;
        *) echo -e 'Please answer yes or no.' ;;
        esac
    fi
    #clear
    echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
    echo -e "${INTRO_TEXT}Please type Admin user:${END}"
    read -r ADMIN
    NetBios=$(echo -e "$DOMAIN" | cut -d '.' -f1)
    #clear
    if ! sudo realm join --verbose --user="$ADMIN" "$DOMAIN"; then
        echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
        exit
    fi
    allowguest=$(sudo grep manual /usr/share/lightdm/lightdm.conf.d/50-disable-guest.conf | grep true | cut -d '=' -f2 | head -1)
    if [ "$allowguest" = "true" ]; then
        echo -e "Lightdm is already configured.. skipping.."
    else
        sudo echo -e "greeter-show-manual-login=true" | sudo tee -a /usr/share/lightdm/lightdm.conf.d/50-disable-guest.conf
    fi
    fi_auth
    exit
}

############################### Update to Realmd from likewise ##################
Realmdupdate() {
    #clear
    echo -e ""
    echo -e "this section has been deprecated, If you are still using likewise please see code"
    echo -e "leave likewise with sudo domainjoin-cli leave"
    exit
}

############################### Fail check ####################################
failcheck() {
    #clear
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    if ! hostname | cut -d '.' -f1 </dev/null >/dev/null 2>&1; then
        echo -e "Sorry I am having issues finding your domain.. please type it"
        read -r DOMAIN
    else
        echo -e ""
    fi
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------"
    echo -e ""
    if ! realm discover $DOMAIN </dev/null >/dev/null 2>&1; then
        echo -e "Realm not found"
    else
        echo -e ""
        therealm=$(realm discover $DOMAIN | grep -i configured | awk '{print $2}')
        if [ "$therealm" = "no" ]; then
            echo -e Realm configured?.. "${RED_TEXT}FAIL${END}"
        else
            echo -e Realm configured?.. "${INTRO_TEXT}OK${END}"
        fi
        if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
            echo -e Checking sudoers file.. "${INTRO_TEXT}OK${END}"
            grouPs=$(grep -i "$myhost" /etc/sudoers.d/sudoers | cut -d '%' -f2 | awk '{print $1}' | head -1 | sed -e 's/sudoers//g')
            if [ "$grouPs" = "$myhost" ]; then
                echo -e Checking sudoers users.. "${INTRO_TEXT}OK${END}"
            else
                echo -e Checking sudoers users.. "${RED_TEXT}FAIL${END}"
            fi
        else
            echo -e Checking sudoers file.. "${RED_TEXT}FAIL${END}"
        fi
        homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
        if [ "$homedir" -eq "0022" ] </dev/null >/dev/null 2>&1; then
            echo -e Checking PAM configuration.. "${INTRO_TEXT}OK${END}"
        else
            echo -e Checking PAM configuration.. "${RED_TEXT}FAIL${END}"
        fi
        cauth=$(grep required /etc/pam.d/common-auth | grep onerr | grep allow | cut -d '=' -f4 | cut -d 'f' -f1)
        if [ "$cauth" = "allow" ] </dev/null >/dev/null 2>&1; then
            echo -e Checking PAM auth configuration.. "${INTRO_TEXT}OK${END}"
        else
            echo -e Checking PAM auth configuration.. "${RED_TEXT}SSH security not configured${END}"
        fi
    fi
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------"
    exit
}

############################### Fail check Yum ####################################
failcheck_yum() {
    #clear
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    if ! hostname | cut -d '.' -f1 </dev/null >/dev/null 2>&1; then
        echo -e "Sorry I am having issues finding your domain.. please type it"
        read -r DOMAIN
    else
        echo -e ""
    fi
    echo -e "-------------------------------------------------------------------------------------"
    echo -e ""
    if ! realm discover; then
        echo -e "realm not found"
    else
        echo -e ""
        therealm=$(realm discover | grep -i realm-name | awk '{print $2}')
        if [ "$therealm" = "no" ]; then
            echo -e "Realm configured?.. FAIL"
        else
            echo -e "Realm configured?.. OK"
        fi
        if [ -f /etc/sudoers.d/admins ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking sudoers file.. OK"
            grouPs=$(grep -i "$myhost" /etc/sudoers.d/admins | cut -d '%' -f2 | cut -d '=' -f1 | sed -e 's/\<ALL\>//g')
            if [ "$grouPs" = "$myhost""sudoers" ]; then
                echo -e "Checking sudoers users.. OK"
            else
                echo -e "Checking sudoers users.. FAIL"
            fi
        else
            if [ -f /etc/sudoers.d/sudoers ] </dev/null >/dev/null 2>&1; then
                echo -e "Checking sudoers file..  OK"
                grouPs1=$(grep -i "$myhost" /etc/sudoers.d/sudoers | cut -d '%' -f2 | awk '{print $1}' | head -1 | head -1)
                if [ "$grouPs1" = "$myhost""sudoers" ]; then
                    echo -e "Checking sudoers user groups.. OK"
                else
                    echo -e "Checking sudoers user groups.. FAIL"
                fi
            else
                echo -e "Checking sudoers file.. FAIL not configured"
            fi
        fi
        homedir=$(grep homedir /etc/pam.d/common-session | grep 0022 | cut -d '=' -f3)
        if [ "$homedir" = "0022" ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking PAM configuration.. OK"
        else
            echo -e "Checking PAM configuration.. FAIL"
        fi
        cauth=$(grep required /etc/pam.d/common-auth | grep onerr | grep allow | cut -d '=' -f4 | cut -d 'f' -f1)
        if [ "$cauth" = "allow" ] </dev/null >/dev/null 2>&1; then
            echo -e "Checking PAM auth configuration.. OK"
        else
            echo -e "Checking PAM auth configuration.. SSH security not configured"
        fi
    fi
    echo -e ""
    echo -e "-------------------------------------------------------------------------------------"
    exit
}

#################################### ldapsearch #####################################################
ldaplook() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    ldaptools=$(sudo dpkg -l | grep -i ldap-utils | cut -d 's' -f1 | cut -d 'l' -f2)
    echo -e "${NUMBER}Remember!you must be logged in with AD admin on the client/server to use this funktion${END}"
    echo -e "${NUMBER}Remember!please edit in ldap.conf the lines BASE and URI in /etc/ldap/ldap.conf ${END}"
    echo -e "${NUMBER}your BASE will be the area you will search in${END}"
    sleep 3
    if [ "$ldaptools" = dap-uti ]; then
        #clear
        echo -e "ldap tool installed.. trying to find this host"
        sudo ldapsearch -x cn="$myhost"
        echo -e "Please type what you are looking for"
        read -r own
        sudo ldapsearch -x | grep -i "$own"
        exit
    else
        #clear
        if ! sudo apt-get install ldap-utils -y; then
            echo -e "install failed"
            exit
        else
            echo -e "${NUMBER}please edit in ldap.conf the lines BASE and URI ${END}"
            sleep 3
            sudo nano /etc/ldap/ldap.conf
            sudo ldapsearch -x | grep -i "$myhost"
            exit
        fi
    fi
}

############################### Reauth ##########################################
Reauthenticate() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    whoelse=$(who -ut | grep -v old | awk '{print $1}' | head -1)
    homeshome=$(sudo realm list | grep domain-name | awk '{print $2}')
    homes=$(find /home/"$homeshome" -maxdepth 1 -mindepth 1 | head -1 | cut -d '/' -f4)
    if [ "$homes" = "$whoelse" ]; then
        echo -e ""
        echo -e "you are logged in as an AD user.. canceling request"
        echo -e "only administrator has permissions"
        echo -e ""
        exit
    else
        LEFT=$(sudo realm list | grep configured | awk '{print $2}')
        DOMAIN=$(realm list | grep -i realm.name | awk '{print $2}')
        SSSD=$(sudo grep domain /etc/sssd/sssd.conf | awk '{print $3}' | head -1)
        DOMAINlower="${DOMAIN,,}"
        if [ -n "$DOMAIN" ] || [ -n "$SSSD" ]; then
            if [ "$DOMAINlower" = "$SSSD" ]; then
                echo -e "Detecting realm $SSSD"
                if [ "$LEFT" = "no" ]; then
                    echo -e ""
                    echo -e "$DOMAIN has not been configured"
                    echo -e ""
                    exit
                fi
            fi
            read -r -p "Do you really want to leave the domain: $DOMAIN (y/n)?" yn
            case $yn in
            [Yy]*)
                echo -e "Listing domain"
                sudo realm discover "$DOMAIN"
                sudo realm leave "$DOMAIN"
                LEFT=$(sudo realm discover "$DOMAIN" | grep configured | awk '{print $2}')
                if [ "$LEFT" = "no" ]; then
                    echo -e ""
                    sudo echo -e "" | sudo tee /etc/sssd/sssd.conf
                    echo -e "$DOMAIN has been left"
                    echo -e ""
                    notify-send ADconnection "Left $DOMAIN "
                    linuxclient
                else
                    echo -e "something went wrong, try to leave manually"
                    read -r DOMAIN
                    sudo realm leave "$DOMAIN"
                    left=$(sudo realm discover "$DOMAIN" | grep configured | awk '{print $2}')
                    if [ "$left" = "no" ]; then
                        echo -e ""
                        sudo echo -e "" | sudo tee /etc/sssd/sssd.conf
                        echo -e "$DOMAIN has been left"
                        echo -e ""
                        notify-send ADconnection "Left $DOMAIN "
                        linuxclient
                    else
                        echo -e "something went wrong"
                    fi
                fi
                ;;
            [Nn]*)
                echo -e "Bye"
                exit
                ;;
            *) echo -e 'Please answer yes or no.' ;;
            esac

        else
            echo -e 'No configured realms available.'
            echo -e 'Join a Realm first.'
        fi
        exit
    fi
}

######################### Leave Realm ################################
leaves() {
    export HOSTNAME
    myhost=$(hostname | cut -d '.' -f1)
    #clear
    LEFT=$(sudo realm list | grep configured | awk '{print $2}') </dev/null >/dev/null 2>&1
    DOMAIN=$(realm list | grep -i realm.name | awk '{print $2}') </dev/null >/dev/null 2>&1
    SSSD=$(sudo cat /etc/sssd/sssd.conf | grep domain | awk '{print $3}' | head -1) </dev/null >/dev/null 2>&1
    DOMAINlower=$(echo -e "$DOMAIN" | tr '[:upper:]' '[:lower:]') </dev/null >/dev/null 2>&1
    if ! realm list </dev/null >/dev/null 2>&1; then
        echo -e ""
        echo -e "Realm not found, nothing to leave"
        echo -e ""
    else
        if [ "$DOMAINlower" = "$SSSD" ] </dev/null >/dev/null 2>&1; then
            echo -e "Detecting realm $SSSD"
        else
            if [ "$LEFT" = "no" ] </dev/null >/dev/null 2>&1; then
                echo -e ""
                echo -e "$DOMAIN has not been configured"
                echo -e ""
                exit
            fi
        fi
        read -r -p "Do you really want to leave the domain: $DOMAIN (y/n)?" yn
        case $yn in
        [Yy]*)
            echo -e "Listing domain"
            sudo realm discover "$DOMAIN"
            sudo realm leave "$DOMAIN"
            LEFT=$(sudo realm discover | grep configured | awk '{print $2}')
            if [ "$LEFT" = "no" ]; then
                echo -e ""
                sudo echo -e "" | sudo tee /etc/sssd/sssd.conf
                echo -e "$DOMAIN has been left"
                echo -e ""
                notify-send ADconnection "Left $DOMAIN "
            else
                echo -e "something went wrong, try to leave manually"
                echo -e ""
                echo -e "Please type domain you wish to leave"
                read -r DOMAIN
                sudo realm leave "$DOMAIN"
                left=$(sudo realm discover | grep configured | awk '{print $2}')
                if [ "$left" = "no" ]; then
                    echo -e ""
                    sudo echo -e "" | sudo tee /etc/sssd/sssd.conf
                    echo -e "$DOMAIN has been left"
                    echo -e ""
                    notify-send ADconnection "Left $DOMAIN "
                else
                    echo -e "something went wrong"
                fi
            fi
            ;;
        [Nn]*)
            echo -e "Bye"
            exit
            ;;
        *) echo -e 'Please answer yes or no.' ;;
        esac
        exit
    fi
    exit
}

################################## info ##################################
readmes() {
    #clear
    echo -e "Usage: sh ADconnection.sh [--help] "
    echo -e "                          [-d (ubuntu debug mode)]"
    echo -e "                          [-j admin domain (Simple direct join) ADconnection -j ADadmin domain"
    echo -e "                          [-l (script output to log file)]"
    echo -e "                          [-s (Discover domain)]"
    echo -e "                          [-o (assign OU for computer object (-o OU=Clients,OU=Computers))"
    echo -e "                          [-u (sh ADconnection -u (autodetect) or -u user (looks up if computer can get user from AD))"
    echo -e ""
    echo -e ""
    echo -e "${INTRO_TEXT}           Active directory connection tool                     ${END}"
    echo -e "${INTRO_TEXT}                          Examples                                      ${END}"
    echo -e "${INTRO_TEXT}     Domain to join:${RED_TEXT}Example:${RED_TEXT}${NUMBER}mydomain.intra${NUMBER}${END}"
    echo -e "${INTRO_TEXT}                                                            ${END}"
    echo -e "${INTRO_TEXT}     Domain’s NetBios name:${RED_TEXT}Example:${RED_TEXT}${NUMBER}mydomain${NUMBER}${END}"
    echo -e "${INTRO_TEXT}                                                            ${END}"
    echo -e "${INTRO_TEXT}     Domain username:${RED_TEXT}Example:${RED_TEXT}${NUMBER}ADadmin${NUMBER}${END}"
    echo -e "${INTRO_TEXT}                                                            ${END}"
    echo -e "${INTRO_TEXT}     AD Group to put users in:${RED_TEXT}Example:${RED_TEXT}${NUMBER}Sudoers.global${NUMBER}${END}"
    echo -e "${RED_TEXT}       group should be created in AD with the group name being the HOSTNAMEsudores             ${END}"
    echo -e "${INTRO_TEXT}                                                            ${END}"
    echo -e "${INTRO_TEXT}     Script will use hostname and add sudoer to it to sudoers ${RED_TEXT}Example:${RED_TEXT}${NUMBER} myhostsudoer${NUMBER}${END}"
    echo -e "${INTRO_TEXT}     It is important that the computerobject ${RED_TEXT}Ex:${RED_TEXT} myhost gets created in AD pre or post running the script ( the join will create an computer object by it self ${END}"
    echo -e "${INTRO_TEXT}     and that the group ${RED_TEXT}Ex:${RED_TEXT} myhostsuoers exists, sudoers must be added or edit this script to remove sudoers from name${END}"
    echo -e "${INTRO_TEXT}     Script will also add domain admin group to suoers                     ${END}"
    echo -e "${NUMBER}     Remember to Check Hostname and add it to AD${END}"
    echo -e "${INTRO_TEXT}     Reauthenticate is a fix for Ubuntu 14 likewise issues when client looses user (who am I?)${END}"
    echo -e "${INTRO_TEXT}                                                                                                ${END}"
    echo -e "${INTRO_TEXT}  Ubuntu 16 and 14 has the setting not to show domain name in name or home folder due it can give${END}"
    echo -e "${INTRO_TEXT}  coding issues when building.. to change this configure /et/sssd/sssd.conf                     ${END}"
    echo -e ""
    exit
}

############################### Menu ###############################
MENU_FN() {
    #clear
    echo -e "${INTRO_TEXT}   Active directory connection tool             ${END}"
    echo -e "${INTRO_TEXT}       Created by Pierre Goude                  ${END}"
    echo -e "${INTRO_TEXT} This script will edit several critical files.. ${END}"
    echo -e "${INTRO_TEXT}  DO NOT attempt this without ${RED_TEXT}expert ${INTRO_TEXT}knowledge  ${END}"
    echo -e "${NORMAL}                                                    ${END}"
    echo -e "${MENU}*${NUMBER} 1)${MENU} Join to AD on Linux (Ubuntu/Rasbian/Kali/Fedora/Debian)    ${END}"
    echo -e "${MENU}*${NUMBER} 2)${MENU} Check for errors    ${END}"
    echo -e "${MENU}*${NUMBER} 3)${MENU} Search with ldap              ${END}"
    echo -e "${MENU}*${NUMBER} 4)${MENU} Reauthenticate   ${END}"
    echo -e "${MENU}*${NUMBER} 5)${MENU} Leave Domain             ${END}"
    echo -e "${NORMAL}                                                    ${END}"
    echo -e "${ENTER_LINE}Please enter a menu option and enter or ${RED_TEXT}ctrl + c to exit. ${END}"
    read -r opt
    while [ "$opt" != '' ]; do
        if [ "$opt" = "" ]; then
            exit
        else
            case $opt in
            1)
                #clear
                echo -e "Installing on Linux Client/Server"
                linuxclient
                ;;

            2)
                #clear
                echo -e "Check for errors"
                failcheck
                ;;
            3)
                #clear
                echo -e "Check in Ldap"
                ldaplook
                ;;
            4)
                #clear
                echo -e "Rejoin to AD"
                Reauthenticate
                ;;
            5)
                #clear
                echo -e "Leave domain"
                leaves
                ;;
            x)
                exit
                ;;
            '\n')
                exit
                ;;
            *)
                #clear
                echo "Pick an option from the menu"
                MENU_FN
                ;;
            esac
        fi
    done
}

############################### Menu YUM ###############################
YUM_MENU() {
    #clear
    echo -e "  Active directory connection tool             "
    echo -e "      Created by Pierre Goude                 "
    echo -e " This script will edit several critical files.. "
    echo -e "  DO NOT attempt this without expert knowledge  "
    echo -e ""
    echo -e "1) Join to AD on Linux (Ubuntu/Rasbian/Kali/Fedora)"
    echo -e "2) Check for errors"
    echo -e "3) Search with ldap"
    echo -e "4) Reauthenticate"
    echo -e "5) Leave Domain"
    echo -e ""
    echo -e "Please enter a menu option and enter or enter to exit."
    read -r opt
    while [ "$opt" != '' ]; do
        if [ "$opt" = "" ]; then
            exit
        else
            case $opt in
            1)
                #clear
                echo -e "Installing on Linux Client/Server"
                linuxclient
                ;;
            2)
                #clear
                echo -e "Check for errors"
                failcheck_yum
                ;;
            3)
                #clear
                echo -e "Check in Ldap"
                ldaplook
                ;;
            4)
                #clear
                echo -e "Rejoin to AD"
                Reauthenticate
                ;;
            5)
                #clear
                echo -e "Leave domain"
                leave
                ;;
            x)
                exit
                ;;
            '\n')
                exit
                ;;
            *)
                #clear
                opt "Pick an option from the menu"
                MENU_FN
                ;;
            esac
        fi
    done
}
################# Precheck for YUM based OS #################
PRECHECK_FN() {
    ## Precheck sends yum based OS to an own menu ##
    TheOS=$(hostnamectl | grep -i Operating | awk '{print $3}') </dev/null >/dev/null 2>&1
    if [ "$TheOS" = "Fedora" ] || [ "$TheOS" = "CentOS" ]; then
        YUM_MENU
    else
        MENU_FN
    fi
}
############################## Flags ###############################
#clear
#Versi0n=$( echo -e "7" )
#update=$( curl -s https://github.com/PierreGode/Linux-Active-Directory-join-script/blob/master/ADconnection.sh | grep -i Versi0n | awk '{print $10}' )
#if [ "$update" -gt "$Version" ]
#then
#echo -e "Updating ADconnection"
#git pull
#else
#echo -e "ADconnection is up to date"
#fi
while test $# -gt 0; do
    case "$1" in
    -help | --help)
        readmes
        ;;
    -d | --d)
        if test $# -gt 0; then
            linuxclientdebug
        else
            echo -e ""
            exit 1
        fi
        ;;
    -l | --d)
        if test $? -gt 0; then
            DATE=$(date +%H:%M)
            echo -e "$DATE"
            MENU_FN 2>&1 | sudo tee adconnection.log
        else
            echo -e ""
            exit 1
        fi
        ;;
    -j | --j)
        if test $# -gt 0; then
            if ! sudo realm join -v -U "$2" "$3" --install=/; then
                echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
                exit
            fi
            exit
        else
            echo -e ""
            exit 1
        fi
        ;;
    -s | --s)
        if test $# -gt 0; then
            if ! realm discover </dev/null >/dev/null 2>&1; then
                #clear
                echo -e ""
                echo -e "realmd is not installed"
                echo -e ""
                exit
            else
                sudo realm discover
                exit
            fi
        else
            echo -e ""
            exit 1
        fi
        ;;
    -u | --u)
        if test $# -gt 0; then
            #clear
            export HOSTNAME
            myhost=$(hostname | cut -d '.' -f1)
            DOMAIN=$(realm discover | grep -i realm.name | awk '{print $2}' | tr "[:upper:]" "[:lower:]")
            if [ -z "$2" ]; then
                if [ -d /home/"$DOMAIN" ]; then
                    ls /home/"$DOMAIN"/ | while read -r user; do
                        id "$user"
                        echo -e "___________________________________________________________________________"
                        echo -e ""
                    done
                else
                    echo -e "no user found on this system. try typing the user:"
                    read -r user
                    id "$user" | grep "$myhost"
                fi
            else
                id "$2"
            fi
            exit
        fi
        ;;
    -o | --o)
        if test $# -gt 0; then
            desktop=$(sudo apt list --installed | grep -i desktop | grep -i ubuntu | cut -d '-' -f1 | grep -i desktop)
            rasp=$(lsb_release -a | grep -i Distributor | awk '{print $3}')
            kalilinux=$(lsb_release -a | grep -i Distributor | awk '{print $3}')
            if [ "$desktop" = "desktop" ]; then
                if [ "$rasp" = "Raspbian" ]; then
                    echo -e "${INTRO_TEXT}Detecting Raspberry Pi${END}"
                    raspberry
                else
                    if [ "$kalilinux" = "Kali" ]; then
                        echo -e "${INTRO_TEXT}Detecting Kali linux${END}"
                        kalijoin
                    else
                        echo -e ""
                    fi
                fi
            else
                echo -e "this seems to be a server, Switching to server mode"
                ubuntuserver14
            fi
            export HOSTNAME
            myhost=$(hostname | cut -d '.' -f1)
            #clear
            sudo echo -e "${RED_TEXT}Installing packages do no abort!.......${END}"
            sudo apt-get -qq install realmd adcli sssd -y
            sudo apt-get -qq install ntp -y
            sudo apt-get install -f -y
            #clear
            if ! sudo dpkg -l | grep realmd; then
                #clear
                sudo echo -e "${RED_TEXT}Installing packages failed.. please check connection ,dpkg and apt-get update then try again.${END}"
                exit
            else
                #clear
                sudo echo -e "${INTRO_TEXT}packages installed${END}"
            fi
            echo -e "hostname is $myhost"
            echo -e "Looking for Realms.. please wait"
            DOMAIN=$(realm discover | grep -i realm.name | awk '{print $2}')
            if ! ping -c 2 "$DOMAIN" >/dev/null; then
                #clear
                echo -e "${NUMBER}I searched for an available domain and found nothing, please type your domain manually below...${END}"
                echo -e "Please enter the domain you wish to join:"
                read -r DOMAIN
            else
                #clear
                echo -e "${NUMBER}I searched for an available domain and found ${MENU}>>> $DOMAIN  <<<${END}${END}"
                read -r -p "Do you wish to use it (y/n)?" yn
                case $yn in
                [Yy]*) echo -e "" ;;

                [Nn]*)
                    echo -e "Please enter the domain you wish to join:"
                    read -r DOMAIN
                    ;;
                *) echo -e 'Please answer yes or no.' ;;
                esac
            fi
            NetBios=$(echo -e "$DOMAIN" | cut -d '.' -f1)
            #clear
            var=$(lsb_release -a | grep -i release | awk '{print $2}' | cut -d '.' -f1)
            if [ "$var" -eq "14" ]; then
                echo -e "Installing additional dependencies"
                sudo apt-get -qq install -y realmd sssd sssd-tools samba-common krb5-user
                sudo apt-get install -f -y
                #clear
                echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
                sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
                echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
                echo -e ""
                echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
                echo -e "${INTRO_TEXT}Please type Admin user:${END}"
                read -r ADMIN
                if ! realm join -v --user="$ADMIN" --computer-ou="$2" "$DOMAIN" --install=/; then
                    echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
                    exit
                fi
            else
                if [ "$var" -eq "16" ]; then
                    echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
                    #clear
                    sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
                    echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
                    echo -e ""
                    echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
                    echo -e "${INTRO_TEXT}Please type Admin user:${END}"
                    read -r ADMIN
                    if ! realm join -v --user="$ADMIN" --computer-ou="$2" "$DOMAIN"; then
                        echo -e "${RED_TEXT}AD join failed.please check your errors with journalctl -xe${END}"
                        exit
                    fi
                else
                    if [ "$var" -eq "17" ] || [ "$var" -eq "18" ] || [ "$var" -eq "19" ]; then
                        echo -e "${INTRO_TEXT}Detecting Ubuntu $var${END}"
                        sleep 1
                        #clear
                        if [ "$var" -eq "19" ]; then
                            echo -e "fixing krb5.keytab: Bad encryption type for ubuntu 19.10"
                            sudo add-apt-repository ppa:aroth/ppa
                            sudo apt-get update
                            sudo apt-get --only-upgrade install adcli
                        fi
                        sudo echo -e "${INTRO_TEXT}Realm=$DOMAIN${END}"
                        echo -e "${INTRO_TEXT}Joining Ubuntu $var${END}"
                        echo -e ""
                        echo -e "${INTRO_TEXT}Please log in with domain admin to $DOMAIN to connect${END}"
                        echo -e "${INTRO_TEXT}Please type Admin user:${END}"
                        read -r ADMIN
                        if ! realm join -v --user="$ADMIN" --computer-ou="$2" "$DOMAIN" --install=/; then
                            echo -e "${RED_TEXT}AD join failed. Please check your errors with journalctl -xe${END}"
                            exit
                        fi
                    else
                        #clear
                        sudo echo -e "${RED_TEXT}I am having issues detecting your Ubuntu version${END}"
                        exit
                    fi
                fi
            fi
            fi_auth
        else
            echo -e ""
            exit 1
        fi
        ;;
    *)
        break
        ;;
    esac
done
PRECHECK_FN
