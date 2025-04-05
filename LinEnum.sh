#!/system/bin/sh
# Android System Enumeration Script
version="version 1.0 (Android)"

# you may have to format this file to run on Android device (it can have errors with last if statement):
# tr -d '\r' < LinEnum.sh > LinEnum_fixed.sh
# chmod 755 LinEnum_fixed.sh
# sh LinEnum_fixed.sh


# Color codes
RED='\e[00;31m'
GREEN='\e[00;32m'
YELLOW='\e[00;33m'
RESET='\e[00m'

#help function
usage () 
{ 
echo -e "\n${RED}#########################################################${RESET}" 
echo -e "${RED}#${RESET}" "${YELLOW}Local Linux Enumeration & Privilege Escalation Script (for Android)${RESET}" "${RED}#${RESET}"
echo -e "${RED}#########################################################${RESET}"
echo -e "${YELLOW}# $version${RESET}\n"
echo -e "${YELLOW}# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t ${RESET}\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-s 	Supply user password for sudo checks (INSECURE)"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
echo -e "${RED}#########################################################${RESET}"		
}
header() {
    echo -e "${YELLOW}### ANDROID SYSTEM ENUMERATION ###${RESET}"
    echo -e "${YELLOW}# $version${RESET}\n"
}

debug_info()
{
echo "[-] Debug Info" 

echo -e "${RED}[-] Current ADB/Debug status:${RESET}"
echo "ro.debuggable: $(getprop ro.debuggable)"
echo "ro.secure: $(getprop ro.secure)"
echo "ro.adb.secure: $(getprop ro.adb.secure)"
echo "persist.sys.usb.config: $(getprop persist.sys.usb.config 2>/dev/null || echo 'N/A')"
echo "service.adb.tcp.port: $(getprop service.adb.tcp.port 2>/dev/null || echo 'Disabled')"
echo "adbd status: $(getprop init.svc.adbd 2>/dev/null || echo 'N/A')"
echo "Developer Options: $(settings get global development_settings_enabled 2>/dev/null || echo 'N/A (or inaccessible)')"
echo "OEM Unlocking Allowed: $(settings get global development_settings_oem_unlock_enable 2>/dev/null || echo 'N/A (or inaccessible)')" # Might require root
echo "ro.oem_unlock_supported: $(getprop ro.oem_unlock_supported 2>/dev/null || echo 'N/A')"

# Check for vendor debug features/props
echo -e "\n${RED}--- Vendor Debug Properties ---${RESET}"
vendordebug=$(getprop | grep -iE 'debug|test|eng|factory|diag|oem' 2>/dev/null)
if [ "$vendordebug" ]; then
    echo -e "$vendordebug"
else
    echo "[-] No common vendor debug properties found."
fi

# Check for common debug interfaces (e.g., Amlogic UART)
echo -e "\n${RED}--- Debug Interfaces ---${RESET}"
debug_ifaces=$(ls -l /dev/tty*USB* /dev/tty*ACM* /dev/ttyAML* /dev/ttyMSM* /sys/class/aml_keys* 2>/dev/null)
if [ "$debug_ifaces" ]; then
    echo -e "${YELLOW}[+] Potential debug interfaces found:${RESET}"
    echo "$debug_ifaces"
else
    echo "[-] No common debug interfaces found in /dev or /sys."
fi
echo ""

if [ "$keyword" ]; then
	echo "[+] Searching for keyword '$keyword' in .conf, .xml, .log, .sh, .prop files."
fi

if [ "$report" ]; then 
	echo "[+] Report name = $report" 
fi

if [ "$export" ]; then 
	echo "[+] Export location = $export" 
fi

if [ "$thorough" ]; then 
	echo "[+] Thorough tests = Enabled" 
else 
	echo -e "${YELLOW}[+] Thorough tests = Disabled${RESET}" 
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
fi

whoami=$(whoami 2>/dev/null || id -un 2>/dev/null) # Get current user
echo -e "\n${YELLOW}Scan running as user: $whoami${RESET}"
echo -e "${YELLOW}Scan started at: $(date)${RESET}\n"
sleep 1

#Android debug checks if Android detected
androidver=`getprop ro.build.version.release 2>/dev/null`
if [ "$androidver" ]; then
   echo -e "${YELLOW}[+] Android debug info:${RESET}"
   
   #check debug status multiple ways
   debuggable=`getprop ro.debuggable 2>/dev/null`
   userdebug=`getprop ro.build.type 2>/dev/null`
   debugsecure=`getprop ro.adb.secure 2>/dev/null`
   
   echo -e "Debug Status:"
   echo -e "- ro.debuggable: $debuggable"
   echo -e "- ro.build.type: $userdebug"
   echo -e "- ro.adb.secure: $debugsecure"

   #check adb status multiple ways
   adbstatus=`getprop init.svc.adbd 2>/dev/null`
   adbsecure=`getprop ro.adb.secure 2>/dev/null`
   adbtcp=`getprop service.adb.tcp.port 2>/dev/null`
   adbusb=`getprop persist.sys.usb.config 2>/dev/null`
   
   echo -e "\nADB Status:"
   echo -e "- init.svc.adbd: $adbstatus"
   echo -e "- ro.adb.secure: $adbsecure"
   echo -e "- adb.tcp.port: $adbtcp"
   echo -e "- usb config: $adbusb"

   #check debug properties with broader search
   debugprops=`getprop | grep -iE "debug|adb|usb" 2>/dev/null`
   if [ "$debugprops" ]; then
       echo -e "\n${RED}[-] Debug-related properties:${RESET}\n$debugprops"
   fi

   echo -e "\n"
fi

# Check for vendor debug features
echo -e "${RED}[-] Vendor debug features:${RESET}"
vendordebug=`getprop | grep -iE "debug|eng|test|vendor.debug" 2>/dev/null`
if [ "$vendordebug" ]; then
    echo -e "$vendordebug"
    echo -e "\n"
fi

# Check for unsecured debug interfaces
debug_ifaces=`ls -l /dev/ttyAML* 2>/dev/null || ls -l /sys/class/aml_keys 2>/dev/null`
if [ "$debug_ifaces" ]; then
    echo -e "${YELLOW}[+] Unsecured Amlogic debug interfaces found:${RESET}"
    echo "$debug_ifaces"
fi
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='aria2c\|arp\|ash\|awk\|base64\|bash\|busybox\|cat\|chmod\|chown\|cp\|csh\|curl\|cut\|dash\|date\|dd\|diff\|dmsetup\|docker\|ed\|emacs\|env\|expand\|expect\|file\|find\|flock\|fmt\|fold\|ftp\|gawk\|gdb\|gimp\|git\|grep\|head\|ht\|iftop\|ionice\|ip$\|irb\|jjs\|jq\|jrunscript\|ksh\|ld.so\|ldconfig\|less\|logsave\|lua\|make\|man\|mawk\|more\|mv\|mysql\|nano\|nawk\|nc\|netcat\|nice\|nl\|nmap\|node\|od\|openssl\|perl\|pg\|php\|pic\|pico\|python\|readelf\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-parts\|rvim\|scp\|script\|sed\|setarch\|sftp\|sh\|shuf\|socat\|sort\|sqlite3\|ssh$\|start-stop-daemon\|stdbuf\|strace\|systemctl\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xxd\|zip\|zsh'

system_info()
{
echo -e "${YELLOW}### SYSTEM ##############################################${RESET}" 

#basic kernel info
unameinfo=`uname -r 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "${RED}[-] Kernel information:${RESET}\n$unameinfo" 
  echo -e "\n" 
fi

# Detailed Kernel version and build info
kernelver=$(cat /proc/version 2>/dev/null)
if [ "$kernelver" ]; then
    echo -e "${RED}--- /proc/version ---${RESET}\n$kernelver"
    # Extract and highlight vendor build info
    vendorbuild=$(echo "$kernelver" | grep -oE '\b(eng|userdebug)\b|\(([^)]+)\)')
    if [ "$vendorbuild" ]; then
        echo -e "${YELLOW}[+] Custom/Debug build info detected in kernel string:${RESET} $vendorbuild"
    fi
    echo ""
fi

# Check kernel config
if [ -f "/proc/config.gz" ]; then
    echo -e "${RED}[-] Kernel config available - checking for vendor options:${RESET}"
    zcat /proc/config.gz 2>/dev/null | grep -iE "VENDOR|CUSTOM|OEM|AMLOGIC|MEDIATEK|QCOM|ROCKCHIP|REALTEK"
    echo -e "\n"
fi

# Check kernel parameters for common security misconfigurations
kernel_params=`cat /proc/cmdline | grep -iE "force_secure|SecureOS|enable_secure"`
if [ "$kernel_params" ]; then
    echo -e "${YELLOW}[+] Security-critical kernel parameters detected:${RESET}"
    echo "$kernel_params"
fi

cpuinfo=`cat /proc/cpuinfo 2>/dev/null`
if [ "$cpuinfo" ]; then
  echo -e "${YELLOW}[-] CPU information:${RESET}\n$cpuinfo" 
  echo -e "\n" 
fi

meminfo=`cat /proc/meminfo 2>/dev/null`
if [ "$meminfo" ]; then
  echo -e "${YELLOW}[-] Memory information:${RESET}\n$meminfo" 
  echo -e "\n" 
fi

# Android build info:
buildinfo=`getprop ro.build.fingerprint 2>/dev/null`
if [ "$buildinfo" ]; then
    echo -e "${RED}[-] Build fingerprint:${RESET}\n$buildinfo"
    echo -e "\n"
fi

# Check vendor kernel modules
echo -e "${YELLOW}[-] Vendor kernel modules:${RESET}"
vendormods=`ls -lR /vendor/lib/modules 2>/dev/null`
if [ "$vendormods" ]; then
    echo -e "$vendormods"
    echo -e "\n"
fi

# Check for vendor init scripts
echo -e "${YELLOW}[-] Vendor init scripts:${RESET}"
vendorinit=`ls -l /vendor/etc/init 2>/dev/null`
if [ "$vendorinit" ]; then
    echo -e "$vendorinit"
    echo -e "\n"
fi

# device info
boardinfo=`getprop ro.product.board 2>/dev/null`
if [ "$boardinfo" ]; then
    echo -e "${RED}[-] Device information:${RESET}\n$boardinfo"
    echo -e "\n"
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "${RED}[-] Hostname:${RESET}\n$hostnamed" 
  echo -e "\n" 
fi

#android/embedded system checks 
androidver=`getprop ro.build.version.release 2>/dev/null`
if [ "$androidver" ]; then
    echo -e "${RED}[-] Android system information:${RESET}"
    echo -e "Version: $androidver"
    
    #security patch level
    patchlevel=`getprop ro.build.version.security_patch 2>/dev/null`
    if [ "$patchlevel" ]; then
        echo -e "Security Patch Level: $patchlevel"
    fi

    #check if running on Android TV using multiple detection methods
    tvinfo=`getprop ro.product.characteristics 2>/dev/null`
    tvuimode=`getprop ro.build.characteristics 2>/dev/null`
    tvpackage=`pm list packages com.google.android.tvlauncher 2>/dev/null`
    tvsettings=`pm list packages com.android.tv.settings 2>/dev/null`

    echo -e "\nAndroid TV Detection Results:"
    echo -e "- ro.product.characteristics: $tvinfo"
    echo -e "- ro.build.characteristics: $tvuimode"
    echo -e "- TV Launcher Package: $tvpackage"
    echo -e "- TV Settings Package: $tvsettings"

    if [ "$tvinfo" = "tv" ] || [ "$tvuimode" = "tv" ] || [ "$tvpackage" ] || [ "$tvsettings" ]; then
        echo -e "${RED}[-] Android TV detected - checking for vulnerabilities${RESET}"
        
        #check system update policy and other security settings
        sysupdate=`getprop persist.sys.system_update_policy 2>/dev/null`
        if [ "$sysupdate" ]; then
            echo -e "${RED}[-] System update policy:${RESET}\n$sysupdate"
        fi

        #check for TV-specific vulnerabilities based on version
        if [ "$androidver" = "10" ]; then
            #MediaProjection checks
            projperms=`dumpsys media_projection 2>/dev/null`
            if [ "$projperms" ]; then
                echo -e "${YELLOW}[+] Potential MediaProjection vulnerability${RESET}"
            fi
        fi

        # Check for vulnerable vendor properties
        vendor_props=`getprop | grep -iE "vendor.sys.gb|vendor.media.secure|ro.vendor.platform.is"`
        if [ "$vendor_props" ]; then
            echo -e "${YELLOW}[+] Found potentially exploitable vendor properties:${RESET}"
            echo "$vendor_props"
        fi

        if [ "$androidver" = "9" ] || [ "$androidver" = "8" ] || [ "$androidver" = "8.1" ]; then
            #Launcher vulnerability checks
            launcherperm=`pm list packages -f com.google.android.tvlauncher 2>/dev/null`
            if [ "$launcherperm" ]; then
                if dumpsys package com.google.android.tvlauncher 2>/dev/null | grep -q "CUSTOM_INTENT"; then
                    echo -e "${YELLOW}[+] TV Launcher vulnerable to privilege escalation${RESET}"
                fi
            fi

            #Check for known Intent redirection vulnerability
            activitycheck=`dumpsys package com.google.android.tvlauncher | grep -A5 "Activity" | grep "android:exported=true" 2>/dev/null`
            if [ "$activitycheck" ]; then
                echo -e "${YELLOW}[+] TV Launcher has exposed activities - potential intent redirection${RESET}"
            fi
        fi

        #Additional checks for Android 8.x
        if [ "$androidver" = "8" ] || [ "$androidver" = "8.1" ]; then
            #Check for SetupActivity vulnerability
            setupact=`dumpsys package com.google.android.tvlauncher | grep -A2 "SetupActivity" | grep "exported=true" 2>/dev/null`
            if [ "$setupact" ]; then
                echo -e "${YELLOW}[+] TV Launcher Setup Activity vulnerability present${RESET}"
            fi

            #Check for TvSettings privilege escalation
            tvsettings=`dumpsys package com.android.tv.settings | grep -A2 "WRITE_SECURE_SETTINGS" 2>/dev/null`
            if [ "$tvsettings" ]; then
                echo -e "${YELLOW}[+] TvSettings has elevated permissions - potential privilege escalation${RESET}"
            fi

            # Check for vulnerable driver versions
            if [ -d "/sys/class/aml-video" ]; then
                vid_driver=`ls -l /sys/class/aml-video`
                echo -e "${YELLOW}[+] Potentially vulnerable video driver detected:${RESET}"
                echo "$vid_driver"
            fi

            #Check for unprotected broadcast receivers
            broadcasts=`dumpsys package com.google.android.tvlauncher | grep -A5 "Receiver" | grep -E "INSTALL_PACKAGES|DELETE_PACKAGES" 2>/dev/null`
            if [ "$broadcasts" ]; then
                echo -e "${YELLOW}[+] TV Launcher has vulnerable broadcast receivers${RESET}"
            fi

            #Check for content provider exposure (8.x specific)
            providers=`dumpsys package com.google.android.tvlauncher | grep -A5 "Provider" | grep "android:exported=true" 2>/dev/null`
            if [ "$providers" ]; then
                echo -e "${YELLOW}[+] TV Launcher has exposed content providers${RESET}"
            fi
        fi

        #Common checks for all TV versions
        if [ "$thorough" = "1" ]; then
            settingscheck=`dumpsys package com.android.tv.settings 2>/dev/null`
            if [ "$settingscheck" ]; then
                if echo "$settingscheck" | grep -q "WRITE_SECURE_SETTINGS"; then
                    echo -e "${YELLOW}[+] TVSettings has dangerous configurations${RESET}"
                fi
                if echo "$settingscheck" | grep -q "android:exported=\"true\""; then
                    echo -e "${YELLOW}[+] TVSettings has exposed components${RESET}"
                fi
            fi
        fi
    fi
    echo -e "\n"

    #check if we have root
    id=`id 2>/dev/null`
    if [ "$id" ]; then
        if echo "$id" | grep -q "uid=0"; then
            echo -e "${YELLOW}[+] Running as root on Android!${RESET}"
        fi
    fi
    
    #check if we're in an app context
    if [ -d "/data/data/$(ps -o NAME= -p $$)" ]; then
        echo -e "${RED}[-] Running from app context:${RESET} $(ps -o NAME= -p $$)"
    fi

    #check security critical properties
    secprops=`getprop | grep -E "ro.secure=|ro.debuggable=|ro.adb.secure=|persist.sys.usb.config" 2>/dev/null`
    if [ "$secprops" ]; then
        echo -e "${RED}[-] Security-relevant Android properties:${RESET}\n$secprops"
    fi
fi

# System props
sysprops=`getprop | grep -E "ro.product|ro.hardware|ro.arch" 2>/dev/null`
if [ "$sysprops" ]; then
    echo -e "${YELLOW}[-] System Properties (product, hardware, & arch):${RESET}\n$sysprops" 
    echo -e "\n" 
fi

# Kernel Memory layout
kernelbase=`grep -i "Kernel" /proc/iomem 2>/dev/null`
if [ "$kernelbase" ]; then
    echo -e "${YELLOW}[-] Kernel memory layout:${RESET}\n$kernelbase" 
    echo -e "\n" 
fi

# Check Vendor specific properties 
amlprops=`getprop | grep -iE "vendor|amlogic|oem|custom|build.display|build.version.custom|build.signature" 2>/dev/null`
if [ "$amlprops" ]; then
    echo -e "${YELLOW}[-] Amlogic properties:${RESET}\n$amlprops"
    echo -e "\n"
fi
}

# includes some partition things
bootloader_info()
{
verityinfo=`getprop ro.boot.veritymode 2>/dev/null`
if [ "$verityinfo" ]; then
    echo -e "${RED}[-] Verified boot status:${RESET}\n$verityinfo"
    echo -e "\n"
fi

boottype=`getprop getprop ro.bootloader 2>/dev/null; getprop getprop ro.boot.bootloader 2>/dev/null;`
if [ "$boottype" ]; then
    echo -e "${YELLOW}[-] Bootloader name and version:${RESET}\n$boottype"
    echo -e "\n"
fi

bootargs=`cat /proc/cmdline 2>/dev/null`
if [ "$bootargs" ]; then
    echo -e "${YELLOW}[-] Bootloader args:${RESET}\n$bootargs"
    echo -e "\n"
fi

bootloaderinfo=`getprop ro.boot.flash.locked 2>/dev/null`
if [ "$bootloaderinfo" ]; then
    echo -e "${RED}[-] Bootloader lock status:${RESET}\n$bootloaderinfo"
    echo -e "\n"
fi
#embedded bootloader info
bootinfo=`find /proc /sys /dev -name "boot*" -type f -exec ls -la {} \; 2>/dev/null`
if [ "$bootinfo" ]; then
    echo -e "${YELLOW}[-] Boot-related files:${RESET}\n$bootinfo"
    echo -e "\n"
fi

# Partition layout
mmcpart=`ls -l /dev/block/platform/*/* | grep -E "system|vendor|boot" 2>/dev/null`
if [ "$mmcpart" ]; then
    echo -e "${YELLOW}[-] MMC partition layout:${RESET}\n$mmcpart"
    echo -e "\n"
fi

#partition sizes
partsizes=`cat /proc/partitions 2>/dev/null`
if [ "$partsizes" ]; then
    echo -e "${YELLOW}[-] Partition sizes:${RESET}\n$partsizes"
    echo -e "\n"
fi

# Add DTB encryption status check
dtbcheck=`dmesg | grep -i "dtb" 2>/dev/null`
if [ "$dtbcheck" ]; then
    echo -e "${RED}[-] DTB status:${RESET}\n$dtbcheck"
    echo -e "\n"
fi

# Add bootloader status 
bootlocks=`getprop ro.boot.verifiedbootstate 2>/dev/null; getprop ro.boot.secureboot 2>/dev/null; getprop ro.boot.veritymode 2>/dev/null`
if [ "$bootlocks" ]; then
    echo -e "${RED}[-] Boot/Secure boot status:${RESET}\n$bootlocks"
    echo -e "\n"
fi

# Add RPMB state
rpmbstate=`getprop ro.boot.rpmb_state 2>/dev/null`
if [ "$rpmbstate" ]; then
    echo -e "${YELLOW}[-] RPMB state:${RESET}\n$rpmbstate"
    echo -e "\n"
fi

bootparams=`cat /proc/cmdline 2>/dev/null`
if [ "$bootparams" ]; then
    echo -e "${YELLOW}[-] Boot Parameters:${RESET}\n$bootparams"
    echo -e "\n"
fi

memaddr=`cat /proc/iomem 2>/dev/null | grep -i "Kernel\|Ramdisk\|Second Stage" 2>/dev/null`
if [ "$memaddr" ]; then
    echo -e "${YELLOW}[-] Memory Layout:${RESET}\n$memaddr"
    echo -e "\n"
fi

emmcinfo=`ls -l /dev/block/platform/*/* | grep -E "bl33|kernel" 2>/dev/null`
if [ "$emmcinfo" ]; then
    echo -e "${YELLOW}[-] eMMC Partition Layout:${RESET}\n$emmcinfo"
    echo -e "\n"
fi
}

user_info()
{
echo -e "${YELLOW}### USER/GROUP ##########################################${RESET}" 

#current processes and users
psinfo=`ps -ef 2>/dev/null`
if [ "$psinfo" ]; then
  echo -e "${RED}[-] Current processes and users:${RESET}\n$psinfo" 
  echo -e "\n"
fi

# Add Android-specific user checks
userinfo=`pm list users 2>/dev/null`
if [ "$userinfo" ]; then
    echo -e "${RED}[-] System users:${RESET}\n$userinfo"
    echo -e "\n"
fi

# Check app users
appusers=`ls -l /data/data 2>/dev/null`
if [ "$appusers" ]; then
    echo -e "${RED}[-] App users:${RESET}\n$appusers"
    echo -e "\n"
fi

# Check user permissions
if [ "$thorough" = "1" ]; then
    userperm=`dumpsys package | grep -A 2 "User" 2>/dev/null`
    if [ "$userperm" ]; then
        echo -e "${RED}[-] User permissions:${RESET}\n$userperm"
        echo -e "\n"
    fi
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "${YELLOW}[+] We can read root's home directory!${RESET}\n$rthmdir" 
  echo -e "\n"
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "${RED}[-] Files not owned by user but writable by group:${RESET}\n$grfilesall" 
    echo -e "\n"
  fi
fi

#looks for files that belong to us
if [ "$thorough" = "1" ]; then
  ourfilesall=`find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$ourfilesall" ]; then
    echo -e "${RED}[-] Files owned by our user:${RESET}\n$ourfilesall"
    echo -e "\n"
  fi
fi

#looks for hidden files
if [ "$thorough" = "1" ]; then
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    echo -e "${RED}[-] Hidden files:${RESET}\n$hiddenfiles"
    echo -e "\n"
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /data/data -perm -o+r -type d 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "${RED}[-] World-readable files within /data:${RESET}\n$wrfileshm" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	fi
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "${RED}[-] Home directory contents:${RESET}\n$homedircontents" 
		echo -e "\n" 
	fi
fi
}

environmental_info()
{
echo -e "${YELLOW}### ENVIRONMENTAL #######################################${RESET}" 

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "${RED}[-] Environment information:${RESET}\n$envinfo" 
  echo -e "\n"
fi

#check if selinux is enabled (android version)
getenforce=`getenforce 2>/dev/null`
if [ "$getenforce" ]; then
    echo -e "${RED}[-] SELinux status (Android):${RESET}\n$getenforce"
    echo -e "\n"
fi

# Check runtime permissions
rtperms=`dumpsys package | grep -A 2 "runtime permissions" 2>/dev/null`
if [ "$rtperms" ]; then
    echo -e "${RED}[-] Runtime permissions:${RESET}\n$rtperms"
    echo -e "\n"
fi

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls -ld $(echo $PATH | tr ":" " ")`
  echo -e "${RED}[-] Path information:${RESET}\n$pathinfo" 
  echo -e "$pathswriteable"
  echo -e "\n"
fi


#lists available shells - compatible with both Android and Linux
echo -e "${RED}[-] Available shells:${RESET}"
if [ -f "/etc/shells" ]; then
    cat /etc/shells 2>/dev/null
fi
#Check common shell locations individually
if [ -d "/system/bin" ]; then
    ls -l /system/bin/*sh 2>/dev/null
fi
if [ -d "/bin" ]; then
    ls -l /bin/*sh 2>/dev/null
fi
if [ -d "/usr/bin" ]; then
    ls -l /usr/bin/*sh 2>/dev/null
fi
echo -e "\n"
}

job_info()
{
echo -e "${YELLOW}### JOBS/TASKS ##########################################${RESET}" 
#check scheduled jobs
scheduledjobs=`dumpsys jobscheduler | grep -A 2 "Pending" 2>/dev/null`
if [ "$scheduledjobs" ]; then
    echo -e "${RED}[-] Pending scheduled jobs:${RESET}\n$scheduledjobs"
    echo -e "\n"
fi
# Add WorkManager jobs
workjobs=`dumpsys jobscheduler | grep "WorkManager" 2>/dev/null`
if [ "$workjobs" ]; then
    echo -e "${RED}[-] WorkManager jobs:${RESET}\n$workjobs"
    echo -e "\n"
fi

# Add Alarm Manager tasks
alarms=`dumpsys alarm 2>/dev/null`
if [ "$alarms" ]; then
    echo -e "${RED}[-] Scheduled alarms:${RESET}\n$alarms"
    echo -e "\n"
fi
}

networking_info()
{
echo -e "${YELLOW}### NETWORKING  ##########################################${RESET}" 

#nic information
nicinfo=`/sbin/ip -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "${RED}[-] Network and IP info:${RESET}\n$nicinfo" 
  echo -e "\n"
fi

#nic information (using ip)
nicinfoip=`/sbin/ip a 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
  echo -e "${RED}[-] Network and IP info:${RESET}\n$nicinfoip" 
  echo -e "\n"
fi

arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "${RED}[-] ARP history:${RESET}\n$arpinfo" 
  echo -e "\n"
fi

arpinfoip=`ip n 2>/dev/null`
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
  echo -e "${RED}[-] ARP history:${RESET}\n$arpinfoip" 
  echo -e "\n"
fi

# Check MAC addresses (multiple methods for Android 8.1)
echo -e "${RED}[-] MAC Address Information:${RESET}"
# Check in /sys
for interface in $(ls /sys/class/net/); do
    mac=$(cat /sys/class/net/$interface/address 2>/dev/null)
    if [ "$mac" ]; then
        echo "Interface $interface MAC: $mac"
    fi
done
# Alternative method using busybox if available
if [ -f "/system/xbin/busybox" ] || [ -f "/system/bin/busybox" ]; then
    busybox ifconfig | grep -i "hwaddr" 2>/dev/null
fi

# Check current IP configuration
echo -e "\n${RED}[-] IP Configuration Method:${RESET}"
# Check DHCP status through getprop
dhcp_status=$(getprop dhcp.wlan0.result 2>/dev/null)
if [ "$dhcp_status" ]; then
    echo "DHCP Status: $dhcp_status"
fi

# Check IP configuration through settings
ip_mode=$(settings get global wifi_static_ip_addresses 2>/dev/null)
if [ "$ip_mode" ]; then
    echo "Static IP Configuration: $ip_mode"
fi

# Get detailed network information from netcfg or ip
if [ -f "/system/bin/netcfg" ]; then
    echo -e "\n${RED}[-] Network Configuration:${RESET}"
    netcfg 2>/dev/null
elif [ -f "/system/bin/ip" ]; then
    echo -e "\n${RED}[-] Network Configuration:${RESET}"
    ip addr show 2>/dev/null
fi

# Check DHCP lease information
if [ -f "/data/misc/dhcp/dnsmasq.leases" ]; then
    echo -e "\n${RED}[-] DHCP Lease Information:${RESET}"
    cat /data/misc/dhcp/dnsmasq.leases 2>/dev/null
fi

#dns settings
nsinfo=`grep "nameserver" /etc/resolv.conf 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "${RED}[-] Nameserver(s):${RESET}\n$nsinfo" 
  echo -e "\n"
fi

# WiFi info
wifiinfo=`dumpsys wifi 2>/dev/null`
if [ "$wifiinfo" ]; then
    echo -e "${RED}[-] WiFi information:${RESET}\n$wifiinfo"
    echo -e "\n"
fi

# Get WiFi configuration details
if [ -d "/data/misc/wifi" ]; then
    echo -e "\n${RED}[-] WiFi Configuration:${RESET}"
    ls -l /data/misc/wifi/wpa_supplicant.conf 2>/dev/null
    if [ "$thorough" = "1" ]; then
        cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null
    fi
fi

# Network interfaces
ifconfig=`ip addr 2>/dev/null`
if [ "$ifconfig" ]; then
    echo -e "${RED}[-] Network interfaces:${RESET}\n$ifconfig"
    echo -e "\n"
fi

# Check network interface properties
for prop in $(getprop | grep -E "dhcp.|net.|wifi." | cut -d: -f1); do
    echo "$prop: $(getprop ${prop#[})" 2>/dev/null
done

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "${RED}[-] Default route:${RESET}\n$defroute" 
  echo -e "\n"
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default`
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "${RED}[-] Default route:${RESET}\n$defrouteip" 
  echo -e "\n"
fi

#listening TCP
tcpservs=`netstat -ntpl 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "${RED}[-] Listening TCP:${RESET}\n$tcpservs" 
  echo -e "\n"
fi

tcpservsip=`ss -t -l -n 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "${RED}[-] Listening TCP:${RESET}\n$tcpservsip" 
  echo -e "\n"
fi

#listening UDP
udpservs=`netstat -nupl 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "${RED}[-] Listening UDP:${RESET}\n$udpservs" 
  echo -e "\n"
fi

udpservsip=`ss -u -l -n 2>/dev/null`
if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
  echo -e "${RED}[-] Listening UDP:${RESET}\n$udpservsip" 
  echo -e "\n"
fi

#mobile/embedded network interfaces
mobileif=`ls -la /sys/class/net/rmnet* 2>/dev/null; ls -la /sys/class/net/wwan* 2>/dev/null`
if [ "$mobileif" ]; then
    echo -e "${RED}[-] Mobile network interfaces:${RESET}\n$mobileif" 
    echo -e "\n"
fi

if [ "$androidver" ]; then
    #check for VPN configurations
    vpnconf=`find /data/misc/vpn -type f 2>/dev/null`
    if [ "$vpnconf" ]; then
        echo -e "${RED}[-] VPN configurations found:${RESET}\n$vpnconf"
    fi
    
    #check network security configuration
    netsec=`find /data/data -name "network_security_config.xml" 2>/dev/null`
    if [ "$netsec" ]; then
        echo -e "${RED}[-] Network security configurations:${RESET}\n$netsec"
    fi
fi

if [ "$androidver" ]; then
    #check remote debugging
    adbnet=`getprop service.adb.tcp.port 2>/dev/null`
    if [ "$adbnet" ]; then
        echo -e "${YELLOW}[+] ADB over network is enabled on port:${RESET}\n$adbnet"
    fi
    
    #check network debug settings
    nettrace=`getprop debug.network 2>/dev/null`
    if [ "$nettrace" ]; then
        echo -e "${RED}[-] Network debug configuration:${RESET}\n$nettrace"
    fi
    
    #check Cast settings
    cast=`dumpsys media_router 2>/dev/null`
    if [ "$cast" ]; then
        echo -e "${RED}[-] Cast/media routing configuration:${RESET}\n$cast"
    fi
fi
}

services_info()
{
echo -e "${YELLOW}### SERVICES #############################################${RESET}" 

#running processes with package names
psaux=`ps -e | grep "u0_" 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "${RED}[-] Running app processes:${RESET}\n$psaux" 
  echo -e "\n"
fi

#lookup process binary path and permissisons
procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  echo -e "${RED}[-] Process binaries and associated permissions (from above list):${RESET}\n$procperm" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
fi

# Running services
services=`dumpsys activity services | grep -A 2 "ServiceRecord{" | grep -E "ServiceRecord{|intent=|packageName=" | grep -v "android.hardware.location" 2>/dev/null`
if [ "$services" ]; then
    echo -e "${RED}[-] Active services:${RESET}\n$services"
    echo -e "\n"
fi
susservices=` dumpsys activity services | grep -B 2 -A 2 "permission=" | grep -v "READ_PHONE_STATE" 2>/dev/null`
if [ "$susservices" ]; then
    echo -e "${RED}[-] Suspicious services:${RESET}\n$susservices"
    echo -e "\n"
fi
    

broadcasts=`dumpsys activity broadcasts | grep -A 3 "Registered Receivers" 2>/dev/null`
if [ "$broadcasts" ]; then
    echo -e "${RED}[-] Registered broadcast receivers:${RESET}\n$broadcasts"
    echo -e "\n"
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "${RED}[-] /usr/local/etc/rc.d binary permissions:${RESET}\n$usrrcdread" 
  echo -e "\n"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "${RED}[-] /usr/local/etc/rc.d files not belonging to root:${RESET}\n$usrrcdperms" 
  echo -e "\n"
fi

initread=`ls -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  echo -e "${RED}[-] /etc/init/ config file permissions:${RESET}\n$initread"
  echo -e "\n"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initperms" ]; then
   echo -e "${RED}[-] /etc/init/ config files not belonging to root:${RESET}\n$initperms"
   echo -e "\n"
fi

#check running packages
packagesinfo=`pm list packages 2>/dev/null`
if [ "$packagesinfo" ]; then
  echo -e "${RED}[-] Installed packages:${RESET}\n$packagesinfo" 
  echo -e "\n"
fi

if [ "$androidver" ]; then
    #check for potentially dangerous permissions
    dangerousperms=`dumpsys package | grep -B 2 "permission.*dangerous" 2>/dev/null | grep -v "android.permission.READ_PHONE_STATE"`
    if [ "$dangerousperms" ]; then
        echo -e "${RED}[-] Apps with dangerous permissions:${RESET}\n$dangerousperms"
        echo -e "\n"
    fi
    signatureperms=`dumpsys package | grep -B 2 "permission.*signatureOrSystem" 2>/dev/null`
    if [ "$signatureperms" ]; then
        echo -e "${RED}[-] Apps with signature permissions:${RESET}\n$signatureperms"
        echo -e "\n"
    fi
fi
#check app permissions
if [ "$thorough" = "1" ]; then
    local app="$1"
    if [ -z "$app" ]; then
        return
    fi
    
    echo -e "\n${RED}[-] Permissions for $app:${RESET}"
    dumpsys package $app | grep -A 5 "granted=true" 2>/dev/null | \
        grep -E "permission\.|granted=true" | \
        grep -v "android.permission.READ_PHONE_STATE"

else
    # Quick permission check
    echo -e "${RED}[-] Dangerous permissions:${RESET}"
    dumpsys package | grep -B 1 "permission.*dangerous" 2>/dev/null
fi
}

software_configs()
{
echo -e "${YELLOW}### SOFTWARE #############################################${RESET}" 
#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "${RED}[-] Apache version:${RESET}\n$apachever" 
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "${RED}[-] Apache user configuration:${RESET}\n$apacheusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  echo -e "${RED}[-] Installed Apache modules:${RESET}\n$apachemodules" 
  echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apachehomedirs=`ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null`
  if [ "$apachehomedirs" ]; then
    echo -e "${RED}[-] www home dir contents:${RESET}\n$apachehomedirs" 
    echo -e "\n"
  fi
fi

#check app configs
appconfigs=`find /data/data -name "*.xml" -type f 2>/dev/null`
if [ "$appconfigs" ]; then
  echo -e "${RED}[-] App configuration files:${RESET}\n$appconfigs" 
  echo -e "\n"
fi

}

interesting_files()
{
echo -e "${YELLOW}### INTERESTING FILES ####################################${RESET}" 

#checks to see if various files are installed
echo -e "${RED}[-] Useful file locations:${RESET}" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null 
echo -e "\n" 

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "${RED}[-] Installed compilers:${RESET}\n$compiler" 
  echo -e "\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "${RED}[-] Can we read/write sensitive files:${RESET}" ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null 
echo -e "\n" 

#search for suid files
allsuid=`find /system /vendor /data -perm -4000 -type f 2>/dev/null`
findsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsuid" ]; then
  echo -e "${RED}[-] SUID files:${RESET}\n$findsuid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsuid" ]; then
  mkdir $format/suid-files/ 2>/dev/null
  for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsuid" ]; then
  echo -e "${YELLOW}[+] Possibly interesting SUID files:${RESET}\n$intsuid" 
  echo -e "\n"
fi

#lists world-writable suid files
wwsuid=`find $allsuid -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuid" ]; then
  echo -e "${YELLOW}[+] World-writable SUID files:${RESET}\n$wwsuid" 
  echo -e "\n"
fi

#lists world-writable suid files owned by root
wwsuidrt=`find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuidrt" ]; then
  echo -e "${YELLOW}[+] World-writable SUID files owned by root:${RESET}\n$wwsuidrt" 
  echo -e "\n"
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2>/dev/null`
findsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  echo -e "${RED}[-] SGID files:${RESET}\n$findsgid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsgid" ]; then
  mkdir $format/sgid-files/ 2>/dev/null
  for i in $findsgid; do cp $i $format/sgid-files/; done 2>/dev/null
fi

#list of 'interesting' sgid files
intsgid=`find $allsgid -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsgid" ]; then
  echo -e "${YELLOW}[+] Possibly interesting SGID files:${RESET}\n$intsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files
wwsgid=`find $allsgid -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgid" ]; then
  echo -e "${YELLOW}[+] World-writable SGID files:${RESET}\n$wwsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files owned by root
wwsgidrt=`find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgidrt" ]; then
  echo -e "${YELLOW}[+] World-writable SGID files owned by root:${RESET}\n$wwsgidrt" 
  echo -e "\n"
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null`
if [ "$fileswithcaps" ]; then
  echo -e "${RED}[+] Files with POSIX capabilities set:${RESET}\n$fileswithcaps"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fileswithcaps" ]; then
  mkdir $format/files_with_capabilities/ 2>/dev/null
  for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
fi

if [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		echo -e "${YELLOW}[+] Capabilities associated with the current user:${RESET}\n$matchedcaps"
		echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			echo -e "${YELLOW}[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):${RESET}\n$matchedfiles"
			echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			echo -e "${YELLOW}[+] Permissions of files with the same capabilities associated with the current user:${RESET}\n$matchedfilesperms"
			echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					echo -e "${YELLOW}[+] User/Group writable files with the same capabilities associated with the current user:${RESET}\n$writablematchedfiles"
					echo -e "\n"
				fi
			fi
		fi
	fi
fi

#look for private keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
privatekeyfiles=`grep -rl "PRIVATE KEY-----" /home 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		echo -e "${YELLOW}[+] Private SSH keys found!:${RESET}\n$privatekeyfiles"
  		echo -e "\n"
	fi
fi

#look for AWS keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
awskeyfiles=`grep -rli "aws_secret_access_key" /home 2>/dev/null`
	if [ "$awskeyfiles" ]; then
  		echo -e "${YELLOW}[+] AWS secret keys found!:${RESET}\n$awskeyfiles"
  		echo -e "\n"
	fi
fi

#look for git credential files - thanks djhohnstein
if [ "$thorough" = "1" ]; then
gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
	if [ "$gitcredfiles" ]; then
  		echo -e "${YELLOW}[+] Git credentials saved on the machine!:${RESET}\n$gitcredfiles"
  		echo -e "\n"
	fi
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "${RED}[-] World-writable files (excluding /proc and /sys):${RESET}\n$wwfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	fi
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    echo -e "${RED}[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems${RESET}"
    echo -e "$fstab"
    echo -e "\n"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  echo -e "${YELLOW}[+] Looks like there are credentials in /etc/fstab!${RESET}\n$fstab"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "${YELLOW}[+] /etc/fstab contains a credentials file!${RESET}\n$fstabcred" 
    echo -e "\n"
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

#use supplied keyword and cat *.conf files for potential matches
if [ "$keyword" = "" ]
then
    echo -e "[-] Can't search *.conf files as no keyword was entered\n"
else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]
    then
        echo -e "${RED}[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):${RESET}\n$confkey"
        echo -e "\n"
    else
        echo -e "${RED}[-] Find keyword ($keyword) in .conf files (recursive 4 levels):${RESET}"
        echo -e "'$keyword' not found in any .conf files"
        echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.php files for potential matches
if [ "$keyword" = "" ]
then
    echo -e "[-] Can't search *.php files as no keyword was entered\n"
else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$phpkey" ]
    then
        echo -e "${RED}[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):${RESET}\n$phpkey"
        echo -e "\n"
    else
        echo -e "${RED}[-] Find keyword ($keyword) in .php files (recursive 10 levels):${RESET}"
        echo -e "'$keyword' not found in any .php files"
        echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]
then
    echo -e "[-] Can't search *.log files as no keyword was entered\n"
else
    logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]
    then
        echo -e "${RED}[-] Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):${RESET}\n$logkey"
        echo -e "\n"
    else
        echo -e "${RED}[-] Find keyword ($keyword) in .log files (recursive 4 levels):${RESET}"
        echo -e "'$keyword' not found in any .log files"
        echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]
then
    echo -e "[-] Can't search *.ini files as no keyword was entered\n"
else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]
    then
        echo -e "${RED}[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):${RESET}\n$inikey"
        echo -e "\n"
    else
        echo -e "${RED}[-] Find keyword ($keyword) in .ini files (recursive 4 levels):${RESET}"
        echo -e "'$keyword' not found in any .ini files"
        echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "${RED}[-] All *.conf files in /etc (recursive 1 level):${RESET}\n$allconf" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
fi

#check command history in shell
if [ -f "/data/local/tmp/.sh_history" ]; then
    echo -e "${RED}[-] Shell history:${RESET}"
    cat /data/local/tmp/.sh_history 2>/dev/null
    echo -e "\n"
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "${YELLOW}[+] Root's history files are accessible!${RESET}\n$roothist" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
fi

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  echo -e "${RED}[-] Location and contents (if accessible) of .bash_history file(s):${RESET}\n$checkbashhist"
  echo -e "\n"
fi

#any .bak files that may be of interest
bakfiles=`find / -name *.bak -type f 2</dev/null`
if [ "$bakfiles" ]; then
  echo -e "${RED}[-] Location and Permissions (if accessible) of .bak file(s):${RESET}"
  for bak in `echo $bakfiles`; do ls -la $bak;done
  echo -e "\n"
fi

#mobile/embedded storage locations
if [ "$thorough" = "1" ]
then
    echo -e "${RED}[-] Checking mobile storage locations:${RESET}"
    # Check each storage location individually
    if [ -d "/storage/emulated" ]
    then
        ls -la /storage/emulated 2>/dev/null
    fi
    if [ -d "/storage/sdcard0" ]
    then
        ls -la /storage/sdcard0 2>/dev/null
    fi
    if [ -d "/sdcard" ]
    then
        ls -la /sdcard 2>/dev/null
    fi
    if [ -d "/data/media" ]
    then
        ls -la /data/media 2>/dev/null
    fi
    echo -e "\n"
    
    #look for sensitive files in mobile locations
    mobilesens=`find /data/data /storage -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.key" -o -name "*.conf" \) 2>/dev/null`
    if [ "$mobilesens" ]
    then
        echo -e "${RED}[-] Potentially sensitive files in mobile locations:${RESET}\n$mobilesens"
        echo -e "\n"
    fi
fi

if [ "$androidver" ]; then
    storageinfo=`dumpsys mount 2>/dev/null`
    if [ "$storageinfo" ]; then
        echo -e "${RED}[-] Storage mounts:${RESET}\n$storageinfo"
        echo -e "\n"
    fi

    encryptinfo=`getprop ro.crypto.state 2>/dev/null`
    if [ "$encryptinfo" ]; then
        echo -e "${RED}[-] Device encryption status:${RESET}\n$encryptinfo"
        echo -e "\n"
    fi
    
    #check for writable app directories
    if [ "$thorough" = "1" ]; then
        appwrite=`find /data/data -writable -type d 2>/dev/null`
        if [ "$appwrite" ]; then
            echo -e "${RED}[-] Writable app directories:${RESET}\n$appwrite"
        fi
    fi
fi

if [ "$androidver" ]; then
    #check for system apps with debug flags
    debugapps=`pm list packages -f | grep -i "debuggable" 2>/dev/null`
    if [ "$debugapps" ]; then
        echo -e "${YELLOW}[+] Debuggable apps found:${RESET}\n$debugapps"
    fi

    #check for apps with backup enabled
    backupapps=`pm list packages -f | grep -i "allowbackup" 2>/dev/null`
    if [ "$backupapps" ]; then
        echo -e "${RED}[-] Apps with backup enabled:${RESET}\n$backupapps"
    fi

    #check for world-readable preference files
    if [ "$thorough" = "1" ]; then
        worldprefs=`find /data/data -name "*.xml" -perm -004 2>/dev/null`
        if [ "$worldprefs" ]; then
            echo -e "${YELLOW}[+] World-readable preference files:${RESET}\n$worldprefs"
        fi
    fi

    #check accessibility services
    accservices=`dumpsys accessibility 2>/dev/null`
    if [ "$accservices" ]; then
        echo -e "${RED}[-] Accessibility Services:${RESET}\n$accservices"
    fi

    #TV-specific privilege escalation
    if [ "$tvinfo" = "tv" ]; then
        #check system customization provider
        customprovider=`pm list packages -f com.android.tv.customization 2>/dev/null`
        if [ "$customprovider" ]; then
            echo -e "${RED}[-] TV customization provider permissions:${RESET}"
            dumpsys package com.android.tv.customization 2>/dev/null
        fi

        #check input service vulnerabilities 
        inputservice=`dumpsys input 2>/dev/null`
        if [ "$inputservice" ]; then
            echo -e "${RED}[-] Input service configuration:${RESET}\n$inputservice"
        fi
    fi
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find /data/data /system -writable ! -user \`whoami\` -type f -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "${RED}[-] Files not owned by user but writable:${RESET}\n$grfilesall" 
    echo -e "\n"
  fi
fi

keystores=`find /data -name "*.key" -o -name "*.keystore" 2>/dev/null`
if [ "$keystores" ]; then
    echo -e "${RED}[-] Key storage files:${RESET}\n$keystores"
    echo -e "\n"
fi
}

check_android_81_vulns() {
echo -e "\n${RED}[!] Checking for Android 8.1 specific vulnerabilities${RESET}"

# CVE-2018-9341 - Download Provider Vulnerability
echo -e "\n${RED}[!] Checking for CVE-2018-9341 (Download Provider Vulnerability)${RESET}"
dlprovider=`dumpsys package com.android.providers.downloads`
if [ "$dlprovider" ]; then
    # Check for specific version with vulnerability
    version=`echo "$dlprovider" | grep "versionName" | cut -d"=" -f2`
    if [[ "$version" < "8.1.0_r43" ]]; then
        echo -e "${YELLOW}[+] Vulnerable Download Provider version detected: $version${RESET}"
    fi
    
    # Check for vulnerable permission configuration
    if echo "$dlprovider" | grep -A 2 "grantUriPermission" | grep -q "true"; then
        echo -e "${YELLOW}[+] Download Provider has vulnerable URI permission configuration${RESET}"
    fi
fi

# CVE-2017-13208 - DHCP vulnerability
echo -e "\n${RED}[!] Checking for CVE-2017-13208 - DHCP Client RCE${RESET}"
# Check for vulnerable libnetutils version
if [ -f "/system/lib/libnetutils.so" ] || [ -f "/system/lib64/libnetutils.so" ]; then
    libnetutils_ver=`strings /system/lib/libnetutils.so 2>/dev/null | grep "receive_packet"`
    if [ "$libnetutils_ver" ]; then
        echo -e "${YELLOW}[+] Potentially vulnerable libnetutils found with receive_packet function${RESET}"
        
        # Check if DHCP client is running
        dhcp_check=`ps -ef | grep -i "dhcp" | grep -v "grep"`
        if [ "$dhcp_check" ]; then
            echo -e "${YELLOW}[+] Active DHCP client detected - system likely vulnerable to CVE-2017-13208${RESET}"
        fi
        
        # Check DHCP configurations
        if [ -f "/system/etc/dhcpcd/dhcpcd.conf" ]; then
            echo -e "${YELLOW}[+] DHCP client configuration found - confirms DHCP usage${RESET}"
        fi
    fi
fi

# CVE-2018-9344 - Media Framework Vulnerability
echo -e "\n${RED}[!] Checking for CVE-2018-9344 (MediaCodec Vulnerability)${RESET}"
# Check MediaCodec implementation
mediacodec=`getprop ro.hardware.mediacodec 2>/dev/null`
if [ "$mediacodec" ]; then
    if [ "$mediacodec" = "amlogic" ]; then
        # Check specific version
        media_ver=`dumpsys media.codec | grep -i "version"`
        echo -e "${YELLOW}[+] Potentially vulnerable Amlogic MediaCodec detected${RESET}"
        echo -e "${YELLOW}[+] Media Codec Version: $media_ver${RESET}"
    fi
fi

# Check CAS implementation
cas_check=`dumpsys media.cas | grep -i "casImpl"`
if [ "$cas_check" ]; then
    echo -e "${YELLOW}[+] CAS implementation detected - potential for CVE-2018-9344${RESET}"
fi

# CVE-2018-9358 - Bluetooth Stack Vulnerability
echo -e "\n${RED}[!] Checking for CVE-2018-9358 (Bluetooth Vulnerability)${RESET}"

# Check Bluetooth version and implementation
bt_version=`dumpsys bluetooth_manager | grep -i "version"`
if [ "$bt_version" ]; then
    echo -e "Bluetooth Version: $bt_version"
    
    # Check for GATT service
    gatt_service=`dumpsys bluetooth_manager | grep -i "gatt"`
    if [ "$gatt_service" ]; then
        echo -e "${YELLOW}[+] GATT service running - potential for CVE-2018-9358${RESET}"
    fi
fi
}

footer()
{
echo -e "${YELLOW}### SCAN COMPLETE ####################################${RESET}" 
}

call_each()
{
  header
  debug_info
  system_info
  check_android_81_vulns
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  footer
}

while getopts "h:k:r:e:st" option
do 
    if [ "$option" = "k" ]; then keyword=$OPTARG; fi
    if [ "$option" = "r" ]; then report=$OPTARG-`date +"%d-%m-%y"`; fi
    if [ "$option" = "e" ]; then export=$OPTARG; fi
    if [ "$option" = "s" ]; then sudopass=1; fi
    if [ "$option" = "t" ]; then thorough=1; fi
    if [ "$option" = "h" ]; then usage; exit; fi
    if [ "$option" = "*" ]; then usage; exit; fi
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
