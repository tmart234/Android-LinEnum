#!/bin/bash

# Base directories
DUMP_DIR="android_dump"
PARTITIONS_DIR="${DUMP_DIR}/partitions"
SYSTEM_DIR="${DUMP_DIR}/system_files"
VENDOR_DIR="${DUMP_DIR}/vendor_files"
CONFIG_DIR="${DUMP_DIR}/config"

# Create directory structure
mkdir -p "${PARTITIONS_DIR}" "${SYSTEM_DIR}" "${VENDOR_DIR}" "${CONFIG_DIR}"

echo "[+] Starting extraction from Android Device..."

# 1. First verify we have root access
echo "[*] Verifying root access..."
if ! adb shell su -c id | grep -q "uid=0"; then
    echo "[-] Root access not available. Exiting."
    exit 1
fi

# Then enable debugging/ ADB
echo "[*] Enabling debugging and ADB access..."
adb shell su -c "setprop ro.debuggable 1"
adb shell su -c "setprop ro.secure 0"
adb shell su -c "setprop ro.adb.secure 0"
adb shell su -c "setprop persist.sys.usb.config adb"
adb shell su -c "start adbd"
# and Remove ADB authentication
echo "[*] Removing ADB authentication..."
adb shell su -c "rm -rf /data/misc/adb/adb_keys"

# 2. Extract partition layout and info
echo "[*] Getting partition information..."
adb shell su -c "cat /proc/partitions" > "${CONFIG_DIR}/partitions.txt"
adb shell su -c "ls -l /dev/block/platform/d0074000.emmc/*" > "${CONFIG_DIR}/partition_map.txt"

# 3. Dump essential partitions
echo "[*] Dumping partitions..."
# Format: "partition_name:start_sector:sector_count"
PARTITIONS=(
    "system:2924544:3145728"
    "vendor:2334720:524288"
    "boot:2154496:32768"
    "bootloader:0:8192"
    "dto:2039808:16384"
)

for part in "${PARTITIONS[@]}"; do
    IFS=':' read -r name start size <<< "$part"
    echo "[*] Dumping ${name} partition..."
    
    # Create temporary file on device
    adb shell su -c "dd if=/dev/block/platform/d0074000.emmc/${name} of=/data/local/tmp/${name}.img bs=512 count=${size}"
    
    # Pull to computer
    adb pull "/data/local/tmp/${name}.img" "${PARTITIONS_DIR}/"
    
    # Cleanup
    adb shell su -c "rm /data/local/tmp/${name}.img"
    
    # Get partition info
    adb shell su -c "ls -l /dev/block/platform/d0074000.emmc/${name}" >> "${CONFIG_DIR}/${name}_info.txt"
done

# 4. Pull essential system files
echo "[*] Pulling system files..."
SYSTEM_FILES=(
    "/system/build.prop"
    "/system/framework"
    "/system/lib"
    "/system/app/com.google.android.tvlauncher"
    "/system/app/com.android.tv.settings"
    "/system/priv-app"
)

for file in "${SYSTEM_FILES[@]}"; do
    echo "[*] Copying ${file}..."
    adb pull "${file}" "${SYSTEM_DIR}/"
done

# 5. Pull vendor files
echo "[*] Pulling vendor files..."
VENDOR_FILES=(
    "/vendor/build.prop"
    "/vendor/lib"
    "/vendor/etc"
    "/vendor/firmware"
)

for file in "${VENDOR_FILES[@]}"; do
    echo "[*] Copying ${file}..."
    adb pull "${file}" "${VENDOR_DIR}/"
done

# 6. Get device configuration and properties
echo "[*] Gathering device configuration..."
adb shell su -c "getprop" > "${CONFIG_DIR}/properties.txt"
adb shell su -c "cat /proc/cpuinfo" > "${CONFIG_DIR}/cpuinfo.txt"
adb shell su -c "cat /proc/cmdline" > "${CONFIG_DIR}/cmdline.txt"
adb shell su -c "ls -Z /system" > "${CONFIG_DIR}/selinux_contexts.txt"

# 7. Verify extracted files
echo "[*] Verifying extracted files..."
echo -e "\nExtracted Partitions:"
ls -lh "${PARTITIONS_DIR}"

echo -e "\nExtracted System Files:"
ls -lh "${SYSTEM_DIR}"

echo -e "\nExtracted Vendor Files:"
ls -lh "${VENDOR_DIR}"

# 8. Create info file about the dump
cat << EOF > "${DUMP_DIR}/DUMP_INFO.txt"
Ematic AGT418 Dump Info
======================
Date: $(date)
Device: Ematic AGT418 (DV8235)
Android Version: 8.1.0

Extracted Partitions:
$(ls -lh "${PARTITIONS_DIR}")

Key System Files:
$(ls -lh "${SYSTEM_DIR}")

Key Vendor Files:
$(ls -lh "${VENDOR_DIR}")

These files are required for QEMU emulation.
Place partition images in the 'images' directory before running QEMU.
EOF

echo "[+] Extraction complete! Files saved in ${DUMP_DIR}"
echo "[*] Next steps:"
echo "Copy partition files from ${PARTITIONS_DIR} to your QEMU 'images' directory"