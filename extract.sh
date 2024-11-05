#!/bin/bash

# Base directories
DUMP_DIR="android_dump"
PARTITIONS_DIR="${DUMP_DIR}/partitions"
SYSTEM_DIR="${DUMP_DIR}/system_files"
VENDOR_DIR="${DUMP_DIR}/vendor_files"
CONFIG_DIR="${DUMP_DIR}/config"
KERNEL_DIR="${DUMP_DIR}/kernel"
DEBUG_DIR="${DUMP_DIR}/debug"

# Create directory structure
mkdir -p "${KERNEL_DIR}" "${PARTITIONS_DIR}" "${DEBUG_DIR}" "${SYSTEM_DIR}" "${VENDOR_DIR}" "${CONFIG_DIR}"

echo "[+] Starting extraction from Android Device..."

# 1. First verify we have root access
echo "[*] Verifying root access..."
if ! adb shell su -c id | grep -q "uid=0"; then
    echo "[-] Root access not available. Exiting."
    exit 1
fi

# 2. Extract partition layout and info
echo "[*] Getting partition information..."
adb shell su -c "cat /proc/partitions" > "${CONFIG_DIR}/partitions.txt"
adb shell su -c "ls -l /dev/block/platform/d0074000.emmc/*" > "${CONFIG_DIR}/partition_map.txt"

echo "[*] Getting kernel config..."
adb shell su -c "cat /proc/config.gz > /data/local/tmp/config.gz"
adb pull "/data/local/tmp/config.gz" "${CONFIG_DIR}/"
gunzip "${CONFIG_DIR}/config.gz"

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
echo "[*] Getting kernel memory layout..."
adb shell su -c "cat /proc/iomem" > "${CONFIG_DIR}/iomem.txt"
adb shell su -c "cat /proc/kallsyms" > "${CONFIG_DIR}/kallsyms.txt"

# 3. Get boot partition info
echo "[*] Locating boot partition..."
BOOT_PATH=$(adb shell su -c "readlink -f /dev/block/platform/*/by-name/boot")
echo "Boot partition: ${BOOT_PATH}"

# Dump boot image
echo "[*] Extracting boot image..."
adb shell su -c "dd if=${BOOT_PATH} of=/data/local/tmp/boot.img"
adb pull "/data/local/tmp/boot.img" "${KERNEL_DIR}/"


# 7. Verify extracted files
echo "[*] Verifying extracted files..."
echo -e "\nExtracted Partitions:"
ls -lh "${PARTITIONS_DIR}"

echo -e "\nExtracted System Files:"
ls -lh "${SYSTEM_DIR}"

echo -e "\nExtracted Vendor Files:"
ls -lh "${VENDOR_DIR}"

# 8. Create summary file
echo "[*] Creating analysis summary..."
cat << EOF > "${DUMP_DIR}/ANALYSIS.txt"
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

Kernel: $(cat "${CONFIG_DIR}/kernel_version.txt")

Boot Partition: ${BOOT_PATH}

Bootloader Parameters:
$(cat "${CONFIG_DIR}/cmdline.txt")

These files are required for QEMU emulation.
Place partition images in the 'images' directory before running QEMU.
EOF

echo "[+] Extraction complete! Check ${DUMP_DIR}/ANALYSIS.txt for details"