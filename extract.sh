#!/bin/bash
# extract_and_setup.sh - Combined extraction and QEMU preparation script
# currently only works on Amlogic GXL but with little editing it could do more
# supports IR driver extractions for qiling

# Base directories
DUMP_DIR="amlogic_dump"
IMAGES_DIR="${DUMP_DIR}/images"
DEBUG_DIR="${DUMP_DIR}/debug"
ROOTFS_DIR="${DUMP_DIR}/rootfs"
SYMBOLS_DIR="${DUMP_DIR}/symbols"
MODULE_DIR="${ROOTFS_DIR}/lib/modules"

# Create directory structure
mkdir -p "${IMAGES_DIR}" "${DEBUG_DIR}" "${ROOTFS_DIR}" "${SYMBOLS_DIR}" "${MODULE_DIR}"

echo "[+] Starting Amlogic GXL extraction..."

# Verify root access
echo "[*] Verifying root access..."
if ! adb shell su -c id | grep -q "uid=0"; then
    echo "[-] Root access not available. Exiting."
    exit 1
fi

# Key partitions for GXL device
PARTITIONS=(
    # name:start_sector:sector_count:description
    "bootloader:0:8192:BL1-BL33 bootloader chain"
    "boot:2154496:32768:Android boot image"
    "recovery:1941504:49152:Recovery partition"
    "system:2924544:3145728:Android system"
    "vendor:2334720:524288:Vendor partition"
    "dto:2039808:16384:Device tree overlay"
    "logo:1908736:16384:Boot logo"
    "misc:2007040:16384:Misc partition"
    "tee:2252800:65536:Trusted execution environment"
    "cri_data:2072576:16384:Critical data"
    "param:2105344:32768:Parameters"
    "rsv:2203648:32768:Reserved"
    "odm:2875392:32768:ODM partition"
)

echo "[*] Extracting symbols..."    
# Get full kernel symbol table
adb shell su -c "cat /proc/kallsyms" > "${SYMBOLS_DIR}/kallsyms.txt"
# Get module specific symbols
adb shell su -c "cat /sys/module/meson_ir/sections/.*" > "${SYMBOLS_DIR}/meson_ir_sections.txt"
# Try to get debug info
adb shell su -c "cat /sys/kernel/debug/meson-ir/*" > "${DEBUG_DIR}/ir_debug.txt" 2>/dev/null
# Get module dependencies
adb shell su -c "cat /proc/modules | grep meson" > "${SYMBOLS_DIR}/module_deps.txt"

echo "[*] Extracting driver files..."
    
# Find and pull the main driver
adb shell su -c "find /vendor/lib/modules -name 'meson-remote.ko'" | while read module; do
    echo "[*] Found module: ${module}"
    adb pull "${module}" "${MODULE_DIR}/"
    
    # Get module info
    adb shell su -c "modinfo ${module}" > "${DEBUG_DIR}/module_info.txt"
done
# Get any dependencies
adb shell su -c "ldd /vendor/lib/modules/meson-remote.ko" 2>/dev/null | while read dep; do
    if [[ $dep == /* ]]; then
        echo "[*] Pulling dependency: ${dep}"
        adb pull "${dep}" "${MODULE_DIR}/"
    fi
done


# Extract partitions
for part in "${PARTITIONS[@]}"; do
    IFS=':' read -r name start size desc <<< "$part"
    echo "[*] Dumping ${name} partition (${desc})..."
    
    # Direct DD with progress using pv if available
    adb shell su -c "dd if=/dev/block/platform/d0074000.emmc/${name} of=/data/local/tmp/${name}.img bs=512 count=${size} status=progress"
    adb pull "/data/local/tmp/${name}.img" "${IMAGES_DIR}/"
    adb shell su -c "rm /data/local/tmp/${name}.img"
    
    # Get partition info for debugging
    adb shell su -c "hexdump -C -n 512 /dev/block/platform/d0074000.emmc/${name}" > "${DEBUG_DIR}/${name}_header.hex"
done

# Extract DTB (important for Amlogic)
echo "[*] Extracting DTB..."
adb shell su -c "dd if=/dev/block/dtb of=/data/local/tmp/dtb.img"
adb pull "/data/local/tmp/dtb.img" "${IMAGES_DIR}/"

# Get essential debug info
echo "[*] Gathering debug info..."
adb shell su -c "cat /proc/cmdline" > "${DEBUG_DIR}/cmdline.txt"
adb shell su -c "dmesg" > "${DEBUG_DIR}/dmesg.txt"
adb shell su -c "cat /proc/mtd" > "${DEBUG_DIR}/mtd.txt"
adb shell su -c "cat /proc/partitions" > "${DEBUG_DIR}/partitions.txt"
adb shell su -c "cat /sys/firmware/devicetree/base/compatible" > "${DEBUG_DIR}/dt_compatible.txt"

# Create QEMU launch script
cat > "${DUMP_DIR}/run_amlogic.sh" << 'EOF'
#!/bin/bash
# QEMU script for Amlogic GXL S905X testing

MACHINE_OPTS="-M virt,secure=on -cpu cortex-a53 -smp 4 -m 2048"
# Memory layout matching device
MEM_OPTS="-global loader.addr=0x01080000"
# Drives with proper memory mapping
DRIVE_OPTS="-drive if=pflash,file=${IMAGES_DIR}/bootloader.img,format=raw \
            -drive if=none,file=${IMAGES_DIR}/system.img,id=systemdisk \
            -device virtio-blk-device,drive=systemdisk \
            -drive if=none,file=${IMAGES_DIR}/vendor.img,id=vendordisk \
            -device virtio-blk-device,drive=vendordisk"
BOOT_OPTS="-bios ${IMAGES_DIR}/boot.img"
DTB_OPTS="-dtb ${IMAGES_DIR}/dtb.img"
# Debug options enhanced
DEBUG_OPTS="-d unimp,guest_errors,int,mmu,exec \
            -D qemu.log \
            -monitor telnet:127.0.0.1:55555,server,nowait \
            -serial mon:stdio"
# Network for ADB
NET_OPTS="-netdev user,id=net0,hostfwd=tcp::5555-:5555 \
          -device virtio-net-device,netdev=net0"
# GPU disabled since we don't need it
DISPLAY_OPTS="-display none"

qemu-system-arm \
    ${MACHINE_OPTS} \
    ${MEM_OPTS} \
    ${DRIVE_OPTS} \
    ${BOOT_OPTS} \
    ${DTB_OPTS} \
    ${DEBUG_OPTS} \
    ${NET_OPTS} \
    ${DISPLAY_OPTS} \
    -nographic

# Debug commands:
# 1. Connect to monitor:
#    telnet localhost 55555
#
# 2. Attach GDB:
#    Add -s -S to command line
#    arm-none-eabi-gdb
#    (gdb) target remote localhost:1234
#
# 3. View full logs:
#    tail -f qemu.log
EOF

chmod +x "${DUMP_DIR}/run_amlogic.sh"

echo "[+] Setup complete! Check ${DUMP_DIR} for extracted files and QEMU script"
echo "
Key files needed for QEMU:
- ${IMAGES_DIR}/bootloader.img (contains BL1-BL33)
- ${IMAGES_DIR}/boot.img (kernel + initrd)
- ${IMAGES_DIR}/system.img (Android system)
- ${IMAGES_DIR}/vendor.img (Vendor partition)
- ${IMAGES_DIR}/recovery.img (Recovery partition)
- ${IMAGES_DIR}/dtb.img (Device Tree)

Additional extracted partitions:
- ${IMAGES_DIR}/tee.img (Trusted execution environment)
- ${IMAGES_DIR}/logo.img (Boot logo)
- ${IMAGES_DIR}/misc.img (Misc config)
- And others in ${IMAGES_DIR}/

To run:
1. cd ${DUMP_DIR}
2. ./run_amlogic.sh

For debugging:
- Check ${DEBUG_DIR} for partition headers and system info
- QEMU debug log will be in qemu.log
- ADB accessible on port 5555
- Connect GDB to debug boot process (use -s -S flags)
"