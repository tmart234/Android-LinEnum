#!/bin/bash
# Complete S905X (GXL) Security Research & Modification Tool
# Combines amlogic-usbdl and gxlimg functionality
# Specifically for: Ematic/DV8235_Ematic/DV8235:8.1.0

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Device specific constants
DEVICE_NAME="DV8235"
ANDROID_VERSION="8.1.0"
BUILD_ID="NHG47L"
SOC_TYPE="GXL"
USB_VID="1b8e"
USB_PID="c003"
UART_PORT="/dev/ttyUSB0"
UART_BAUD="115200"

# Directory setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="s905x_research_${TIMESTAMP}"
BACKUP_DIR="${WORK_DIR}/backups"
DUMP_DIR="${WORK_DIR}/dumps"
KEYS_DIR="${WORK_DIR}/keys"
DECRYPT_DIR="${WORK_DIR}/decrypted"
MODIFIED_DIR="${WORK_DIR}/modified"
LOG_DIR="${WORK_DIR}/logs"

setup_directories() {
    echo -e "${GREEN}[+] Setting up working directories${NC}"
    mkdir -p "$BACKUP_DIR" "$DUMP_DIR" "$KEYS_DIR" "$DECRYPT_DIR" "$MODIFIED_DIR" "$LOG_DIR"
}

# SMC module setup
setup_smc_module() {
    echo -e "${GREEN}[+] Setting up SMC access module${NC}"
    
    # Create module directory
    mkdir -p "${WORK_DIR}/smc_module"
    
    # Create smc_access.c
    cat > "${WORK_DIR}/smc_module/smc_access.c" << 'EOF'
/* SMC access module code as provided */
EOF
    
    # Create Makefile
    cat > "${WORK_DIR}/smc_module/Makefile" << 'EOF'
obj-m := smc_access.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
EOF
    
    # Build module
    (cd "${WORK_DIR}/smc_module" && make)
}

install_dependencies() {
    echo -e "${GREEN}[+] Installing required dependencies${NC}"
    sudo apt-get update
    sudo apt-get install -y git python3-pip adb fastboot build-essential \
        gcc-aarch64-linux-gnu device-tree-compiler python3-serial \
        libusb-1.0-0-dev pkg-config

    # Clone required repositories
    git clone https://github.com/frederic/amlogic-usbdl.git
    git clone https://github.com/repk/gxlimg.git
    git clone https://github.com/superna9999/pyamlboot.git

    # Build tools
    (cd gxlimg && make)
    (cd amlogic-usbdl && make)
    pip3 install --user pyamlboot pyserial
}

check_usb_dl_mode() {
    echo -e "${BLUE}[*] Checking USB download mode status${NC}"
    if lsusb | grep -q "${USB_VID}:${USB_PID}"; then
        echo -e "${GREEN}[+] Device detected in USB download mode${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Device not in USB download mode${NC}"
        echo "Instructions to enter USB download mode:"
        echo "1. Power off device completely"
        echo "2. Locate the AV/reset hole"
        echo "3. Use a paperclip/pin to hold the button while connecting USB"
        echo "4. Keep holding for 10 seconds after connecting"
        return 1
    fi
}

dump_bootrom() {
    echo -e "${GREEN}[+] Dumping BootROM${NC}"
    cat > ${DUMP_DIR}/bootrom_dump.s << 'EOF'
    .global _start
_start:
    // S905X BootROM range: 0xFFFF0000 - 0xFFFFFFFF
    mov x0, #0xffff0000    // Start address
    mov x1, #0x10000       // 64KB size
    
dump_loop:
    ldrb w2, [x0]         // Load byte
    bl uart_putc          // Send via UART
    add x0, x0, #1        // Next address
    subs x1, x1, #1       // Decrement counter
    bne dump_loop
    ret

uart_putc:
    // S905X UART registers
    mov x3, #0xff803000   // UART base
1:  
    ldr w4, [x3, #0xc]    // Load status
    tbz w4, #21, 1b       // Check if TX ready
    str w2, [x3]          // Send byte
    ret
EOF

    # Compile bootrom dumper
    aarch64-linux-gnu-as ${DUMP_DIR}/bootrom_dump.s -o ${DUMP_DIR}/bootrom_dump.o
    aarch64-linux-gnu-objcopy -O binary ${DUMP_DIR}/bootrom_dump.o ${DUMP_DIR}/bootrom_dump.bin
    
    echo -e "${BLUE}[*] Executing BootROM dump payload${NC}"
    ./amlogic-usbdl/amlogic-usbdl ${DUMP_DIR}/bootrom_dump.bin ${DUMP_DIR}/bootrom.bin
}

dump_efuse() {
    echo -e "${GREEN}[+] Dumping eFuse data${NC}"
    cat > ${DUMP_DIR}/efuse_dump.s << 'EOF'
    .global _start
_start:
    // S905X eFuse base: 0xff800000
    mov x0, #0xff800000
    mov x1, #0x1000      // 4KB size
    
read_efuse:
    ldr w2, [x0]        // Read 32-bit word
    bl uart_put_hex     // Send as hex
    add x0, x0, #4      // Next word
    subs x1, x1, #4     // Decrement size
    bne read_efuse
    ret

uart_put_hex:
    // Implement hex output via UART
    mov x3, #8          // 8 hex digits
1:  
    ror w4, w2, #28     // Get top nibble
    and w4, w4, #0xf    // Mask
    cmp w4, #10         // Convert to ASCII
    add w4, w4, #'0'    
    cmp w4, #'9'
    ble 2f
    add w4, w4, #39     // Adjust for A-F
2:  
    bl uart_putc        // Output character
    lsl w2, w2, #4      // Next nibble
    subs x3, x3, #1     // Count down
    bne 1b
    ret

uart_putc:
    mov x5, #0xff803000
3:  
    ldr w6, [x5, #0xc]
    tbz w6, #21, 3b
    str w4, [x5]
    ret
EOF

    # Compile efuse dumper
    aarch64-linux-gnu-as ${DUMP_DIR}/efuse_dump.s -o ${DUMP_DIR}/efuse_dump.o
    aarch64-linux-gnu-objcopy -O binary ${DUMP_DIR}/efuse_dump.o ${DUMP_DIR}/efuse_dump.bin
    
    echo -e "${BLUE}[*] Executing eFuse dump payload${NC}"
    ./amlogic-usbdl/amlogic-usbdl ${DUMP_DIR}/efuse_dump.bin ${DUMP_DIR}/efuse.bin
}

# Function to dump memory using SMC
dump_memory_smc() {
    local start_addr=$1
    local size=$2
    local output_file=$3
    
    echo -e "${BLUE}[*] Dumping memory via SMC from ${start_addr} size ${size}${NC}"
    
    # Load SMC module if not loaded
    if ! lsmod | grep -q "smc_access"; then
        insmod "${WORK_DIR}/smc_module/smc_access.ko"
    fi
    
    # Create dump script
    cat > "${WORK_DIR}/dump_smc.sh" << EOF
#!/bin/bash
for addr in \$(seq -f %1.f ${start_addr} 4 $((start_addr + size - 4))); do
    printf "Reading 0x%x\n" \$addr >&2
    echo "82000018 \$addr" > /sys/kernel/debug/aml_smc/smc
done
EOF
    chmod +x "${WORK_DIR}/dump_smc.sh"
    
    # Execute dump and parse output
    ${WORK_DIR}/dump_smc.sh 2>/dev/null | while read line; do
        if [[ $line =~ "returns: "([[:xdigit:]]+) ]]; then
            printf "%08x\n" "${BASH_REMATCH[1]}" >> "${output_file}.txt"
        fi
    done
    
    # Convert to binary
    xxd -r -p "${output_file}.txt" > "${output_file}"
    rm "${output_file}.txt"
}

# Function to dump bootrom using SMC
dump_bootrom_smc() {
    echo -e "${GREEN}[+] Attempting bootROM dump via SMC${NC}"
    
    # BootROM address range for S905X
    local bootrom_start=0xD9040000
    local bootrom_size=0x10000  # 64KB
    
    dump_memory_smc $bootrom_start $bootrom_size "${DUMP_DIR}/bootrom_smc.bin"
    
    # Verify dump
    if verify_dump "${DUMP_DIR}/bootrom_smc.bin" $bootrom_size; then
        echo -e "${GREEN}[+] BootROM dump successful${NC}"
        # Create SHA1 for comparison
        sha1sum "${DUMP_DIR}/bootrom_smc.bin" > "${DUMP_DIR}/bootrom_smc.sha1"
    else
        echo -e "${RED}[-] BootROM dump failed${NC}"
    fi
}

# Function to dump efuse using SMC
dump_efuse_smc() {
    echo -e "${GREEN}[+] Attempting eFuse dump via SMC${NC}"
    
    # eFuse address range
    local efuse_start=0xff800000
    local efuse_size=0x1000  # 4KB
    
    dump_memory_smc $efuse_start $efuse_size "${DUMP_DIR}/efuse_smc.bin"
}

extract_keys() {
    echo -e "${GREEN}[+] Extracting encryption keys${NC}"
    # Extract AES keys from SRAM
    ./gxlimg/gxlimg -t keys -i ${DUMP_DIR}/efuse.bin ${KEYS_DIR}/keys.bin
    
    # Try to extract root RSA keys if available
    if [ -f "${DUMP_DIR}/bootrom.bin" ]; then
        dd if=${DUMP_DIR}/bootrom.bin of=${KEYS_DIR}/rsa_keys.bin bs=1 skip=$((0x8000)) count=1024
    fi
}

dump_bootloader() {
    echo -e "${GREEN}[+] Dumping complete bootloader${NC}"
    
    # Dump BL2
    adb shell "dd if=/dev/mtd0 of=/data/local/tmp/bl2.bin"
    adb pull /data/local/tmp/bl2.bin ${DUMP_DIR}/
    
    # Dump FIP
    adb shell "dd if=/dev/mtd1 of=/data/local/tmp/fip.bin"
    adb pull /data/local/tmp/fip.bin ${DUMP_DIR}/
    
    # Extract FIP components
    ./gxlimg/gxlimg -t fip -x ${DUMP_DIR}/fip.bin ${DUMP_DIR}/fip/
}

decrypt_bootloader() {
    echo -e "${GREEN}[+] Decrypting bootloader components${NC}"
    
    # Decrypt BL2
    ./gxlimg/gxlimg -t bl2 -d ${DUMP_DIR}/bl2.bin ${DECRYPT_DIR}/bl2.dec
    
    # Decrypt FIP components
    for comp in bl30 bl31 bl33; do
        if [ -f "${DUMP_DIR}/fip/${comp}.bin" ]; then
            ./gxlimg/gxlimg -t bl3x -d ${DUMP_DIR}/fip/${comp}.bin ${DECRYPT_DIR}/${comp}.dec
        fi
    done
}

modify_security() {
    echo -e "${GREEN}[+] Preparing security modifications${NC}"
    
    # Copy decrypted files for modification
    cp ${DECRYPT_DIR}/* ${MODIFIED_DIR}/
    
    # Disable verified boot in BL2
    if [ -f "${MODIFIED_DIR}/bl2.dec" ]; then
        sed -i 's/verified-boot=enforcing/verified-boot=disabled/g' ${MODIFIED_DIR}/bl2.dec
    fi
    
    # Modify U-Boot (BL33) parameters
    if [ -f "${MODIFIED_DIR}/bl33.dec" ]; then
        sed -i 's/avb=enable/avb=disable/g' ${MODIFIED_DIR}/bl33.dec
        sed -i 's/ro.debuggable=0/ro.debuggable=1/g' ${MODIFIED_DIR}/bl33.dec
        sed -i 's/ro.adb.secure=1/ro.adb.secure=0/g' ${MODIFIED_DIR}/bl33.dec
    fi
}

rebuild_boot_image() {
    echo -e "${GREEN}[+] Rebuilding boot image${NC}"
    
    # Re-encrypt modified components
    ./gxlimg/gxlimg -t bl2 -s ${MODIFIED_DIR}/bl2.dec ${MODIFIED_DIR}/bl2.enc
    
    for comp in bl30 bl31 bl33; do
        if [ -f "${MODIFIED_DIR}/${comp}.dec" ]; then
            ./gxlimg/gxlimg -t bl3x -c ${MODIFIED_DIR}/${comp}.dec ${MODIFIED_DIR}/${comp}.enc
        fi
    done
    
    # Create final FIP image
    ./gxlimg/gxlimg -t fip \
        --bl2 ${MODIFIED_DIR}/bl2.enc \
        --bl30 ${MODIFIED_DIR}/bl30.enc \
        --bl31 ${MODIFIED_DIR}/bl31.enc \
        --bl33 ${MODIFIED_DIR}/bl33.enc \
        ${MODIFIED_DIR}/new-boot.bin
}

create_usb_boot() {
    echo -e "${GREEN}[+] Creating USB boot files${NC}"
    
    # Split for USB boot
    dd if=${MODIFIED_DIR}/new-boot.bin of=${MODIFIED_DIR}/u-boot.bin.usb.bl2 bs=49152 count=1
    dd if=${MODIFIED_DIR}/new-boot.bin of=${MODIFIED_DIR}/u-boot.bin.usb.tpl skip=49152 bs=1
    
    # Copy to pyamlboot directory
    mkdir -p pyamlboot/files/${DEVICE_NAME}
    cp ${MODIFIED_DIR}/u-boot.bin.usb.bl2 pyamlboot/files/${DEVICE_NAME}/
    cp ${MODIFIED_DIR}/u-boot.bin.usb.tpl pyamlboot/files/${DEVICE_NAME}/
}

flash_modified_boot() {
    echo -e "${RED}[!] WARNING: This will modify your device bootloader${NC}"
    echo -e "${RED}[!] Make sure you have backups and understand the risks${NC}"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*] Flashing modified boot image${NC}"
        adb wait-for-device
        adb shell "dd if=/dev/zero of=/dev/mtd0 bs=1M count=1"
        adb shell "dd if=/dev/zero of=/dev/mtd1 bs=1M count=1"
        adb push ${MODIFIED_DIR}/new-boot.bin /data/local/tmp/
        adb shell "dd if=/data/local/tmp/new-boot.bin of=/dev/mtd0 bs=512 seek=1"
    fi
}

# Function to modify BL31 and bypass verification
modify_bl31() {
    echo -e "${GREEN}[+] Modifying BL31 image${NC}"
    
    # Extract BL31
    ./gxlimg/gxlimg -t bl3x -d "${DUMP_DIR}/fip.bin" "${MODIFIED_DIR}/bl31.dec"
    
    # Modify signature type to SHA-256
    sed -i 's/sig_type\x00\x00\x00\x01/sig_type\x00\x00\x00\x00/' "${MODIFIED_DIR}/bl31.dec"
    
    # Remove memory access restrictions in hdcp22_sec_read_reg
    # Convert restrictions to NOP
    sed -i 's/\x1f\x03\x00\x71/\x1f\x20\x03\xd5/' "${MODIFIED_DIR}/bl31.dec"
    
    # Extend MMU mappings to include BootROM
    # Modify mapped region size from 0x40000 to 0x80000
    sed -i 's/\x00\x00\x04\x00/\x00\x00\x08\x00/' "${MODIFIED_DIR}/bl31.dec"
    
    # Regenerate SHA-256
    ./aml_bootloader_tool "${MODIFIED_DIR}/bl31.dec" H 2
}

# Function to extract all necessary QEMU data
extract_qemu_data() {
    echo -e "${GREEN}[+] Extracting all data needed for QEMU${NC}"
    
    local QEMU_DIR="${WORK_DIR}/qemu_data"
    mkdir -p "${QEMU_DIR}"
    
    # 1. Core memory regions for S905X
    local MEMORY_REGIONS=(
        "0xFFFF0000 0x10000 bootrom"      # Main BootROM
        "0xFFFE0020 0x100 aes_storage"    # AES key storage
        "0xFFFE3800 0x800 stack_mem"      # Stack memory start
        "0xFFFA0000 0x10000 dl_buffer"    # Download buffer
        "0xff800000 0x1000 efuse"         # eFuse
        "0xc0000000 0x1000000 secmon"     # Secure monitor
        "0xff800000 0x100 arb_counters"   # Anti-rollback counters
        "0xffff0000 0x1000 sec_patterns"  # Security patterns
    )

    # 2. Dump all memory regions
    for region in "${MEMORY_REGIONS[@]}"; do
        read addr size name <<< "$region"
        echo -e "${BLUE}[*] Dumping $name region (${addr}, size: ${size})${NC}"
        dump_memory_smc $addr $size "${QEMU_DIR}/${name}.bin"
        
        # Verify dump
        if verify_dump "${QEMU_DIR}/${name}.bin" $((size)); then
            echo -e "${GREEN}[+] Successfully dumped ${name}${NC}"
        else
            echo -e "${RED}[-] Failed to dump ${name}${NC}"
        fi
    done

    # 3. Extract secure monitor calls table
    echo -e "${BLUE}[*] Mapping SMC calls${NC}"
    for smc_id in $(seq 0x82000000 0x82000100); do
        echo "Testing SMC 0x${smc_id}"
        echo "${smc_id} 0 0 0 0" > /sys/kernel/debug/aml_smc/smc
    done > "${QEMU_DIR}/smc_calls.txt"

    # 4. Extract crypto keys and IV if BL2 available
    if [ -f "${DUMP_DIR}/bl2.bin" ]; then
        echo -e "${BLUE}[*] Extracting crypto keys from BL2${NC}"
        ./gxlimg/gxlimg -t keys -i "${DUMP_DIR}/bl2.bin" "${QEMU_DIR}/crypto_keys.bin"
    fi

    # 5. Create QEMU config
    cat > "${QEMU_DIR}/s905x.cfg" << EOF
[platform]
soc=s905x
bootrom_file=bootrom.bin
efuse_file=efuse.bin
secmon_file=secmon.bin
stack_mem_file=stack_mem.bin
aes_storage_file=aes_storage.bin
dl_buffer_file=dl_buffer.bin

[crypto]
keys_file=crypto_keys.bin

[security]
arb_counters_file=arb_counters.bin
security_patterns_file=sec_patterns.bin

[memory_map]
0xFFFF0000 bootrom    0x10000
0xFFFE0020 aes        0x100
0xFFFE3800 stack      0x800
0xFFFA0000 dl_buffer  0x10000
0xff800000 efuse      0x1000
0xc0000000 secmon     0x1000000
0xff800000 arb        0x100
0xffff0000 patterns   0x1000

[smc_handlers]
file=smc_calls.txt
EOF

    # 6. Package everything
    tar -czf "${WORK_DIR}/qemu_package.tar.gz" -C "${QEMU_DIR}" .
    
    echo -e "${GREEN}[+] QEMU data package created: ${WORK_DIR}/qemu_package.tar.gz${NC}"
    echo -e "${BLUE}[*] Package contains:"
    echo -e "    - Full memory dumps for all critical regions"
    echo -e "    - Security patterns and ARB counters"
    echo -e "    - SMC call mapping"
    echo -e "    - Crypto keys and IV"
    echo -e "    - QEMU configuration file${NC}"
}

cleanup() {
    echo -e "${GREEN}[+] Cleaning up temporary files${NC}"
    rm -f ${DUMP_DIR}/*.o
    echo -e "${BLUE}[*] All files preserved in ${WORK_DIR}${NC}"
}

show_menu() {
    while true; do
        echo -e "\n${GREEN}=== S905X Complete Security Research Tool ===${NC}"
        echo -e "${BLUE}Device: ${DEVICE_NAME} (${SOC_TYPE})${NC}"
        echo -e "${BLUE}Android: ${ANDROID_VERSION} (${BUILD_ID})${NC}"
        echo
        echo "1.  Install Dependencies"
        echo "2.  Check USB Download Mode"
        echo "3.  Dump BootROM"
        echo "4.  Dump eFuse"
        echo "5.  Extract Keys"
        echo "6.  Dump Bootloader"
        echo "7.  Decrypt Bootloader"
        echo "8.  Modify Security Settings"
        echo "9.  Rebuild Boot Image"
        echo "10. Create USB Boot Files"
        echo "11. Flash Modified Boot"
        echo "12. Full Chain (2-7)"
        echo "13. Full Modification Chain (8-11)"
        echo "14. Extract QEMU Requirements"
        echo "15. Setup SMC Module"
        echo "16. Dump BootROM (SMC)"
        echo "17. Dump eFuse (SMC)"
        echo "18. Modify BL31 (Bypass Verification)"
        echo "19. Exit"

        read -p "Select option (1-14): " choice
        
        case $choice in
            1) install_dependencies ;;
            2) check_usb_dl_mode ;;
            3) dump_bootrom ;;
            4) dump_efuse ;;
            5) extract_keys ;;
            6) dump_bootloader ;;
            7) decrypt_bootloader ;;
            8) modify_security ;;
            9) rebuild_boot_image ;;
            10) create_usb_boot ;;
            11) flash_modified_boot ;;
            12) 
                check_usb_dl_mode && \
                dump_bootrom && \
                dump_efuse && \
                extract_keys && \
                dump_bootloader && \
                decrypt_bootloader
                ;;
            13)
                modify_security && \
                rebuild_boot_image && \
                create_usb_boot && \
                flash_modified_boot
                ;;
            14) extract_qemu_data ;;
            15) setup_smc_module ;;
            16) dump_bootrom_smc ;;
            17) dump_efuse_smc ;;
            18) modify_bl31 ;;
            19) cleanup; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
    done
}

# Logger function
log() {
    local level=$1
    shift
    local message=$@
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_DIR}/operation.log"
}

# Error handler
handle_error() {
    local exit_code=$?
    local line_number=$1
    log "ERROR" "Error occurred in line ${line_number}, exit code ${exit_code}"
    echo -e "${RED}[!] Operation failed! Check ${LOG_DIR}/operation.log for details${NC}"
}

# Backup function
create_backup() {
    local component=$1
    local source=$2
    log "INFO" "Creating backup of ${component}"
    cp "${source}" "${BACKUP_DIR}/${component}_backup_${TIMESTAMP}"
}

# Verify dumps
verify_dump() {
    local file=$1
    local expected_size=$2
    local actual_size=$(stat -c%s "$file" 2>/dev/null)
    
    if [ ! -f "$file" ] || [ "$actual_size" != "$expected_size" ]; then
        log "ERROR" "Dump verification failed for ${file}"
        return 1
    fi
    log "INFO" "Dump verified: ${file}"
    return 0
}

# Check for root/sudo
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "This script requires root privileges"
        echo -e "${RED}[!] Please run with sudo${NC}"
        exit 1
    fi
}

# Device specific configurations
load_device_config() {
    log "INFO" "Loading device configuration for ${DEVICE_NAME}"
    # Add any device-specific configurations here
    case ${DEVICE_NAME} in
        "DV8235")
            BOOTROM_SIZE=65536
            EFUSE_SIZE=4096
            BL2_OFFSET=0
            FIP_OFFSET=0xc000
            ;;
        *)
            log "ERROR" "Unknown device ${DEVICE_NAME}"
            exit 1
            ;;
    esac
}

# Progress bar
show_progress() {
    local current=$1
    local total=$2
    local prefix=$3
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r%s [%${completed}s%${remaining}s] %d%%" "$prefix" | tr ' ' '=' | tr ' ' '-' "$percentage"
}

# Main execution
main() {
    # Set up error handling
    trap 'handle_error ${LINENO}' ERR
    
    # Check for root privileges
    check_privileges
    
    # Create working directories
    setup_directories
    
    # Start logging
    log "INFO" "Starting S905X Security Research Tool v1.0"
    log "INFO" "Device: ${DEVICE_NAME}"
    log "INFO" "Android: ${ANDROID_VERSION}"
    log "INFO" "Build: ${BUILD_ID}"
    
    # Load device configuration
    load_device_config
    
    # Create initial backup of critical partitions if accessible
    if adb devices | grep -q "device$"; then
        log "INFO" "Creating initial backup of critical partitions"
        create_backup "mtd0" "/dev/mtd0"
        create_backup "mtd1" "/dev/mtd1"
    fi
    
    # Save system information
    {
        echo "Device Information:"
        echo "==================="
        echo "Model: ${DEVICE_NAME}"
        echo "Android Version: ${ANDROID_VERSION}"
        echo "Build ID: ${BUILD_ID}"
        echo "SOC Type: ${SOC_TYPE}"
        echo "Timestamp: ${TIMESTAMP}"
        echo
        echo "System Properties:"
        echo "=================="
        adb shell getprop | sort
    } > "${LOG_DIR}/system_info.txt"
    
    # Show menu and handle operations
    show_menu
    
    # Cleanup on exit
    cleanup
    
    log "INFO" "Operations completed successfully"
    echo -e "${GREEN}[+] All operations completed${NC}"
    echo -e "${BLUE}[*] Results saved in ${WORK_DIR}${NC}"
    echo -e "${YELLOW}[!] Don't forget to check logs in ${LOG_DIR}${NC}"
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi