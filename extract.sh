#!/bin/bash
# Combined extraction script for Amlogic IR Analysis
# Supports: QEMU full system emulation, Qiling fuzzing, and Flipper verification

set -e

# Base directories
DUMP_DIR="amlogic_dump"
IMAGES_DIR="${DUMP_DIR}/images"
DEBUG_DIR="${DUMP_DIR}/debug"
ROOTFS_DIR="${DUMP_DIR}/rootfs"
SYMBOLS_DIR="${DUMP_DIR}/symbols"
MODULE_DIR="${ROOTFS_DIR}/lib/modules"
QILING_DIR="${DUMP_DIR}/qiling"
IR_PATTERNS="${DUMP_DIR}/ir_patterns"

# Parse arguments
MODE="both"
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--mode (both|qemu|qiling)]"
            exit 1
            ;;
    esac
done

# Validate mode
case $MODE in
    both|qemu|qiling) ;;
    *)
        echo "Invalid mode: $MODE"
        echo "Valid modes: both, qemu, qiling"
        exit 1
        ;;
esac

# Create directory structure
mkdir -p "${IMAGES_DIR}" "${DEBUG_DIR}" "${ROOTFS_DIR}" "${SYMBOLS_DIR}" \
         "${MODULE_DIR}" "${QILING_DIR}" "${IR_PATTERNS}/crashes"

echo "[+] Starting Amlogic GXL extraction (Mode: $MODE)..."

# Verify root access
echo "[*] Verifying root access..."
if ! adb shell su -c id | grep -q "uid=0"; then
    echo "[-] Root access not available. Exiting."
    exit 1
fi

# Original partition definitions
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

extract_symbols() {
    echo "[*] Extracting symbols..."    
    adb shell su -c "cat /proc/kallsyms" > "${SYMBOLS_DIR}/kallsyms.txt"
    adb shell su -c "cat /sys/module/meson_ir/sections/.*" > "${SYMBOLS_DIR}/meson_ir_sections.txt"
    adb shell su -c "cat /sys/kernel/debug/meson-ir/*" > "${DEBUG_DIR}/ir_debug.txt" 2>/dev/null || true
    adb shell su -c "cat /proc/modules | grep meson" > "${SYMBOLS_DIR}/module_deps.txt"    
    adb shell su -c "ls -R /lib/firmware/" > "${SYMBOLS_DIR}/firmware_files.txt"

    echo "[*] Extracting register and memory info..."
    adb shell su -c "cat /proc/iomem | grep -A 20 'c8100580.*meson-ir'" > "${SYMBOLS_DIR}/register_map.txt"
    adb shell su -c "od -tx4 -v /dev/mem" 2>/dev/null | grep -A 20 "c8100580" > "${SYMBOLS_DIR}/register_state.txt" || true
}

extract_driver() {
    echo "[*] Extracting driver files..."
    adb shell su -c "find /vendor/lib/modules -name 'meson-remote.ko'" | while read module; do
        echo "[*] Found module: ${module}"
        adb pull "${module}" "${MODULE_DIR}/"
        adb shell su -c "modinfo ${module}" > "${DEBUG_DIR}/module_info.txt"
    done

    adb shell su -c "ldd /vendor/lib/modules/meson-remote.ko" 2>/dev/null | while read dep; do
        if [[ $dep == /* ]]; then
            echo "[*] Pulling dependency: ${dep}"
            adb pull "${dep}" "${MODULE_DIR}/"
        fi
    done
}

extract_partitions() {
    if [ "$MODE" = "qiling" ]; then
        return
    fi

    for part in "${PARTITIONS[@]}"; do
        IFS=':' read -r name start size desc <<< "$part"
        echo "[*] Dumping ${name} partition (${desc})..."
        
        adb shell su -c "dd if=/dev/block/platform/d0074000.emmc/${name} of=/data/local/tmp/${name}.img bs=512 count=${size} status=progress"
        adb pull "/data/local/tmp/${name}.img" "${IMAGES_DIR}/"
        adb shell su -c "rm /data/local/tmp/${name}.img"
        
        adb shell su -c "hexdump -C -n 512 /dev/block/platform/d0074000.emmc/${name}" > "${DEBUG_DIR}/${name}_header.hex"
    done

    echo "[*] Extracting DTB..."
    adb shell su -c "dd if=/dev/block/dtb of=/data/local/tmp/dtb.img"
    adb pull "/data/local/tmp/dtb.img" "${IMAGES_DIR}/"
}

gather_debug_info() {
    echo "[*] Gathering debug info..."
    adb shell su -c "cat /proc/cmdline" > "${DEBUG_DIR}/cmdline.txt"
    adb shell su -c "dmesg" > "${DEBUG_DIR}/dmesg.txt"
    adb shell su -c "cat /proc/mtd" > "${DEBUG_DIR}/mtd.txt"
    adb shell su -c "cat /proc/partitions" > "${DEBUG_DIR}/partitions.txt"
    adb shell su -c "cat /sys/firmware/devicetree/base/compatible" > "${DEBUG_DIR}/dt_compatible.txt"
}

generate_qemu_script() {
    if [ "$MODE" = "qiling" ]; then
        return
    fi

    cat > "${DUMP_DIR}/qemu_amlogic.sh" << 'EOF'
#!/bin/bash
# QEMU script for Amlogic GXL S905X testing

MACHINE_OPTS="-M virt,secure=on -cpu cortex-a53 -smp 4 -m 2048"
MEM_OPTS="-global loader.addr=0x01080000"
DRIVE_OPTS="-drive if=pflash,file=${IMAGES_DIR}/bootloader.img,format=raw \
            -drive if=none,file=${IMAGES_DIR}/system.img,id=systemdisk \
            -device virtio-blk-device,drive=systemdisk \
            -drive if=none,file=${IMAGES_DIR}/vendor.img,id=vendordisk \
            -device virtio-blk-device,drive=vendordisk"
BOOT_OPTS="-bios ${IMAGES_DIR}/boot.img"
DTB_OPTS="-dtb ${IMAGES_DIR}/dtb.img"
DEBUG_OPTS="-d unimp,guest_errors,int,mmu,exec \
            -D qemu.log \
            -monitor telnet:127.0.0.1:55555,server,nowait \
            -serial mon:stdio"
NET_OPTS="-netdev user,id=net0,hostfwd=tcp::5555-:5555 \
          -device virtio-net-device,netdev=net0"
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
EOF
    chmod +x "${DUMP_DIR}/qemu_amlogic.sh"
}

generate_qiling_scripts() {
    if [ "$MODE" = "qemu" ]; then
        return
    fi

    # Generate main fuzzing script
    cat > "${QILING_DIR}/fuzz_meson_ir.py" << 'EOF'
#!/usr/bin/env python3
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap
import sys, os

class MesonIRFuzzer:
    def __init__(self, rootfs_dir, module_dir):
        self.rootfs = rootfs_dir
        self.module = f"{module_dir}/meson-remote.ko"
        self.reg_base = 0xc8100580
        
    def setup_qiling(self):
        ql = Qiling([self.module], self.rootfs, verbose=QL_VERBOSE.DEBUG)
        
        # Enable sanitizer
        ql.os.heap = QlSanitizedMemoryHeap(ql)
        
        # Map IR registers
        ql.mem.map(self.reg_base & ~0xfff, 0x1000)
        
        # Load symbols
        self.load_symbols(ql)
        
        return ql
        
    def load_symbols(self, ql):
        with open(f"{os.path.dirname(self.rootfs)}/symbols/kallsyms.txt") as f:
            for line in f:
                if not line.strip(): continue
                addr, type, name = line.strip().split()
                if name.startswith('meson_ir'):
                    ql.sym.add_symbol(int(addr, 16), name)

    def fuzz(self, input_file):
        ql = self.setup_qiling()
        with open(input_file, 'rb') as f:
            data = f.read()
        
        try:
            self.process_input(ql, data)
        except Exception as e:
            print(f"Crash detected: {e}")
            self.save_crash(data, str(e))

    def process_input(self, ql, data):
        # Simulate IR packet reception
        duration = int.from_bytes(data[:4], 'little') if len(data) >= 4 else 0
        pulse = bool(data[4] & 1) if len(data) >= 5 else False
        
        # Write to emulated registers
        ql.mem.write(self.reg_base + 0x1c, duration.to_bytes(4, 'little'))
        ql.mem.write(self.reg_base + 0x18, (int(pulse) << 8).to_bytes(4, 'little'))
        
        # Call IRQ handler
        irq_handler = ql.sym.get_symbol('meson_ir_irq')
        if irq_handler:
            ql.run(begin=irq_handler)

    def save_crash(self, data, error):
        crash_file = f"ir_patterns/crashes/crash_{hex(hash(data))}.bin"
        with open(crash_file, 'wb') as f:
            f.write(data)
        print(f"Saved crash input to {crash_file}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        return
    
    fuzzer = MesonIRFuzzer("rootfs", "rootfs/lib/modules")
    fuzzer.fuzz(sys.argv[1])

if __name__ == "__main__":
    main()
EOF

    # Generate Flipper verification script
    cat > "${QILING_DIR}/verify_flipper.py" << 'EOF'
#!/usr/bin/env python3
import serial
import time
import sys

def verify_crash(port, crash_file):
    ser = serial.Serial(port, 115200)
    
    with open(crash_file, 'rb') as f:
        data = f.read()
    
    # Convert binary crash data to IR pattern
    duration = int.from_bytes(data[:4], 'little') if len(data) >= 4 else 0
    pulse = bool(data[4] & 1) if len(data) >= 5 else False
    
    # Send to Flipper
    cmd = f"ir_tx raw {duration}{'1' if pulse else '0'}"
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(0.1)
    
    print(f"Sent crash pattern: duration={duration}, pulse={pulse}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <flipper_port> <crash_file>")
        sys.exit(1)
    verify_crash(sys.argv[1], sys.argv[2])
EOF

    chmod +x "${QILING_DIR}/fuzz_meson_ir.py" "${QILING_DIR}/verify_flipper.py"
}

main() {
    extract_symbols
    extract_driver
    extract_partitions
    gather_debug_info
    generate_qemu_script
    generate_qiling_scripts
    
    echo "[+] Extraction complete! Directory structure:"
    tree "${DUMP_DIR}"
    
    case $MODE in
        both)
            echo "Both QEMU and Qiling environments prepared"
            echo "1. For QEMU: cd ${DUMP_DIR} && ./qemu_amlogic.sh"
            echo "2. For Qiling: cd ${QILING_DIR} && ./fuzz_meson_ir.py <input_file>"
            ;;
        qemu)
            echo "QEMU environment prepared"
            echo "Run: cd ${DUMP_DIR} && ./qemu_amlogic.sh"
            ;;
        qiling)
            echo "Qiling environment prepared"
            echo "1. Fuzz: cd ${QILING_DIR} && ./fuzz_meson_ir.py <input_file>"
            echo "2. Verify crashes with Flipper: ./verify_flipper.py <port> <crash_file>"
            ;;
    esac
}

main