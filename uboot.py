import serial
import time
import re
from typing import Optional, Dict, Set, List, Tuple
from dataclasses import dataclass
import logging
from enum import Enum
import json

# tool to:
# - disable selinux and verity mode
# - mmc enumeration

class BootSettings:
    def __init__(self):
        self.original_values = {}
        self.supported_vars = {
            'bootdelay': True,
            'bootretry': False,
            'bootcount': False,
            'bootlimit': False,
            'timeout': False
        }

class MMCInfo:
    def __init__(self):
        self.devices = []  # List of MMC device numbers found
        self.partitions = {}  # Dict of device -> list of partitions
        self.current_device = None
        self.command_support = {
            'mmc': False,
            'list': False,
            'part': False,
            'rescan': False
        }

class SecurityType(Enum):
    SELINUX = "selinux"
    VERITY = "verity"

@dataclass
class SecuritySetting:
    value: str
    source_var: str
    depth: int
    path: List[str]

class UBootVersion:
    V1_1 = "1.1"
    V1_3 = "1.3"
    UNKNOWN = "unknown"

class UBootSecurityTracer:
    def __init__(self, port: str = '/dev/ttyUSB0', baudrate: int = 115200, 
                 timeout: int = 1, max_depth: int = 5, max_retries: int = 3):
        self.logger = logging.getLogger('UBootTracer')
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_retries = max_retries
        self.ser = None
        self.env_vars = {}
        self.uboot_version = UBootVersion.UNKNOWN
        self.vendor = "unknown"
        
        # Known patterns for different vendors
        self.vendor_patterns = {
            'amlogic': [r'gxl_', r'g12', r'meson'],
            'rockchip': [r'rk3', r'rockchip'],
            'allwinner': [r'sun\d+i', r'allwinner'],
        }
        
        # Common bootargs variable names by vendor
        self.bootargs_vars = {
            'amlogic': ['bootargs', 'initargs', 'bootargs_common'],
            'rockchip': ['bootargs', 'bootargs_ext'],
            'allwinner': ['bootargs', 'boot_args'],
            'default': ['bootargs', 'bootargs_common', 'cmdline']
        }

    def connect(self) -> bool:
        """Establish serial connection with retry mechanism."""
        for attempt in range(self.max_retries):
            try:
                self.ser = serial.Serial(
                    port=self.port,
                    baudrate=self.baudrate,
                    timeout=self.timeout,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE
                )
                self.logger.info(f"Connected to {self.port} (attempt {attempt + 1})")
                return True
            except serial.SerialException as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {str(e)}")
                time.sleep(1)
        
        self.logger.error(f"Failed to connect after {self.max_retries} attempts")
        return False
    
        def enumerate_mmc_devices(self) -> Optional[MMCInfo]:
            """
            Enumerate MMC devices and their partitions.
            Adapts to different U-Boot versions and command support.
            """
        mmc_info = MMCInfo()

        # First check if mmc command is available
        help_output = self.send_command("help mmc")
        if not help_output or "unknown command" in help_output.lower():
            self.logger.info("MMC command not supported on this device")
            return None

        mmc_info.command_support['mmc'] = True

        # Get mmc command usage
        mmc_usage = self.send_command("mmc")
        if mmc_usage:
            # Check for supported subcommands
            mmc_info.command_support.update({
                'list': 'list' in mmc_usage.lower(),
                'part': 'part' in mmc_usage.lower(),
                'rescan': 'rescan' in mmc_usage.lower()
            })

        # Try to rescan MMC devices first
        if mmc_info.command_support['rescan']:
            self.send_command("mmc rescan", wait_time=2)

        # Get list of MMC devices
        if mmc_info.command_support['list']:
            # Modern U-Boot with mmc list command
            list_output = self.send_command("mmc list")
            if list_output and "no mmc devices" not in list_output.lower():
                # Parse devices from list output
                for line in list_output.split('\n'):
                    if ':' in line:  # Usually format is "Device: Name"
                        dev_num = self._extract_device_number(line)
                        if dev_num is not None:
                            mmc_info.devices.append(dev_num)
        else:
            # Older U-Boot - try devices 0-2 directly
            for i in range(3):
                response = self.send_command(f"mmc dev {i}")
                if response and "no card" not in response.lower():
                    mmc_info.devices.append(i)

        # Get partition information for each device
        for dev_num in mmc_info.devices:
            partitions = self._get_device_partitions(dev_num)
            if partitions:
                mmc_info.partitions[dev_num] = partitions

        return mmc_info

    def _extract_device_number(self, line: str) -> Optional[int]:
        """Extract MMC device number from a line of text."""
        try:
            # Try different patterns
            patterns = [
                r'mmc\s*(\d+)',  # matches "mmc0" or "mmc 0"
                r'dev\s*(\d+)',  # matches "dev0" or "dev 0"
                r'^(\d+):',      # matches "0: Device Name"
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line.lower())
                if match:
                    return int(match.group(1))
            return None
        except:
            return None

    def _get_device_partitions(self, dev_num: int) -> List[Dict[str, str]]:
        """Get partition information for a specific MMC device."""
        partitions = []
        
        # Select the device
        dev_response = self.send_command(f"mmc dev {dev_num}")
        if not dev_response or "no card" in dev_response.lower():
            return partitions

        # Get partition information
        if self.command_support.get('part'):
            part_output = self.send_command(f"mmc part")
            
            # Parse partition output
            if part_output:
                # Remove common headers/footers
                lines = [line.strip() for line in part_output.split('\n')
                        if line.strip() and not line.startswith(('Partition', 'Number', '---'))]
                
                for line in lines:
                    # Try to parse partition info
                    # Format varies by U-Boot version, try multiple patterns
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            partition = {
                                'number': parts[0].rstrip(':,'),
                                'start': parts[-2],
                                'size': parts[-1]
                            }
                            if len(parts) > 3:
                                partition['name'] = ' '.join(parts[1:-2])
                            partitions.append(partition)
                    except:
                        continue

        return partitions

    def print_mmc_info(self, mmc_info: MMCInfo):
        """Print MMC device and partition information."""
        print("\nMMC Device Information:")
        print("=======================")
        
        if not mmc_info.devices:
            print("No MMC devices found")
            return

        print("\nCommand Support:")
        for cmd, supported in mmc_info.command_support.items():
            print(f"  {cmd}: {'Yes' if supported else 'No'}")

        print("\nDevices Found:")
        for dev_num in mmc_info.devices:
            print(f"\nMMC Device {dev_num}:")
            
            if dev_num in mmc_info.partitions:
                partitions = mmc_info.partitions[dev_num]
                if partitions:
                    print("  Partitions:")
                    for part in partitions:
                        print(f"    {part['number']}: "
                              f"Start: {part['start']}, "
                              f"Size: {part['size']}"
                              f"{f', Name: {part['name']}' if 'name' in part else ''}")
                else:
                    print("  No partition information available")
            else:
                print("  No partition information available")

    def detect_uboot_version(self) -> str:
        """Detect U-Boot version and vendor."""
        version_output = self.send_command("version")
        if not version_output:
            return UBootVersion.UNKNOWN

        # Try to detect version
        if "U-Boot 2013" in version_output:
            self.uboot_version = UBootVersion.V1_1
        elif "U-Boot 2015" in version_output:
            self.uboot_version = UBootVersion.V1_3
        
        # Try to detect vendor
        for vendor, patterns in self.vendor_patterns.items():
            if any(re.search(pattern, version_output, re.IGNORECASE) for pattern in patterns):
                self.vendor = vendor
                break

        self.logger.info(f"Detected U-Boot version: {self.uboot_version}, vendor: {self.vendor}")
        return self.uboot_version

    def interrupt_boot(self) -> bool:
        """Interrupt boot process with multiple strategies."""
        if not self.ser:
            return False
        
        interrupt_sequences = [
            b'\x03',  # CTRL+C
            b' ',     # Space
            b'\x1b'   # ESC
        ]
        
        for sequence in interrupt_sequences:
            try:
                # Clear input buffer
                self.ser.reset_input_buffer()
                
                # Send interrupt sequence multiple times
                for _ in range(5):
                    self.ser.write(sequence)
                    time.sleep(0.1)
                
                # Check for prompt
                timeout = time.time() + 5
                buffer = ""
                while time.time() < timeout:
                    if self.ser.in_waiting:
                        char = self.ser.read().decode('utf-8', errors='ignore')
                        buffer += char
                        if any(prompt in buffer for prompt in ['#', 'U-Boot>', '>', 'boot>']):
                            self.logger.info(f"Successfully entered U-Boot console using {sequence}")
                            return True
                
                # Small delay before trying next sequence
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.warning(f"Error during interrupt sequence {sequence}: {str(e)}")
                continue
        
        self.logger.error("Failed to enter U-Boot console with all sequences")
        return False

    def send_command(self, cmd: str, wait_time: float = 1, retry: bool = True) -> Optional[str]:
        """Send command with retry mechanism."""
        if not self.ser:
            return None
        
        for attempt in range(self.max_retries if retry else 1):
            try:
                self.ser.write(f"{cmd}\n".encode())
                time.sleep(wait_time)
                
                response = ""
                timeout = time.time() + self.timeout
                while time.time() < timeout and (self.ser.in_waiting or not response):
                    if self.ser.in_waiting:
                        response += self.ser.read().decode('utf-8', errors='ignore')
                
                if response:
                    return response.strip()
                
                if attempt < self.max_retries - 1:
                    self.logger.warning(f"Retry {attempt + 1} for command: {cmd}")
                    time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error sending command '{cmd}' (attempt {attempt + 1}): {str(e)}")
                if not retry:
                    break
                time.sleep(1)
        
        return None

    def get_environment(self) -> bool:
        """Get environment variables with vendor-specific handling."""
        # Try printenv first
        printenv_output = self.send_command("printenv")
        if not printenv_output:
            # Fallback to individual variable reading if supported
            self.logger.warning("printenv failed, trying alternative methods...")
            return self._get_environment_fallback()
        
        try:
            self.env_vars = {}
            for line in printenv_output.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    self.env_vars[key.strip()] = value.strip()
            return bool(self.env_vars)
        except Exception as e:
            self.logger.error(f"Error parsing environment: {str(e)}")
            return False

    def control_boot_timing(self, restore: bool = False) -> bool:
        """
        Control boot timing parameters to prevent automatic boot.
        When restore=True, restores original values.
        Returns True if successful.
        """
        if not hasattr(self, 'boot_settings'):
            self.boot_settings = BootSettings()
            
        try:
            if restore:
                return self._restore_boot_timing()
            else:
                return self._disable_boot_timing()
        except Exception as e:
            self.logger.error(f"Boot timing control error: {str(e)}")
            return False

    def _disable_boot_timing(self) -> bool:
        """
        Disable automatic boot by modifying boot timing parameters.
        Saves original values for later restoration.
        """
        self.logger.info("Disabling automatic boot...")

        # First, check which variables are supported
        help_output = self.send_command("help printenv")
        if help_output:
            for var in self.boot_settings.supported_vars.keys():
                check = self.send_command(f"printenv {var}")
                self.boot_settings.supported_vars[var] = bool(check and '=' in check)

        # Save current values and set new ones
        commands = []
        success = True

        try:
            # Always try bootdelay as it's most common
            delay_check = self.send_command("printenv bootdelay")
            if delay_check and '=' in delay_check:
                current = delay_check.split('=')[1].strip()
                self.boot_settings.original_values['bootdelay'] = current
                commands.append("setenv bootdelay -1")  # -1 disables auto-boot

            # Check other timing variables if supported
            for var, supported in self.boot_settings.supported_vars.items():
                if supported and var != 'bootdelay':
                    check = self.send_command(f"printenv {var}")
                    if check and '=' in check:
                        current = check.split('=')[1].strip()
                        self.boot_settings.original_values[var] = current
                        if var in ['bootcount', 'bootlimit']:
                            commands.append(f"setenv {var} 0")
                        elif var in ['bootretry', 'timeout']:
                            commands.append(f"setenv {var} -1")

            # Apply new settings
            for cmd in commands:
                result = self.send_command(cmd)
                if not result:
                    self.logger.warning(f"Failed to execute: {cmd}")
                    success = False

            # Save environment
            if commands:
                save_result = self.send_command("saveenv")
                if not save_result:
                    self.logger.warning("Failed to save environment")
                    success = False

            if success:
                self.logger.info("Successfully disabled automatic boot")
                # Verify changes
                success = self._verify_boot_timing_changes()
            
            return success

        except Exception as e:
            self.logger.error(f"Error disabling boot timing: {str(e)}")
            return False

    def _restore_boot_timing(self) -> bool:
        """
        Restore original boot timing parameters.
        """
        if not self.boot_settings.original_values:
            self.logger.info("No boot timing values to restore")
            return True

        self.logger.info("Restoring original boot timing values...")
        
        commands = []
        success = True

        try:
            # Restore all saved values
            for var, value in self.boot_settings.original_values.items():
                commands.append(f"setenv {var} {value}")

            # Apply original settings
            for cmd in commands:
                result = self.send_command(cmd)
                if not result:
                    self.logger.warning(f"Failed to execute: {cmd}")
                    success = False

            # Save environment
            if commands:
                save_result = self.send_command("saveenv")
                if not save_result:
                    self.logger.warning("Failed to save environment")
                    success = False

            if success:
                self.logger.info("Successfully restored boot timing values")
            
            return success

        except Exception as e:
            self.logger.error(f"Error restoring boot timing: {str(e)}")
            return False

    def _verify_boot_timing_changes(self) -> bool:
        """
        Verify that boot timing changes were applied correctly.
        """
        try:
            # Refresh environment variables
            if not self.get_environment():
                return False

            # Verify each changed variable
            for var in self.boot_settings.supported_vars:
                if var in self.env_vars:
                    current_value = self.env_vars[var]
                    expected_value = '-1' if var in ['bootdelay', 'bootretry', 'timeout'] else '0'
                    
                    if current_value != expected_value:
                        self.logger.warning(
                            f"Boot timing verification failed for {var}. "
                            f"Expected: {expected_value}, Got: {current_value}"
                        )
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Error verifying boot timing changes: {str(e)}")
            return False

    def _get_environment_fallback(self) -> bool:
        """Fallback method to get environment variables."""
        try:
            # Get list of variables first (some U-Boot versions support this)
            vars_list = self.send_command("env list") or ""
            var_names = set()
            
            # Add known important variables
            var_names.update(self.bootargs_vars.get(self.vendor, self.bootargs_vars['default']))
            var_names.update(['bootcmd', 'bootdelay', 'bootargs'])
            
            # Add variables from env list if available
            var_names.update(name.strip() for name in vars_list.split() if name.strip())
            
            # Try to get each variable individually
            self.env_vars = {}
            for var in var_names:
                result = self.send_command(f"printenv {var}")
                if result and '=' in result:
                    _, value = result.split('=', 1)
                    self.env_vars[var] = value.strip()
            
            return bool(self.env_vars)
        except Exception as e:
            self.logger.error(f"Fallback environment reading failed: {str(e)}")
            return False

    def trace_security_settings(self) -> Dict[str, Dict[str, SecuritySetting]]:
        """Trace security settings with depth limit and cycle detection."""
        settings = {
            SecurityType.SELINUX: {},
            SecurityType.VERITY: {}
        }
        
        # Start with vendor-specific bootargs variables
        start_vars = self.bootargs_vars.get(self.vendor, self.bootargs_vars['default'])
        
        for var in start_vars:
            if var in self.env_vars:
                self._trace_variable_recursive(var, [], 0, settings)
        
        return settings

    def _trace_variable_recursive(self, var_name: str, path: List[str], depth: int, 
                                settings: Dict[SecurityType, Dict[str, SecuritySetting]]) -> None:
        """Recursively trace variable references with safety checks."""
        # Check depth limit
        if depth >= self.max_depth:
            self.logger.warning(f"Max depth reached at variable {var_name}")
            return
        
        # Check for cycles
        if var_name in path:
            self.logger.warning(f"Cycle detected: {' -> '.join(path + [var_name])}")
            return
        
        # Get variable value
        value = self.env_vars.get(var_name)
        if not value:
            return
        
        current_path = path + [var_name]
        
        # Check for security settings
        if self._is_selinux_related(value):
            settings[SecurityType.SELINUX][var_name] = SecuritySetting(
                value=value,
                source_var=path[0] if path else var_name,
                depth=depth,
                path=current_path
            )
        
        if self._is_verity_related(value):
            settings[SecurityType.VERITY][var_name] = SecuritySetting(
                value=value,
                source_var=path[0] if path else var_name,
                depth=depth,
                path=current_path
            )
        
        # Find and trace referenced variables
        for ref_var in self.find_variable_references(value):
            self._trace_variable_recursive(ref_var, current_path, depth + 1, settings)

    def _is_selinux_related(self, value: str) -> bool:
        """Check if value contains SELinux-related settings."""
        return any(term in value.lower() for term in [
            'selinux=', 
            'androidboot.selinux=',
        ])

    def _is_verity_related(self, value: str) -> bool:
        """Check if value contains Verity-related settings."""
        return any(term in value.lower() for term in [
            'veritymode=',
            'androidboot.veritymode=',
        ])

    def generate_fix_commands(self, settings: Dict[str, Dict[str, SecuritySetting]]) -> List[str]:
        """Generate commands to disable security features."""
        commands = []
        processed_vars = set()
        
        for security_type, variables in settings.items():
            for var_name, setting in variables.items():
                if var_name in processed_vars:
                    continue
                
                processed_vars.add(var_name)
                value = setting.value
                
                if security_type == SecurityType.SELINUX:
                    value = re.sub(r'androidboot\.selinux=\S+', 'androidboot.selinux=disabled', value)
                    value = re.sub(r'selinux=\S+', 'selinux=disabled', value)
                    
                if security_type == SecurityType.VERITY:
                    value = re.sub(r'androidboot\.veritymode=\S+', 'androidboot.veritymode=disabled', value)
                    value = re.sub(r'veritymode=\S+', 'veritymode=disabled', value)
                
                if value != setting.value:
                    commands.append(f'setenv {var_name} {value}')
        
        if commands:
            commands.append('saveenv')
        
        return commands

    def save_analysis(self, filename: str, settings: Dict[str, Dict[str, SecuritySetting]]) -> None:
        """Save analysis results to file."""
        try:
            output = {
                'uboot_version': self.uboot_version,
                'vendor': self.vendor,
                'settings': {
                    security_type.value: {
                        var_name: {
                            'value': setting.value,
                            'source': setting.source_var,
                            'depth': setting.depth,
                            'path': setting.path
                        }
                        for var_name, setting in vars_dict.items()
                    }
                    for security_type, vars_dict in settings.items()
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            
            self.logger.info(f"Analysis saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save analysis: {str(e)}")

def apply_fixes(self, commands: List[str]) -> bool:
    """
    Apply the fix commands with user confirmation and status reporting.
    Returns True if all commands were applied successfully.
    """
    if not commands:
        self.logger.info("No fixes needed!")
        return True

    print("\nProposed fixes:")
    for i, cmd in enumerate(commands, 1):
        print(f"{i}. {cmd}")
    
    try:
        response = input("\nWould you like to apply these fixes? (yes/no): ").lower().strip()
        if response != 'yes':
            print("Fix application cancelled.")
            return False
        
        print("\nApplying fixes...")
        for i, cmd in enumerate(commands, 1):
            print(f"\nExecuting ({i}/{len(commands)}): {cmd}")
            result = self.send_command(cmd, wait_time=2)
            
            if not result:
                self.logger.error(f"Command failed: {cmd}")
                
                # Ask user if they want to continue
                cont = input("\nCommand failed. Continue with remaining commands? (yes/no): ").lower().strip()
                if cont != 'yes':
                    print("Fix application aborted.")
                    return False
            else:
                print(f"Command successful: {cmd}")
                
                # For saveenv specifically, wait a bit longer and verify
                if cmd == 'saveenv':
                    time.sleep(2)  # Give more time for save to complete
                    verify = self.send_command("printenv")
                    if not verify:
                        print("Warning: Could not verify environment save!")
                    else:
                        print("Environment saved successfully!")

        # Verify the changes
        print("\nVerifying changes...")
        success = self._verify_fixes(commands)
        
        if success:
            print("\nAll fixes have been applied and verified successfully!")
        else:
            print("\nWarning: Some changes could not be verified. Please check manually.")
        
        return success

    except KeyboardInterrupt:
        print("\nFix application interrupted by user.")
        return False
    except Exception as e:
        self.logger.error(f"Error applying fixes: {str(e)}")
        return False

def _verify_fixes(self, applied_commands: List[str]) -> bool:
    """
    Verify that the fixes were applied correctly.
    """
    # Skip saveenv command for verification
    commands_to_verify = [cmd for cmd in applied_commands if cmd != 'saveenv']
    
    if not commands_to_verify:
        return True
    
    # Get fresh environment
    if not self.get_environment():
        print("Warning: Could not refresh environment for verification!")
        return False
    
    all_verified = True
    for cmd in commands_to_verify:
        if cmd.startswith('setenv'):
            _, var, *value = cmd.split(None, 2)
            if value:  # If there was a value set
                expected_value = value[0]
                actual_value = self.env_vars.get(var)
                if actual_value != expected_value:
                    print(f"Verification failed for {var}:")
                    print(f"Expected: {expected_value}")
                    print(f"Actual: {actual_value}")
                    all_verified = False
    
    return all_verified

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    tracer = UBootSecurityTracer()
    
    try:
        print("\nU-Boot Security & MMC Tool")
        print("=========================")

        # Get baud rate from user
        try:
            baud_input = input("\nEnter baud rate [default: 115200]: ").strip()
            if baud_input:
                baud_rate = int(baud_input)
            else:
                baud_rate = 115200
        except ValueError:
            print("Invalid baud rate. Using default: 115200")
            baud_rate = 115200

        tracer = UBootSecurityTracer(baudrate=baud_rate)
        
        # 1. Connect to device
        print("\nConnecting to device...")
        if not tracer.connect():
            print("Failed to connect to device. Exiting.")
            return

        # 2. Interrupt boot
        print("\nInterrupting boot process...")
        if not tracer.interrupt_boot():
            print("Failed to interrupt boot process. Exiting.")
            return

        # 3. Control boot timing to prevent auto-boot
        print("\nDisabling automatic boot...")
        if not tracer.control_boot_timing(restore=False):
            print("Warning: Could not fully control boot timing")
            response = input("Continue anyway? (yes/no): ").lower().strip()
            if response != 'yes':
                return

        # 4. Detect U-Boot version and vendor
        print("\nDetecting U-Boot version...")
        version = tracer.detect_uboot_version()
        print(f"Detected Version: {version}")
        print(f"Detected Vendor: {tracer.vendor}")

        # 5. Enumerate MMC devices
        print("\nEnumerating MMC devices...")
        mmc_info = tracer.enumerate_mmc_devices()
        if mmc_info:
            tracer.print_mmc_info(mmc_info)
        else:
            print("MMC enumeration not supported or no devices found")

        # 6. Get environment variables
        print("\nReading environment variables...")
        if not tracer.get_environment():
            print("Failed to get environment variables. Exiting.")
            return

        # 7. Analyze security settings
        print("\nAnalyzing security settings...")
        settings = tracer.trace_security_settings()
        
        print("\nSecurity Settings Analysis:")
        print("==========================")
        
        for security_type in SecurityType:
            print(f"\n{security_type.value.upper()} Settings:")
            if settings[security_type]:
                for var_name, setting in settings[security_type].items():
                    print(f"\nVariable: {var_name}")
                    print(f"Value: {setting.value}")
                    print(f"Source: {setting.source_var}")
                    print(f"Depth: {setting.depth}")
                    print(f"Path: {' -> '.join(setting.path)}")
            else:
                print("No settings found")

        # 8. Generate and apply fixes if needed
        commands = tracer.generate_fix_commands(settings)
        
        if commands:
            print("\nRequired Modifications:")
            print("=====================")
            for cmd in commands:
                print(cmd)
            
            if tracer.apply_fixes(commands):
                print("\nFixes applied successfully!")
            else:
                print("\nFix application was not completed.")
        else:
            print("\nNo security modifications required!")

        # 9. Save analysis to file
        print("\nSaving analysis...")
        tracer.save_analysis("uboot_security_analysis.json", settings)
        print("Analysis saved to uboot_security_analysis.json")

    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
    except Exception as e:
        tracer.logger.error(f"Script error: {str(e)}")
    finally:
        # Always try to restore boot timing
        print("\nRestoring boot timing settings...")
        try:
            if hasattr(tracer, 'boot_settings'):
                tracer.control_boot_timing(restore=True)
        except Exception as e:
            print(f"Warning: Failed to restore boot timing: {str(e)}")
        
        # Close serial connection
        if tracer.ser:
            print("Closing serial connection...")
            tracer.ser.close()

if __name__ == "__main__":
    main()

# TODO: set env args stdin, stdout, stderr  to serial if not
# TODO: USB enum
# TODO: vendor commands?
# TODO: store commands for dtb/others? (store dtb read 1000000 and md.b 1000000 2000)
#   md.b 0x8c200 0x100 ?
# TODO: check 'test' command is availible for seeing if store writes will work to SD card?
#         then ask if user wants to exfil
#           store? -> store list? - store part?