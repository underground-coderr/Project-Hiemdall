import os
import platform
import hashlib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

class FirmwareDumper:
    """
    Handles firmware acquisition from multiple sourse.
    Supports: file loading, QEMU extraction, flashrom, and UEFI variable Dumps.
    """

    def __init__(self, output_dir="./firmware_dumps"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.os_type = platform.system()
        self.acquired_files = []

    # Method 1: Load from existing file (Used for testing)

    def load_from_file(self, file_path):
        """
        load a firmware dump that already exists.
        we would use this main method for testing with sample data.
        """
        path = Path(file_path)

        if not path.exists():
            console.print(f"[red]Error:[/red] File not found: {file_path}")
            return None
        
        if not path.suffix == ".bin" and not path.suffix == ".fd":
            console.print(f"[yellow]Warning:[/yellow] Unexpected extension '{path.suffix}' - expected .bin or .fd")

        data = path.read_bytes()

        if len(data) == 0:
            console.print(f"[red]Error:[/red] File is empty: {file_path}")
            return None
        
        result = self._build_acquisition_result(path.name, data, source="file")
        self.acquired_files.append(result)

        console.print(f"[green]Loaded:[/green] {path.name} ({len(data):,} bytes)")
        console.print(f"[dim]SHA256: {result['sha256']}[/dim]")

        return result
    
    # Method 2: Dump via flashrom (Linux only)

    def dump_via_flashrom(self):
        """
        Dump firmware using flashrom utility
        Requires Linux + Root access + flashrom installation.
        """
        if self.os_type != "Linux":
            console.print(f"[red]Error:[/red] flashrom dump requires Linux (you're on {self.os_type})")
            return None
        
        output_path = self.output_dir / f"flashrom_dump_{self._timestamp()}.bin"

        console.print("[yellow]Running flashrom - this needs root and may take 1-2 minutes...[/yellow]")

        try:
            result = subprocess.run(
                ["flashrom", "-p", "internal", "-r", str(output_path)],
                capture_output=True,
                text=True,
                timeout=180
            )

            if result.returncode != 0:
                console.print(f"[red]flashrom failed:[/red] {result.stderr}")
                return None
            
            data = output_path.read_bytes()
            acquisition = self._build_acquisition_result(output_path.name, data, source="flashrom")
            self.acquired_files.append(acquisition)

            console.print(f"[green]Dump comlete:[/green] {output_path.name} ({len(data):,} bytes)")
            return acquisition
        
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] flashrom not found - install it with: sudo apt install flashrom")
            return None
        except subprocess.TimeoutExpired:
            console.print("[red]Error:[/red] flashrom timed out after 3 minutes.")
            return None
        
    # Method 3: Extract from QEMU/VM 

    def extract_from_qemu(self, vm_dir):
        """
        Copy OVMF.fd (UEFI firmware) from a VM directory
        OVMF is the open-source UEFI implementation used by QEMU
        """

        vm_path = Path(vm_dir)

        # Common OVMF file names
        possible_names = ["OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd", "bios.bin"]

        found = None
        for name in possible_names:
            candidate = vm_path / name
            if candidate.exists():
                found = candidate
                break

        if not found:
            console.print(f"[red]Error:[/red] No UEFI firmware file found in {vm_dir}")
            console.print(f"[dim]Looked for: {', '.join(possible_names)}[/dim]")
            return None
        
        output_path = self.output_dir / f"qemu_dump_{self._timestamp()}.bin"
        shutil.copy(found, output_path)

        data = output_path.read_bytes()
        acquisition = self._build_acquisition_result(output_path.name, data, source="qemu")
        self.acquired_files.append(acquisition)

        console.print(f"[green]Extracted:[/green] {found.name} → {output_path.name} ({len(data):,} bytes)")
        return acquisition
    
    # Method 4: Dump UEFI variables via efivarfs (Linux Only)

    def dump_uefi_variables(self):
        """
        Read UEFI NVRAM variables from /sys/firmware/efi/efivars
        Linux only - Requires efivarfs to be mounted.
        """
        if self.os_type != "Linux":
            console.print(f"[red]Error:[/red] /sys/firmware/efi/efivars not found - is efivarfs mounted?")
            console.print("[dim]Try: sudo mount -t efivarfs efivarfs /sys/firmware/efi/efivars[/dim]")
            return None
        
        variables = {}
        error = []

        for var_path in efi_vars_path.glob("*"):
            try:
                raw = var_path.read_bytes()
                variables[var_path.name] = {
                    "data": raw.hex(),
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest()
                }
            except (PermissionError, OSError) as e:
                errors.append(f"{var_path.name}: {e}")

        if errors:
            console.print(f"[yellow]Warning:[/yellow] Could not read {len(errors)} variable(s)")

        console.print(f"[green]Dumped:[/green] {len(variables)} UEFI variables")
        return {
            "source": "efivarfs",
            "timestamp": self._timestamp(),
            "variable_count": len(variables),
            "variables": variables
        }            
    
    # Utility methods

    def verify_integrity(self, acquisition_result):
        """
        Re-hash the file and confirms it matches the stored hash.
        to verify nothing changed between acquisition and analysis.
        """
        if not acquisition_result:
            return False
        
        file_path = self.output_dir / acquisition_result["filename"]

        if not file_path.exists():
            console.print(f"[red]Error:[/red] File missing: {file_path}")
            return False
        
        current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        original_hash = acquisition_result["sha256"]

        if current_hash == original_hash:
            console.print("[green]Integrity check passed[/green] - file unchanged")
            return True
        else:
            console.print("[red]INTEGRITY CHECK FAILED[/red] - file has been modified!")
            console.print(f"[dim]Expected:  {original_hash}[/dim]")
            console.print(f"[dim]Got:       {current_hash}[/dim]")
            return False
        
    def get_summary(self):
        """
        Print a summary of all acquired firmware files for the session
        """
        if not self.acquired_files:
            console.print("[yellow]No firmware files acquired this session[/yellow]")
            return
        
        console.print(f"[bold]Acquuired {len(self.acquired_files)} firmware file's:[/bold]")
        for f in self.acquired_files:
            console.print(f"    • {f['filename']} | {f['size']:,} bytes | {f['source']} | {f['timestamp']}")

    def _build_acquisition_result(self, filename, data, source):
        """
        Build a standardized result dict for any acquisition method
        """
        output_path = self.output_dir / filename

        # Save a copy to output dir if its not there
        if not output_path.exists():
            output_path.write_bytes(data)
        
        return {
            "filename": filename,
            "path": str(output_path),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "source": source,
            "timestamp": self._timestamp,
            "os": self.os_type
        }
    
    def _timestamp(self):
        from datetime import timezone
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")