import pytest
import os
from pathlib import Path
from firmware_module.acquisition import FirmwareDumper

# Will use a temp dir and fake binary data for all test

FAKE_FIRMWARE = bytes([0x00, 0x5A, 0x46, 0x56, 0x00] * 1000) # 6KB of fake blob

@pytest.fixture
def dumper(tmp_path):
    """
    create a firmwareDumper that outputs to a temp dir
    """
    return FirmwareDumper(output_dir=str(tmp_path))

@pytest.fixture
def fake_bin_file(tmp_path):
    """
    Create a fake .bin firmware file for testing
    """
    p = tmp_path / "fake_firmware.bin"
    p.write_bytes(FAKE_FIRMWARE)
    return p

def test_load_from_file_success(dumper, fake_bin_file):
    result = dumper.load_from_file(str(fake_bin_file))

    assert result is not None
    assert result["filename"] == "fake_firmware.bin"
    assert result["size"] == len(FAKE_FIRMWARE)
    assert result["source"] == "file"
    assert len(result["sha256"]) == 64  # Valid SHA256 hex string
    assert len(result["md5"]) == 32      # Valid MD5 hex string   
    
def test_load_from_file_not_found(dumper, tmp_path):
    result = dumper.load_from_file(str(tmp_path / "does_not_exist.bin"))
    assert result is None


def test_load_from_file_empty(dumper, tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    result = dumper.load_from_file(str(empty))
    assert result is None


def test_hash_is_deterministic(dumper, fake_bin_file):
    """Same file loaded twice should give same hash"""
    r1 = dumper.load_from_file(str(fake_bin_file))
    r2 = dumper.load_from_file(str(fake_bin_file))
    assert r1["sha256"] == r2["sha256"]


def test_integrity_check_passes(dumper, fake_bin_file):
    result = dumper.load_from_file(str(fake_bin_file))
    assert dumper.verify_integrity(result) is True


def test_integrity_check_fails_on_modified_file(dumper, fake_bin_file):
    result = dumper.load_from_file(str(fake_bin_file))

    # Tamper with the file after acquisition
    p = Path(result["path"])
    p.write_bytes(b"tampered data")

    assert dumper.verify_integrity(result) is False


def test_qemu_extract_missing_dir(dumper, tmp_path):
    result = dumper.extract_from_qemu(str(tmp_path / "nonexistent_vm"))
    assert result is None


def test_qemu_extract_no_ovmf(dumper, tmp_path):
    """VM dir exists but has no OVMF file"""
    vm_dir = tmp_path / "my_vm"
    vm_dir.mkdir()
    result = dumper.extract_from_qemu(str(vm_dir))
    assert result is None


def test_qemu_extract_success(dumper, tmp_path):
    vm_dir = tmp_path / "my_vm"
    vm_dir.mkdir()
    ovmf = vm_dir / "OVMF.fd"
    ovmf.write_bytes(FAKE_FIRMWARE)

    result = dumper.extract_from_qemu(str(vm_dir))

    assert result is not None
    assert result["source"] == "qemu"
    assert result["size"] == len(FAKE_FIRMWARE)


def test_flashrom_windows_blocked(dumper):
    """On Windows, flashrom should return None gracefully"""
    import platform
    if platform.system() == "Windows":
        result = dumper.dump_via_flashrom()
        assert result is None


def test_get_summary_empty(dumper):
    """Should not crash when no files acquired"""
    dumper.get_summary()  # Just checking it doesn't throw


def test_acquired_files_tracked(dumper, fake_bin_file):
    dumper.load_from_file(str(fake_bin_file))
    dumper.load_from_file(str(fake_bin_file))
    assert len(dumper.acquired_files) == 2