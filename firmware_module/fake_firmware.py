import struct
import os


def build_ffs_file(guid_bytes: bytes, ffs_type: int, body: bytes) -> bytes:
    """
    Build a minimal EFI_FFS_FILE_HEADER + body.
    Total size is header (24 bytes) + body, 8-byte aligned.
    """
    raw_size = 24 + len(body)
    # Pad to 8-byte boundary
    padded_size = (raw_size + 7) & ~7
    padding = bytes(padded_size - raw_size)

    size_field = struct.pack("<I", padded_size)[:3]  # 3-byte size

    header = (
        guid_bytes[:16]          # Name GUID (16 bytes)
        + b"\x00\x00"            # IntegrityCheck (placeholder)
        + bytes([ffs_type])      # Type
        + b"\x00"                # Attributes
        + size_field             # Size[3]
        + b"\xF8"                # State (valid file)
    )

    return header + body + padding


def build_firmware_volume(ffs_files: list[bytes]) -> bytes:
    """
    Wrap a list of FFS file blobs in a Firmware Volume.
    Produces a valid EFI_FIRMWARE_VOLUME_HEADER followed by the files.
    """
    header_length = 56       # Minimal FV header (no block map beyond sentinel)
    ffs_data = b"".join(ffs_files)
    fv_length = header_length + len(ffs_data)

    header = (
        b"\x00" * 16            # ZeroVector
        + b"\x00" * 16          # FileSystemGuid (simplified)
        + struct.pack("<Q", fv_length)   # FvLength
        + b"_FVH"               # Signature
        + struct.pack("<I", 0x0004FEFF)  # Attributes
        + struct.pack("<H", header_length)  # HeaderLength
        + struct.pack("<H", 0x0000)      # Checksum (not validated in tests)
        + struct.pack("<H", 0x0000)      # ExtHeaderOffset
        + b"\x00"               # Reserved
        + b"\x02"               # Revision
        # Block map: one entry + terminator
        + struct.pack("<I", 1)           # NumBlocks
        + struct.pack("<I", fv_length)   # Length
        + struct.pack("<Q", 0)           # Terminator entry
    )

    # Pad header to header_length if needed
    header = header[:header_length].ljust(header_length, b"\x00")

    return header + ffs_data


def make_test_firmware(
    include_smm: bool = False,
    include_dxe: bool = True,
    smm_with_signature: bool = False,
) -> bytes:
    """
    Generate a minimal but structurally valid UEFI firmware blob.

    Args:
        include_smm: Add an SMM_DRIVER type FFS file
        include_dxe: Add a DXE_DRIVER type FFS file
        smm_with_signature: Put an SMM signature string inside a DXE driver body
                            (simulates a DXE driver that calls into SMM)

    Returns:
        Raw bytes of fake firmware ready for UEFIParser
    """
    ffs_list = []

    # Always add a PEI core - every real firmware has one
    pei_guid = bytes([
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ])
    ffs_list.append(build_ffs_file(pei_guid, 0x04, b"PEI_CORE_BODY" + b"\x00" * 64))

    if include_dxe:
        dxe_guid = bytes([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        ])
        body = b"DXE_DRIVER_BODY" + b"\x00" * 64
        if smm_with_signature:
            body += b"SmmConfigurationTable"  # Triggers SMM heuristic
        ffs_list.append(build_ffs_file(dxe_guid, 0x06, body))

    if include_smm:
        smm_guid = bytes([
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        ])
        ffs_list.append(build_ffs_file(smm_guid, 0x0A, b"SMM_DRIVER_BODY" + b"\x00" * 64))

    volume = build_firmware_volume(ffs_list)

    # Pad to 1MB total - real firmware is 4-16MB but 1MB is fine for tests
    target_size = 1024 * 1024
    if len(volume) < target_size:
        volume += b"\xFF" * (target_size - len(volume))

    return volume