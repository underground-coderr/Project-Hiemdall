rule Unsigned_SMM_Driver
{
    meta:
        description = "SMM driver missing WinCert signature block"
        severity    = "HIGH"

    strings:
        $smm1 = "SmmConfigurationTable"       ascii
        $smm2 = "EFI_SMM_SYSTEM_TABLE"        ascii
        $smm3 = "SmmInstallProtocolInterface" ascii
        $no_cert = "WIN_CERT"                  ascii

    condition:
        any of ($smm*) and not $no_cert
}

rule Suspicious_SMM_Allocation
{
    meta:
        description = "Detects SMM driver attempting runtime memory allocation - common rootkit technique"
        severity    = "HIGH"

    strings:
        $alloc1 = "SmmAllocatePool"  ascii
        $alloc2 = "SmmAllocatePages" ascii
        $alloc3 = "gSmst"            ascii

    condition:
        2 of them
}

rule Hidden_DXE_Driver
{
    meta:
        description = "DXE driver with SMM internals but no visible GUID - possible hiding technique"
        severity    = "MEDIUM"

    strings:
        $smm_ref  = "EFI_SMM_BASE2_PROTOCOL" ascii
        $hook_ref = "EFI_BOOT_SERVICES"       ascii

    condition:
        all of them
}