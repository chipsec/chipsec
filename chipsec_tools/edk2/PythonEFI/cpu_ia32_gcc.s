
.global WritePortDword
.global WritePortWord
.global WritePortByte
.global ReadPortDword
.global ReadPortWord
.global ReadPortByte
.global WriteHighCMOSByte
.global WriteLowCMOSByte
.global SendAPMSMI
.global WritePCIByte
.global WritePCIWord
.global WritePCIDword
.global ReadPCIByte
.global ReadPCIWord
.global ReadPCIDword
.global _rdmsr
.global _wrmsr
.global _swsmi


.intel_syntax noprefix
.text


#------------------------------------------------------------------------------
# void _store_ldtr(
#   unsigned char *address // rcx
#   )
#------------------------------------------------------------------------------
_store_ldtr:
    mov ecx, dword ptr [esp+4]
    sldt word ptr [ecx]
    ret

#------------------------------------------------------------------------------
#  void __stdcall _rdmsr(
#    IN UINT32 msr,
#    OUT UINT32* msrlo,
#    OUT UINT32* msrhi 
#    )
#------------------------------------------------------------------------------
_rdmsr:
    mov ecx, dword ptr [esp + 4] # msr

    rdmsr

    mov ecx, dword ptr [esp + 8] 
    mov dword ptr [ecx], eax # msrlo
    mov ecx, dword ptr [esp + 12] 
    mov dword ptr [ecx], edx # msrhi
    ret

#------------------------------------------------------------------------------
#  VOID __stdcall _wrmsr(
#    IN UINT32 msr,
#    IN UINT32 msrlo,
#    IN UINT32 msrhi 
#    )
#------------------------------------------------------------------------------
_wrmsr:
    mov ecx, dword ptr [esp + 4]  # msr
    mov eax, dword ptr [esp + 8] # msrlo
    mov edx, dword ptr [esp + 12] # msrhi

    wrmsr
    ret

#------------------------------------------------------------------------------
#UINT32 _eflags()
#------------------------------------------------------------------------------
eflags:
    pushfd
    pop eax
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePortDword (
#    IN   UINT32    out_value
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
WritePortDword:
    mov eax, dword ptr [esp + 4]    # out_value
    mov edx, dword ptr [esp + 8]   # port_num
    out dx, eax
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePortWord (
#    IN   UINT16    out_value
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
WritePortWord:
    mov eax, dword ptr [esp + 4]   # out_value
    mov edx, dword ptr [esp + 8]  # port_num
    out dx, ax
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePortByte (
#    IN   UINT8     out_value
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
WritePortByte:
    mov eax, dword ptr [esp + 4]   # out_value
    mov edx, dword ptr [esp + 8]  # port_num
    out dx, al
    ret

#------------------------------------------------------------------------------
#  UINT32
#  ReadPortDword (
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
ReadPortDword:
    xor eax, eax
    mov edx, dword ptr [esp + 4] # port_num
    in eax, dx
   ret

#------------------------------------------------------------------------------
#  UINT16
#  ReadPortWord (
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
ReadPortWord:
    xor eax, eax    
    mov edx, dword ptr [esp + 4] # port_num
    in ax, dx
    ret

#------------------------------------------------------------------------------
#  UINT8
#  ReadPortByte (
#    IN   UINT16    port_num
#    )
#------------------------------------------------------------------------------
ReadPortByte:
    xor eax, eax    
    mov edx, dword ptr [esp + 4] # port_num
    in al, dx
    ret

#------------------------------------------------------------------------------
#  VOID
#  WriteHighCMOSByte (
#    IN   UINT8     cmos_off
#    IN   UINT8     val
#    )
#------------------------------------------------------------------------------
WriteHighCMOSByte:
    mov eax, dword ptr [esp + 4]  # cmos_off
    out 0x72, al
    mov eax, dword ptr [esp + 8]  # val
    out 0x73, al
    ret


#------------------------------------------------------------------------------
#  VOID
#  WriteLowCMOSByte (
#    IN   UINT8     cmos_off
#    IN   UINT8     val
#    )
#------------------------------------------------------------------------------
WriteLowCMOSByte:
    mov eax, dword ptr [esp + 4]  # cmos_off
    or al, 0x80
    out 0x70, al
    mov eax, dword ptr [esp + 8]  # val
    out 0x71, al
    ret


#------------------------------------------------------------------------------
#  VOID
#  SendAPMSMI (
#    IN   UINT32	apm_port_value
#    IN   UINT64	rax_value               // NOT USED???
#    )
#------------------------------------------------------------------------------
SendAPMSMI:
    mov eax, dword ptr [esp + 4]  # apm_port_value
    mov dx, 0x0B2
    out dx, eax
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePCIByte (
#    IN   UINT32    pci_reg
#    IN   UINT16    cfg_data_port
#    IN   UINT8     byte_value
#    )
#------------------------------------------------------------------------------
WritePCIByte:
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    mov eax, dword ptr [esp + 12]  # word_value
    mov edx, dword ptr [esp + 8]  # cfg_data_port
    out dx, al
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePCIWord (
#    IN   UINT32    pci_reg
#    IN   UINT16    cfg_data_port
#    IN   UINT16    word_value
#    )
#------------------------------------------------------------------------------
WritePCIWord:
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    mov eax, dword ptr [esp + 12]  # word_value
    mov edx, dword ptr [esp + 8]  # cfg_data_port
    out dx, ax
    ret

#------------------------------------------------------------------------------
#  VOID
#  WritePCIDword (
#    IN   UINT32	pci_reg
#    IN   UINT16	cfg_data_port    // rdx
#    IN   UINT32	dword_value      // r8
#    )
#------------------------------------------------------------------------------
WritePCIDword:
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    mov eax, dword ptr [esp + 12]  # dword_value
    mov edx, dword ptr [esp + 8]  # cfg_data_port
    out dx, eax
    ret

#------------------------------------------------------------------------------
#  unsigned char
#  ReadPCIByte (
#    unsigned int	pci_reg          // rcx
#    unsigned short	cfg_data_port    // rdx
#    )
#------------------------------------------------------------------------------
ReadPCIByte:
    cli
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    xor eax, eax
    mov edx, dword ptr [esp + 8]   # cfg_data_port
    in  al, dx
    sti

    ret

#------------------------------------------------------------------------------
#  unsigned short
#  ReadPCIWord (
#    unsigned int	pci_reg          // rcx
#    unsigned short	cfg_data_port    // rdx
#    )
#------------------------------------------------------------------------------
ReadPCIWord:
    cli
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    xor eax, eax	
    mov edx, dword ptr [esp + 8]   # cfg_data_port
    in  ax, dx
    sti

    ret

#------------------------------------------------------------------------------
#  unsigned int
#  ReadPCIDword (
#    unsigned int	pci_reg          // rcx
#    unsigned short	cfg_data_port    // rdx
#    )
#------------------------------------------------------------------------------
ReadPCIDword:
    cli
    mov eax, dword ptr [esp + 4]  # pci_reg
    mov dx, 0x0CF8
    out dx, eax

    xor eax, eax	
    mov edx, dword ptr [esp + 8]   # cfg_data_port
    in  eax, dx
    sti

    ret

#------------------------------------------------------------------------------
#  void
#  _swsmi (
#    unsigned int	smi_code_data	// rcx
#    IN   UINT32	rax_value	// rdx
#    IN   UINT32	rbx_value	// r8
#    IN   UINT32	rcx_value	// r9
#    IN   UINT32	rdx_value	// r10
#    IN   UINT32	rsi_value	// r11
#    IN   UINT32	rdi_value	// r12
#    )
#------------------------------------------------------------------------------
_swsmi:
    xor eax, eax
    ret
