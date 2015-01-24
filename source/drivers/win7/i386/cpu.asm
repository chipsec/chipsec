TITLE   cpu.asm: Assembly code for the i386 resources

include callconv.inc

.686p
.XMM
_TEXT    SEGMENT DWORD PUBLIC 'CODE'
    ASSUME  DS:FLAT, ES:FLAT, SS:NOTHING, FS:NOTHING, GS:NOTHING

;------------------------------------------------------------------------------
; void _store_idtr(
;   unsigned char *address // rcx
;   )
;------------------------------------------------------------------------------
cPublicProc __store_idtr, 1
    mov ecx, dword ptr [esp+4]
    sidt dword ptr [ecx]
    stdRET __store_idtr
stdENDP __store_idtr

;------------------------------------------------------------------------------
; void _load_idtr(
;   unsigned char *address // rcx
;   )
;------------------------------------------------------------------------------
cPublicProc __load_idtr, 1
    mov ecx, dword ptr [esp+4]
    lidt fword ptr [ecx]
    stdRET __load_idtr
stdENDP __load_idtr

;------------------------------------------------------------------------------
; void _store_gdtr(
;   unsigned char *address // rcx
;   )
;------------------------------------------------------------------------------
cPublicProc __store_gdtr, 1
    mov ecx, dword ptr [esp+4]
    sgdt dword ptr [ecx]
    stdRET __store_gdtr
stdENDP __store_gdtr

;------------------------------------------------------------------------------
; void _store_ldtr(
;   unsigned char *address // rcx
;   )
;------------------------------------------------------------------------------
cPublicProc __store_ldtr, 1
    mov ecx, dword ptr [esp+4]
    sldt word ptr [ecx]
    stdRET __store_ldtr
stdENDP __store_ldtr

;------------------------------------------------------------------------------
;  void __stdcall _rdmsr(
;    IN UINT32 msr,
;    OUT UINT32* msrlo,
;    OUT UINT32* msrhi 
;    )
;------------------------------------------------------------------------------
cPublicProc __rdmsr, 3
    mov ecx, dword ptr [esp + 4] ; msr

    rdmsr

    mov ecx, dword ptr [esp + 8] 
    mov dword ptr [ecx], eax ; msrlo
    mov ecx, dword ptr [esp + 12] 
    mov dword ptr [ecx], edx ; msrhi

    stdRET __rdmsr
stdENDP __rdmsr

;------------------------------------------------------------------------------
;  VOID __stdcall _wrmsr(
;    IN UINT32 msr,
;    IN UINT32 msrlo,
;    IN UINT32 msrhi 
;    )
;------------------------------------------------------------------------------
cPublicProc __wrmsr, 3
    mov ecx, dword ptr [esp + 4]  ; msr
    mov eax, dword ptr [esp + 8] ; msrlo
    mov edx, dword ptr [esp + 12] ; msrhi

    wrmsr

    stdRET __wrmsr
stdENDP __wrmsr

;------------------------------------------------------------------------------
;UINT32 _eflags()
;------------------------------------------------------------------------------
cPublicProc _eflags
    pushfd
    pop eax
    stdRET _eflags
stdENDP _eflags

;------------------------------------------------------------------------------
;  VOID
;  WritePortDword (
;    IN   UINT32    out_value
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePortDword, 2
    mov eax, dword ptr [esp + 4]    ; out_value
    mov edx, dword ptr [esp + 8]   ; port_num
    out dx, eax

    stdRET _WritePortDword
stdENDP _WritePortDword

;------------------------------------------------------------------------------
;  VOID
;  WritePortWord (
;    IN   UINT16    out_value
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePortWord, 2
    mov eax, dword ptr [esp + 4]   ; out_value
    mov edx, dword ptr [esp + 8]  ; port_num
    out dx, ax

    stdRET _WritePortWord
stdENDP _WritePortWord

;------------------------------------------------------------------------------
;  VOID
;  WritePortByte (
;    IN   UINT8     out_value
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePortByte, 2
    mov eax, dword ptr [esp + 4]   ; out_value
    mov edx, dword ptr [esp + 8]  ; port_num
    out dx, al

    stdRET _WritePortByte
stdENDP _WritePortByte

;------------------------------------------------------------------------------
;  UINT32
;  ReadPortDword (
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPortDword, 1
    xor eax, eax
    mov edx, dword ptr [esp + 4] ; port_num
    in eax, dx

    stdRET _ReadPortDword
stdENDP _ReadPortDword

;------------------------------------------------------------------------------
;  UINT16
;  ReadPortWord (
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPortWord, 1
    xor eax, eax    
    mov edx, dword ptr [esp + 4] ; port_num
    in ax, dx

    stdRET _ReadPortWord
stdENDP _ReadPortWord

;------------------------------------------------------------------------------
;  UINT8
;  ReadPortByte (
;    IN   UINT16    port_num
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPortByte, 1
    xor eax, eax    
    mov edx, dword ptr [esp + 4] ; port_num
    in al, dx

    stdRET _ReadPortByte
stdENDP _ReadPortByte

;------------------------------------------------------------------------------
;  VOID
;  WriteHighCMOSByte (
;    IN   UINT8     cmos_off
;    IN   UINT8     val
;    )
;------------------------------------------------------------------------------
cPublicProc _WriteHighCMOSByte, 2
    mov eax, dword ptr [esp + 4]  ; cmos_off
    out 72h, al
    mov eax, dword ptr [esp + 8]  ; val
    out 73h, al

    stdRET _WriteHighCMOSByte
stdENDP _WriteHighCMOSByte

;------------------------------------------------------------------------------
;  VOID
;  WriteLowCMOSByte (
;    IN   UINT8     cmos_off
;    IN   UINT8     val
;    )
;------------------------------------------------------------------------------
cPublicProc _WriteLowCMOSByte, 2
    mov eax, dword ptr [esp + 4]  ; cmos_off
    or al, 80h
    out 70h, al
    mov eax, dword ptr [esp + 8]  ; val
    out 71h, al

    stdRET _WriteLowCMOSByte
stdENDP _WriteLowCMOSByte


;------------------------------------------------------------------------------
;  VOID
;  SendAPMSMI (
;    IN   UINT32	apm_port_value
;    IN   UINT64	rax_value               // NOT USED???
;    )
;------------------------------------------------------------------------------
cPublicProc _SendAPMSMI, 2
    mov eax, dword ptr [esp + 4]  ; apm_port_value
    mov dx, 0B2h
    out dx, eax

    stdRET _SendAPMSMI
stdENDP _SendAPMSMI

;------------------------------------------------------------------------------
;  VOID
;  WritePCIByte (
;    IN   UINT32    pci_reg
;    IN   UINT16    cfg_data_port
;    IN   UINT8     byte_value
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePCIByte, 3
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    mov eax, dword ptr [esp + 12]  ; word_value
    mov edx, dword ptr [esp + 8]  ; cfg_data_port
    out dx, al

    stdRET _WritePCIByte
stdENDP _WritePCIByte

;------------------------------------------------------------------------------
;  VOID
;  WritePCIWord (
;    IN   UINT32    pci_reg
;    IN   UINT16    cfg_data_port
;    IN   UINT16    word_value
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePCIWord, 3
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    mov eax, dword ptr [esp + 12]  ; word_value
    mov edx, dword ptr [esp + 8]  ; cfg_data_port
    out dx, ax

    stdRET _WritePCIWord
stdENDP _WritePCIWord


;------------------------------------------------------------------------------
;  VOID
;  WritePCIDword (
;    IN   UINT32	pci_reg
;    IN   UINT16	cfg_data_port    // rdx
;    IN   UINT32	dword_value      // r8
;    )
;------------------------------------------------------------------------------
cPublicProc _WritePCIDword, 3
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    mov eax, dword ptr [esp + 12]  ; dword_value
    mov edx, dword ptr [esp + 8]  ; cfg_data_port
    out dx, eax

    stdRET _WritePCIDword
stdENDP _WritePCIDword

;------------------------------------------------------------------------------
;  unsigned char
;  ReadPCIByte (
;    unsigned int	pci_reg          // rcx
;    unsigned short	cfg_data_port    // rdx
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPCIByte, 2
    cli
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax
	
    xor eax, eax	
    mov edx, dword ptr [esp + 8]   ; cfg_data_port
    in  al, dx
    sti

    stdRET _ReadPCIByte
stdENDP _ReadPCIByte

;------------------------------------------------------------------------------
;  unsigned short
;  ReadPCIWord (
;    unsigned int	pci_reg          // rcx
;    unsigned short	cfg_data_port    // rdx
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPCIWord, 2
    cli
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    xor eax, eax	
    mov edx, dword ptr [esp + 8]   ; cfg_data_port
    in  ax, dx
    sti

    stdRET _ReadPCIWord
stdENDP _ReadPCIWord

;------------------------------------------------------------------------------
;  unsigned int
;  ReadPCIDword (
;    unsigned int	pci_reg          // rcx
;    unsigned short	cfg_data_port    // rdx
;    )
;------------------------------------------------------------------------------
cPublicProc _ReadPCIDword, 2
    cli
    mov eax, dword ptr [esp + 4]  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    xor eax, eax	
    mov edx, dword ptr [esp + 8]   ; cfg_data_port
    in  eax, dx
    sti

    stdRET _ReadPCIDword
stdENDP _ReadPCIDword

;------------------------------------------------------------------------------
;  void
;  _swsmi (
;    unsigned int	smi_code_data	// rcx
;    IN   UINT32	rax_value	// rdx
;    IN   UINT32	rbx_value	// r8
;    IN   UINT32	rcx_value	// r9
;    IN   UINT32	rdx_value	// r10
;    IN   UINT32	rsi_value	// r11
;    IN   UINT32	rdi_value	// r12
;    )
;------------------------------------------------------------------------------

cPublicProc __swsmi, 7
    xor eax, eax
    stdRET __swsmi
stdENDP __swsmi

cPublicProc _ReadCR0
    xor eax, eax
    mov eax, cr0
    stdRET _ReadCR0
stdENDP _ReadCR0

cPublicProc _ReadCR2
    xor eax, eax
    mov eax, cr2
    stdRET _ReadCR2
stdENDP _ReadCR2

cPublicProc _ReadCR3
    xor eax, eax
    mov eax, cr3
    stdRET _ReadCR3
stdENDP _ReadCR3

cPublicProc _ReadCR4
    xor eax, eax
    mov eax, cr4
    stdRET _ReadCR4
stdENDP _ReadCR4

cPublicProc _WriteCR0, 1
    mov eax, dword ptr [esp + 4]
    mov cr0, eax
    stdRET _WriteCR0
stdENDP _WriteCR0

cPublicProc _WriteCR2, 1
    mov eax, dword ptr [esp + 4]
    mov cr2, eax
    stdRET _WriteCR2
stdENDP _WriteCR2

cPublicProc _WriteCR3, 1
    mov eax, dword ptr [esp + 4]
    mov cr3, eax
    stdRET _WriteCR3
stdENDP _WriteCR3

cPublicProc _WriteCR4, 1
    mov eax, dword ptr [esp + 4]
    mov cr4, eax
    stdRET _WriteCR4
stdENDP _WriteCR4

_TEXT    ENDS

END
