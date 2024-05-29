;TITLE   cpu.asm: Assembly code for the x64 resources

 global DisableInterrupts
 global WritePortDword
 global WritePortWord
 global WritePortByte
 global ReadPortDword
 global ReadPortWord
 global ReadPortByte
 global WriteHighCMOSByte
 global WriteLowCMOSByte
 global SendAPMSMI
 global WritePCIByte
 global WritePCIWord
 global WritePCIDword
 global ReadPCIByte
 global ReadPCIWord
 global ReadPCIDword
 global _rdmsr
 global _wrmsr
 global _load_gdt
 global _store_idtr
 global _store_gdtr
 global _store_ldtr
 global _rflags

 global ReadCR0
 global ReadCR2
 global ReadCR3
 global ReadCR4
 global ReadCR8
 global WriteCR0
 global WriteCR2
 global WriteCR3
 global WriteCR4
 global WriteCR8
 global hypercall
 global hypercall_page

 global __cpuid__
 global __swsmi__
 global __swsmi_timed__
 global __swsmi_timed_test__

 section .text

setctx_cpuid:
	xchg rax, [rdi]
	xchg rbx, [rdi+0x8]
	xchg rcx, [rdi+0x10]
	xchg rdx, [rdi+0x18]
	ret

;This function has one argument: CPUID_CTX structure which contain 4 regs: rax, rbx, rcx, rdx:
;------------------------------------------------------------------------------
;  void
; __cpuid__ (
;    CPUID_CTX ctx
;    )
;------------------------------------------------------------------------------

__cpuid__:

	call setctx_cpuid

	cpuid

	call setctx_cpuid

	ret

;------------------------------------------------------------------------------
; UINT64 _rflags()
;------------------------------------------------------------------------------
_rflags:
    pushfq
    pop rax
    ret

;------------------------------------------------------------------------------
; void _store_idtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_store_idtr:
    sidt [rdi]
    ret

;------------------------------------------------------------------------------
; void _load_idtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_load_idtr:
    lidt [rdi]
    ret

;------------------------------------------------------------------------------
; void _store_gdtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_store_gdtr: 
    sgdt [rdi]
    ret

;------------------------------------------------------------------------------
; void _load_gdtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_load_gdtr: 
    lgdt [rdi]
    ret

;------------------------------------------------------------------------------
; void _store_ldtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_store_ldtr:
    ;sldt fword ptr [rdi]
    sldt [rdi]
    ret

;------------------------------------------------------------------------------
; void _load_ldtr(
;   unsigned char *address // rdi
;   )
;------------------------------------------------------------------------------
_load_ldtr: 
    ;lldt fword ptr [rdi]
    ret

;------------------------------------------------------------------------------
; void _load_gdt(
;   unsigned char *value // rdi
;   )
;------------------------------------------------------------------------------
_load_gdt: 

    sgdt [rdi]
    lgdt [rdi]

    ret

;------------------------------------------------------------------------------
;  void _rdmsr( 
;    unsigned int msr_num, // rdi
;    unsigned int* msr_lo, // rsi
;    unsigned int* msr_hi  // rdx
;    )
;------------------------------------------------------------------------------
_rdmsr: 
    push r10
    push r11
    push rax
    push rdx


    mov rcx, rdi
    mov r10, rsi ; msr_lo
    mov r11, rdx ; msr_hi

    ; rcx has msr_num
    rdmsr

    ; Write MSR results in edx:eax
    mov [r10], eax

    mov [r11], edx

    pop rdx
    pop rax
    pop r11
    pop r10

    ret

;------------------------------------------------------------------------------
;  void _wrmsr(
;    unsigned int msr_num, // rdi
;    unsigned int msr_hi,  // rsi
;    unsigned int msr_lo   // rdx
;    )
;------------------------------------------------------------------------------
_wrmsr: 
    push rax
    push rcx

    ; move msr_num to rcx 
    mov rcx, rdi
    ; move msr_lo from rdx to rax
    mov rax, rsi
    ; move msr_hi to rdx
    wrmsr

    pop rcx
    pop rax
    ret

;------------------------------------------------------------------------------
;  void
;  DisableInterrupts (
;    )
;------------------------------------------------------------------------------
DisableInterrupts:
    cli
    ret

;------------------------------------------------------------------------------
;  void
;  WritePortDword (
;    unsigned int	out_value          // rdi
;    unsigned short	port_num           // rsi
;    )
;------------------------------------------------------------------------------
WritePortDword: 
    push rax
    push rdx

    mov rax, rdi
    mov rdx, rsi	
    out dx, eax

    pop rdx
    pop rax
    ret

;------------------------------------------------------------------------------
;  void
;  WritePortWord (
;    unsigned short	out_value          // rdi 
;    unsigned short	port_num           // rsi
;    )
;------------------------------------------------------------------------------
WritePortWord: 
    push rax
    push rdx

    mov rax, rdi
    mov rdx, rsi	
    out dx, ax

    pop rdx
    pop rax
    ret

;------------------------------------------------------------------------------
;  void
;  WritePortByte (
;    unsigned char	out_value          // rdi
;    unsigned short	port_num           // rsi
;    )
;------------------------------------------------------------------------------
WritePortByte:
    push rax
    push rdx

    mov rax, rdi
    mov rdx, rsi	
    out dx, al

    pop rdx
    pop rax
    ret

;------------------------------------------------------------------------------
;  unsigned int
;  ReadPortDword (
;    unsigned short	port_num           // rdi
;    )
;------------------------------------------------------------------------------
ReadPortDword: 
    push rdx

    xor rax, rax    
    mov rdx, rdi
    in eax, dx

    pop rdx
    ret

;------------------------------------------------------------------------------
;  unsigned short
;  ReadPortWord (
;    unsigned short	port_num           // rdi
;    )
;------------------------------------------------------------------------------
ReadPortWord: 
    push rdx

    xor rax, rax    
    mov rdx, rdi
    in ax, dx

    pop rdx
    ret

;------------------------------------------------------------------------------
;  unsigned char
;  ReadPortByte (
;    unsigned short	port_num           // rdi
;    )
;------------------------------------------------------------------------------
ReadPortByte:
    push rdx

    xor rax, rax    
    mov rdx, rdi
    in al, dx

    pop rdx
    ret


;------------------------------------------------------------------------------
;  void
;  WriteHighCMOSByte (
;    unsigned char	cmos_off        // rdi
;    unsigned char	val   		// rsi
;    )
;------------------------------------------------------------------------------
WriteHighCMOSByte:
    push rax

    mov rax, rdi
    out 72h, al
    mov rax, rsi
    out 73h, al

    pop rax
    ret
;------------------------------------------------------------------------------
;  void
;  WriteLowCMOSByte (
;    unsigned char	cmos_off        // rdi
;    unsigned char	val   		// rsi
;    )
;------------------------------------------------------------------------------
WriteLowCMOSByte:
    push rax

    mov rax, rdi 
    or al, 80h
    out 70h, al
    mov rax, rsi
    out 71h, al

    pop rax
    ret

; @TODO: looks incorrect
;------------------------------------------------------------------------------
;  void
;  SendAPMSMI (
;    unsigned int	apm_port_value          // rdi
;    IN   UINT64	rax_value               // rsi
;    )
;------------------------------------------------------------------------------
SendAPMSMI:
    push rax
    push rdx

    mov rax, rdi
    mov rdx, rsi
    mov dx, 0B2h
    out dx, eax

    pop rdx
    pop rax
    ret

;------------------------------------------------------------------------------
;This function has one argument: SMI_CTX structure pointer which contain SMI code and data values and 6 regs: rax, rbx, rcx, rdx, rsi, rdi:
;    IN       UINT64	smi_code_data (only lower 16 bit used)
;    IN/OUT   UINT64	rax_value
;    IN/OUT   UINT64	rbx_value
;    IN/OUT   UINT64	rcx_value
;    IN/OUT   UINT64	rdx_value
;    IN/OUT   UINT64	rsi_value
;    IN/OUT   UINT64	rdi_value
;------------------------------------------------------------------------------
;  void
; __swsmi__ (
;    SMI_CTX ctx
;    )
;------------------------------------------------------------------------------
__swsmi__:
    mov  r10, rdi

    ; setting up GPR (arguments) to SMI handler call
    ; notes:
    ;   RAX will get partially overwritten (AX) by smi_code_data
    xchg rax, [r10+08h]  ; rax_value (partially overwritten with smi_code_data)
    mov  ax,  [r10+0h]   ; smi_code_data
    xchg rbx, [r10+010h] ; rbx_value
    xchg rcx, [r10+018h] ; rcx_value
    xchg rdx, [r10+020h] ; rdx_value
    xchg rsi, [r10+028h] ; rsi_value
    xchg rdi, [r10+030h] ; rdi_value

    ; Output smi_code_data split up to their designated ports, SW SMI data
    ; (0xB3) and SW SMI control (0xB2), respectively.
    ;
    ; Resist from outputting both at once as a single word, as some systems
    ; reject the request if the i/o spans more than a byte, e.g.:
    ; https://github.com/tianocore/edk2-platforms/blob/aa3f6fd542e99dde4206537b095f1a2201275e75/Silicon/Intel/CoffeelakeSiliconPkg/Pch/PchSmiDispatcher/Smm/PchSmmSw.c#L314
    ror ax, 8
    out 0B3h, al
    ror ax, 8
    out 0B2h, al

    ; some SMI handlers return data/errorcode in GPRs, need to return this to the caller
    xchg rax, [r10+08h]  ; rax_value
    xchg rbx, [r10+010h] ; rbx_value
    xchg rcx, [r10+018h] ; rcx_value
    xchg rdx, [r10+020h] ; rdx_value
    xchg rsi, [r10+028h] ; rsi_value
    xchg rdi, [r10+030h] ; rdi_value

    ret

;------------------------------------------------------------------------------
;This function has two arguments: SMI_CTX structure pointer which contain SMI code and data values and 6 regs: rax, rbx, rcx, rdx, rsi, rdi:
;    IN       UINT64	smi_code_data (only lower 16 bit used)
;    IN/OUT   UINT64	rax_value
;    IN/OUT   UINT64	rbx_value
;    IN/OUT   UINT64	rcx_value
;    IN/OUT   UINT64	rdx_value
;    IN/OUT   UINT64	rsi_value
;    IN/OUT   UINT64	rdi_value
; The second argument is a pointer to an unsigned long to return the measured execution time
;------------------------------------------------------------------------------
;  void
; __swsmi_timed__ (
;    SMI_CTX ctx            // rdi
;    unsigned long *time    // rsi
;    )
;------------------------------------------------------------------------------
__swsmi_timed__:
    mov  r10, rdi
    push r12 ; callee-saved register
    mov  r12, rsi

    ; setting up GPR (arguments) to SMI handler call
    ; notes:
    ;   RAX will get partially overwritten (AX) by smi_code_data
    xchg rax, [r10+08h]  ; rax_value (partially overwritten with smi_code_data)
    mov  ax,  [r10+0h]   ; smi_code_data
    xchg rbx, [r10+010h] ; rbx_value
    xchg rcx, [r10+018h] ; rcx_value
    xchg rdx, [r10+020h] ; rdx_value
    xchg rsi, [r10+028h] ; rsi_value
    xchg rdi, [r10+030h] ; rdi_value

    ; Output smi_code_data split up to their designated ports, SW SMI data
    ; (0xB3) and SW SMI control (0xB2), respectively.
    ;
    ; Resist from outputting both at once as a single word, as some systems
    ; reject the request if the i/o spans more than a byte, e.g.:
    ; https://github.com/tianocore/edk2-platforms/blob/aa3f6fd542e99dde4206537b095f1a2201275e75/Silicon/Intel/CoffeelakeSiliconPkg/Pch/PchSmiDispatcher/Smm/PchSmmSw.c#L314
    ror ax, 8
    out 0B3h, al

    ; read time-stamp counter
    mov r9, rax
    mov r11, rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax
    mov rax, r9
    mov rdx, r11

    ; trigger SMI
    ror ax, 8
    out 0B2h, al

    ; measure SMI execution time
    mov r9, rax
    mov r11, rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r8
    mov [r12], rax
    mov rax, r9
    mov rdx, r11

    ; some SMI handlers return data/errorcode in GPRs, need to return this to the caller
    xchg rax, [r10+08h]  ; rax_value
    xchg rbx, [r10+010h] ; rbx_value
    xchg rcx, [r10+018h] ; rcx_value
    xchg rdx, [r10+020h] ; rdx_value
    xchg rsi, [r10+028h] ; rsi_value
    xchg rdi, [r10+030h] ; rdi_value

    pop r12
    ret

;------------------------------------------------------------------------------
;  void
;  WritePCIByte (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    unsigned char	byte_value       // rdx
;    )
;------------------------------------------------------------------------------
WritePCIByte:
    push rax
    push rsi
    push rdx

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    pop rax      ; byte_value
    pop rdx       ; cfg_data_port
    out dx, al
    sti

    pop rax  
    ret

;------------------------------------------------------------------------------
;  void
;  WritePCIWord (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    unsigned short	word_value       // rdx
;    )
;------------------------------------------------------------------------------
WritePCIWord:
    push rax
    push rsi
    push rdx

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    pop rax       ; byte_value
    pop rdx       ; cfg_data_port
    out dx, ax
    sti

    pop rax  
    ret

;------------------------------------------------------------------------------
;  void
;  WritePCIDword (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    unsigned int	dword_value      // rdx
;    )
;------------------------------------------------------------------------------
WritePCIDword: 
    push rax
    push rsi
    push rdx

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    pop rax       ; byte_value
    pop rdx       ; cfg_data_port
    out dx, eax
    sti

    pop rax  
    ret

;------------------------------------------------------------------------------
;  unsigned char
;  ReadPCIByte (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    )
;------------------------------------------------------------------------------
ReadPCIByte:

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax
	
    xor rax, rax	
    mov rdx, rsi       ; cfg_data_port
    in  al, dx
    sti

    ret

;------------------------------------------------------------------------------
;  unsigned short
;  ReadPCIWord (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    )
;------------------------------------------------------------------------------
ReadPCIWord: 

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    xor rax, rax	
    mov rdx, rsi       ; cfg_data_port
    in  ax, dx
    sti

    ret

;------------------------------------------------------------------------------
;  unsigned int
;  ReadPCIDword (
;    unsigned int	pci_reg          // rdi
;    unsigned short	cfg_data_port    // rsi
;    )
;------------------------------------------------------------------------------
ReadPCIDword:

    cli
    mov rax, rdi  ; pci_reg
    mov dx, 0CF8h
    out dx, eax

    xor rax, rax	
    mov rdx, rsi       ; cfg_data_port
    in  eax, dx
    sti

    ret

ReadCR0:
    xor rax, rax
    mov rax, cr0
    ret

ReadCR2:
    xor rax, rax
    mov rax, cr2
    ret

ReadCR3:
    xor rax, rax
    mov rax, cr3
    ret

ReadCR4:
    xor rax, rax
    mov rax, cr4
    ret

ReadCR8:
    xor rax, rax
    mov rax, cr8
    ret

WriteCR0:
    mov cr0, rdi
    ret

WriteCR2:
    mov cr2, rdi
    ret

WriteCR3:
    mov cr3, rdi
    ret

WriteCR4:
    mov cr4, rdi
    ret

WriteCR8:
    mov cr8, rdi
    ret

;------------------------------------------------------------------------------
;  UINT64
;  hypercall(
;    UINT64    rcx_val,                // rdi
;    UINT64    rdx_val,                // rsi
;    UINT64    r8_val,                 // rdx
;    UINT64    r9_val,                 // rcx
;    UINT64    r10_val,                // r8
;    UINT64    r11_val,                // r9
;    UINT64    rax_val,                // on stack +10h
;    UINT64    rbx_val,                // on stack +18h
;    UINT64    rdi_val,                // on stack +20h 
;    UINT64    rsi_val,                // on stack +28h
;    UINT64    xmm_buffer,             // on stack +30h
;    UINT64    hypercall_page          // on stack +38h
;    )
;------------------------------------------------------------------------------

hypercall:
    push   rbp
    mov    rbp, rsp
    push   rbx
    mov    rax, qword [rbp + 30h]
    test   rax, rax
    jz     hypercall_skip_xmm
    pinsrq xmm0, qword [rax + 000h], 00h
    pinsrq xmm0, qword [rax + 008h], 01h
    pinsrq xmm1, qword [rax + 010h], 00h
    pinsrq xmm1, qword [rax + 018h], 01h
    pinsrq xmm2, qword [rax + 020h], 00h
    pinsrq xmm2, qword [rax + 028h], 01h
    pinsrq xmm3, qword [rax + 030h], 00h
    pinsrq xmm3, qword [rax + 038h], 01h
    pinsrq xmm4, qword [rax + 040h], 00h
    pinsrq xmm4, qword [rax + 048h], 01h
    pinsrq xmm5, qword [rax + 050h], 00h
    pinsrq xmm5, qword [rax + 058h], 01h
  hypercall_skip_xmm:
    mov    r11, r9
    mov    r10, r8
    mov    r9,  rcx
    mov    r8,  rdx
    mov    rdx, rsi
    mov    rcx, rdi
    mov    rdi, qword [rbp + 20h]
    mov    rsi, qword [rbp + 28h]
    mov    rax, qword [rbp + 10h]
    mov    rbx, qword [rbp + 18h]
    call   qword [rbp + 38h]
    pop    rbx
    pop    rbp
    ret

;------------------------------------------------------------------------------
;  UINT64 hypercall_page ( )
;------------------------------------------------------------------------------

hypercall_page:
    vmcall
    ret

