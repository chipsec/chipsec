;TITLE   cpu.asm: Assembly code for the i386 resources

 global _store_idtr
 global _load_idtr
 global _store_gdtr
 global _store_ldtr
 global _rdmsr
 global _wrmsr
 global _eflags
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

 global ReadCR0
 global ReadCR2
 global ReadCR3
 global ReadCR4
 global WriteCR0
 global WriteCR2
 global WriteCR3
 global WriteCR4
 
 global __cpuid__
 global __swsmi__

 section .text

setctx_cpuid:
	xchg ebx, [eax+0x4]
	xchg ecx, [eax+0x8]
	xchg edx, [eax+0xc]
	xchg eax, [eax]
	ret

;This function has one argument: CPUID_CTX structure which contain 4 regs: rax, rbx, rcx, rdx:
;------------------------------------------------------------------------------
;  void
; __cpuid__ (
;    CPUID_CTX ctx
;    )
;------------------------------------------------------------------------------

__cpuid__:

        push edi

        mov  edi, eax
	call setctx_cpuid

	cpuid

	call setctx_cpuid

	pop edi

	ret

; TODO: need to implement
__swsmi__:
	ret

;------------------------------------------------------------------------------
; void _store_idtr(
;   unsigned char *address // eax
;   )
;------------------------------------------------------------------------------
 _store_idtr:
    push ecx

    mov ecx, eax
    sidt [ecx]
 
    pop ecx

    ret

;------------------------------------------------------------------------------
; void _load_idtr(
;   unsigned char *address // eax
;   )
;------------------------------------------------------------------------------
 _load_idtr:
    push ecx

    mov ecx, eax
    lidt [ecx]

    pop ecx

    ret

;------------------------------------------------------------------------------
; void _store_gdtr(
;   unsigned char *address // eax
;   )
;------------------------------------------------------------------------------
 _store_gdtr:
    push ecx

    mov ecx, eax
    sgdt [ecx]

    pop ecx

    ret

;------------------------------------------------------------------------------
; void _store_ldtr(
;   unsigned char *address // eax
;   )
;------------------------------------------------------------------------------
 _store_ldtr:
    push ecx

    mov ecx, eax
    sldt word [ecx]

    pop ecx

    ret

;------------------------------------------------------------------------------
;    IN UINT32 msr,     //eax
;    OUT UINT32* msrlo, //edx
;    OUT UINT32* msrhi  //ecx
;    )
;------------------------------------------------------------------------------

 _rdmsr:

    push ebx
    push esi

    mov ebx, ecx ; msrhi
    mov ecx, eax ; msr
    mov esi, edx ; msrlo

    rdmsr

    mov ecx, esi
    mov [ecx], eax ; msrlo
    mov ecx, ebx
    mov [ecx], edx ; msrhi

    pop esi
    pop ebx

    ret


;------------------------------------------------------------------------------
;    IN UINT32 msr,   //eax
;    IN UINT32 msrlo, //edx
;    IN UINT32 msrhi  //ecx 
;    )
;------------------------------------------------------------------------------
 _wrmsr:
    
    push ebx

    mov ebx, ecx

    mov ecx, eax  ; msr
    mov eax, edx ; msrlo
    mov edx, ebx ; msrhi

    pop ebx

    wrmsr
    ret


;------------------------------------------------------------------------------
;UINT32 _eflags()
;------------------------------------------------------------------------------
 _eflags:
    pushfd
    pop eax
    ret

;------------------------------------------------------------------------------
;  VOID
;  WritePortDword (
;    IN   UINT32    out_value //eax
;    IN   UINT16    port_num  //edx
;    )
;------------------------------------------------------------------------------
 WritePortDword:

    out dx, eax

    ret

;------------------------------------------------------------------------------
;  VOID
;  WritePortWord (
;    IN   UINT16    outvalue //eax
;    IN   UINT16    portnum  //edx
;    )
;------------------------------------------------------------------------------
 WritePortWord:
    out dx, ax
    ret


;------------------------------------------------------------------------------
;  VOID
;  WritePortByte (
;    IN   UINT8     outvalue //eax
;    IN   UINT16    portnum  //edx
;    )
;------------------------------------------------------------------------------
 WritePortByte:
    out dx, al
    ret


;------------------------------------------------------------------------------
;  UINT32
;  ReadPortDword (
;    IN   UINT16    portnum //eax
;    )
;------------------------------------------------------------------------------
 ReadPortDword:
  
    push edx

    mov edx, eax ; portnum
    xor eax, eax
    in eax, dx

    pop edx

    ret


;------------------------------------------------------------------------------
;  UINT16
;  ReadPortWord (
;    IN   UINT16    portnum //eax
;    )
;------------------------------------------------------------------------------
 ReadPortWord:

    push edx

    mov edx, eax ; portnum
    xor eax, eax    
    in ax, dx

    pop edx

    ret


;------------------------------------------------------------------------------
;  UINT8
;  ReadPortByte (
;    IN   UINT16    portnum //eax
;    )
;------------------------------------------------------------------------------
 ReadPortByte:

    push edx

    mov edx, eax; portnum
    xor eax, eax    
    in al, dx

    pop edx

    ret

;------------------------------------------------------------------------------
;  VOID
;  WriteHighCMOSByte (
;    IN   UINT8     cmosoff //eax
;    IN   UINT8     val     //edx
;    )
;------------------------------------------------------------------------------
 WriteHighCMOSByte:
    out 72h, al
    mov eax, edx  ; val
    out 73h, al
    ret

;------------------------------------------------------------------------------
;  VOID
;  WriteLowCMOSByte (
;    IN   UINT8     cmosoff //eax
;    IN   UINT8     val     //edx
;    )
;------------------------------------------------------------------------------
 WriteLowCMOSByte:
    or al, 80h
    out 70h, al
    mov eax, edx  ; val
    out 71h, al
    ret

;------------------------------------------------------------------------------
;  VOID
;  SendAPMSMI (
;    IN   UINT32	apmportvalue  //eax
;    IN   UINT64	raxvalue               // NOT USED???
;    )
;------------------------------------------------------------------------------
 SendAPMSMI:
    mov dx, 0B2h
    out dx, eax
    ret


;------------------------------------------------------------------------------
;  VOID
;  WritePCIByte (
;    IN   UINT32    pcireg       //eax
;    IN   UINT16    cfgdataport  //edx
;    IN   UINT8     bytevalue    //ecx
;    )
;------------------------------------------------------------------------------
 WritePCIByte:

    push edx

    mov dx, 0CF8h
    out dx, eax

    mov eax, ecx              ; bytevalue
    pop edx
    out dx, al

    ret

;------------------------------------------------------------------------------
;  VOID
;  WritePCIWord (
;    IN   UINT32    pcireg      //eax
;    IN   UINT16    cfgdataport //edx
;    IN   UINT16    wordvalue   //ecx
;    )
;------------------------------------------------------------------------------
 WritePCIWord:

    push edx

    mov dx, 0CF8h
    out dx, eax

    mov eax, ecx              ; wordvalue
    pop edx
    out dx, ax

    ret

;------------------------------------------------------------------------------
;  VOID
;  WritePCIDword (
;    IN   UINT32	pcireg         //eax
;    IN   UINT16	cfgdataport    //edx
;    IN   UINT32	dwordvalue     //ecx
;    )
;------------------------------------------------------------------------------
 WritePCIDword:

    push edx

    mov dx, 0CF8h
    out dx, eax

    mov eax, ecx  ; dwordvalue
    pop edx
    out dx, eax
    ret


;------------------------------------------------------------------------------
;  unsigned char
;  ReadPCIByte (
;    unsigned int	pcireg         //eax
;    unsigned short	cfgdataport    //edx 
;    )
;------------------------------------------------------------------------------
 ReadPCIByte:

    push edx

    cli
    mov dx, 0CF8h
    out dx, eax
	
    xor eax, eax	
    pop edx
    in  al, dx
    sti

    ret

;------------------------------------------------------------------------------
;  unsigned short
;  ReadPCIWord (
;    unsigned int	pcireg         //eax 
;    unsigned short	cfgdataport    //edx
;    )
;------------------------------------------------------------------------------
 ReadPCIWord:

    push edx

    cli
    mov dx, 0CF8h
    out dx, eax

    xor eax, eax	
    pop edx
    in  ax, dx
    sti

    ret

;------------------------------------------------------------------------------
;  unsigned int
;  ReadPCIDword (
;    unsigned int	pcireg         //eax
;    unsigned short	cfgdataport    //edx
;    )
;------------------------------------------------------------------------------
 ReadPCIDword:

    push edx

    cli
    mov dx, 0CF8h
    out dx, eax

    xor eax, eax	
    pop edx
    in  eax, dx
    sti


    ret

;------------------------------------------------------------------------------
 ReadCR0:
    xor eax, eax
    mov eax, cr0
    ret

 ReadCR2:
    xor eax, eax
    mov eax, cr2
    ret

 ReadCR3:
    xor eax, eax
    mov eax, cr3
    ret

 ReadCR4:
    xor eax, eax
    mov eax, cr4
    ret

 WriteCR0:
    mov cr0, eax
    ret

 WriteCR2:
    mov cr2, eax
    ret

 WriteCR3:
    mov cr3, eax
    ret

 WriteCR4:
    mov cr4, eax
    ret

