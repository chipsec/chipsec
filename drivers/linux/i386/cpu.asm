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
 global hypercall
 global hypercall_page
 
 global __cpuid__
 global __swsmi__

 section .text

setctx_cpuid:
	xchg ebx, [edi+0x4]
	xchg ecx, [edi+0x8]
	xchg edx, [edi+0xc]
	xchg eax, [edi]
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

;------------------------------------------------------------------------------
;  UINT32
;  hypercall(
;    UINT32    ecx_val,                // on stack +08h
;    UINT32    edx_val,                // on stack +0Ch
;    UINT32    reserved1,              // on stack +10h
;    UINT32    reserved2,              // on stack +14h
;    UINT32    reserved3,              // on stack +18h
;    UINT32    reserved4,              // on stack +1Ch
;    UINT32    eax_val,                // on stack +20h
;    UINT32    ebx_val,                // on stack +24h
;    UINT32    edi_val,                // on stack +28h 
;    UINT32    esi_val,                // on stack +2Ch
;    UINT32    xmm_buffer,             // on stack +30h
;    UINT32    hypercall_page          // on stack +34h
;    )
;------------------------------------------------------------------------------

 hypercall:
    push   ebp
    mov    ebp, esp
    push   ebx
    push   esi
    push   edi
    mov    eax, dword [ebp + 30h]
    test   eax, eax
    jz     hypercall_skip_xmm
    pinsrd xmm0, dword [eax + 000h], 00h
    pinsrd xmm0, dword [eax + 004h], 01h
    pinsrd xmm0, dword [eax + 008h], 02h
    pinsrd xmm0, dword [eax + 00Ch], 03h
    pinsrd xmm1, dword [eax + 010h], 00h
    pinsrd xmm1, dword [eax + 014h], 01h
    pinsrd xmm1, dword [eax + 018h], 02h
    pinsrd xmm1, dword [eax + 01Ch], 03h
    pinsrd xmm2, dword [eax + 020h], 00h
    pinsrd xmm2, dword [eax + 024h], 01h
    pinsrd xmm2, dword [eax + 028h], 02h
    pinsrd xmm2, dword [eax + 02Ch], 03h
    pinsrd xmm3, dword [eax + 030h], 00h
    pinsrd xmm3, dword [eax + 034h], 01h
    pinsrd xmm3, dword [eax + 038h], 02h
    pinsrd xmm3, dword [eax + 03Ch], 03h
    pinsrd xmm4, dword [eax + 040h], 00h
    pinsrd xmm4, dword [eax + 044h], 01h
    pinsrd xmm4, dword [eax + 048h], 02h
    pinsrd xmm4, dword [eax + 04Ch], 03h
    pinsrd xmm5, dword [eax + 050h], 00h
    pinsrd xmm5, dword [eax + 054h], 01h
    pinsrd xmm5, dword [eax + 058h], 02h
    pinsrd xmm5, dword [eax + 05Ch], 03h
  hypercall_skip_xmm:
    mov    ecx,  dword [ebp + 08h]
    mov    edx,  dword [ebp + 0Ch]
    mov    eax,  dword [ebp + 20h]
    mov    ebx,  dword [ebp + 24h]
    mov    edi,  dword [ebp + 28h]
    mov    esi,  dword [ebp + 2Ch]
    call   dword [ebp + 34h]
    pop    edi
    pop    esi
    pop    ebx
    pop    ebp
    ret

;------------------------------------------------------------------------------
;  UINT32 hypercall_page ( )
;------------------------------------------------------------------------------

 hypercall_page:
    vmcall
    ret

