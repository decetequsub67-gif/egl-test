#include <windows.h>
#include <intrin.h>

// Minimal PEB/LDR structures (no winternl.h to keep imports clean)
typedef struct _PEB_LDR_DATA2 {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

typedef struct _PEB2 {
    BYTE           Reserved1[2];
    BYTE           BeingDebugged;
    BYTE           Reserved2[1];
    PVOID          Reserved3[2];
    PPEB_LDR_DATA2 Ldr;
} PEB2, *PPEB2;

#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/ENTRY:__dummy_entry")

// Helper typedefs
typedef HANDLE (WINAPI* fnGetStdHandle)(DWORD);
typedef BOOL   (WINAPI* fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI* fnWriteConsoleW)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);
typedef void   (WINAPI* fnExitProcess)(UINT);
typedef BOOL   (WINAPI* fnIsDebuggerPresent)(VOID);

// Linker-provided image base (не требует PEB-обхода)
extern "C" IMAGE_DOS_HEADER __ImageBase;

// Forward declarations
extern "C" void obf_stage2();
extern "C" void real_logic();

// ====================================================
// SECTIONS: .idata = stage2 (зашифрован, ERW), .crt = real_logic (зашифрован, ERW)
// ====================================================
#pragma comment(linker, "/SECTION:.idata,ERW")
#pragma comment(linker, "/SECTION:.crt,ERW")

// ====================================================
// SECTION .text (Decoys + Entry Point)
// ====================================================
#pragma code_seg(".text")

// ---- DECOY STUBS: мусорные пустые функции, забивают список функций в IDA ----
#define DECOY(n) __declspec(noinline) void decoy_##n() { volatile int t = 0x1000 + (n); (void)t; }
DECOY(0)  DECOY(1)  DECOY(2)  DECOY(3)
DECOY(4)  DECOY(5)  DECOY(6)  DECOY(7)
DECOY(8)  DECOY(9)  DECOY(10) DECOY(11)
DECOY(12) DECOY(13) DECOY(14) DECOY(15)
DECOY(16) DECOY(17) DECOY(18) DECOY(19)
DECOY(20) DECOY(21) DECOY(22) DECOY(23)

// Таблица ссылок, чтобы линкер не выкинул заглушки и скрытые функции по /OPT:REF
static void (*volatile stub_keep[])(void) = {
    decoy_0,  decoy_1,  decoy_2,  decoy_3,
    decoy_4,  decoy_5,  decoy_6,  decoy_7,
    decoy_8,  decoy_9,  decoy_10, decoy_11,
    decoy_12, decoy_13, decoy_14, decoy_15,
    decoy_16, decoy_17, decoy_18, decoy_19,
    decoy_20, decoy_21, decoy_22, decoy_23,
    obf_stage2, real_logic
};

// ====================================================
// STAGE 1 (entry): размазан в state-machine с opaque-предикатами,
// чтобы декомпил в IDA превратился в нечитаемую кашу
// ====================================================
extern "C" void __stdcall __dummy_entry() {
    // Volatile-чтение, чтобы линкер оставил таблицу (а с ней все функции из неё)
    { volatile void* keep_alive = (volatile void*)stub_keep[0]; (void)keep_alive; }

    // Opaque-предикат: первый байт 'MZ' = 0x4D (нечётный) -> всегда истинно,
    // но компилятор не может это вычислить заранее (volatile)
    #define OPAQUE_TRUE ((*(volatile const BYTE*)&__ImageBase & 1) != 0)

    volatile DWORD       state = 0;
    volatile DWORD       j     = 0;
    volatile DWORD       tsize = 0;
    volatile BYTE*       tgt   = NULL;
    volatile BYTE        k1    = 0;

    while (state != 0x5A5A) {
        if (!OPAQUE_TRUE) { state = 0xDEAD; continue; } // никогда не выполняется

        switch (state) {
        case 0: {
            PIMAGE_DOS_HEADER dos = &__ImageBase;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)&__ImageBase + dos->e_lfanew);
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            DWORD i = 0;
            while (i < nt->FileHeader.NumberOfSections) {
                if (*(DWORD*)sec[i].Name == 0x6164692E) { // ".ida" (LE)
                    tgt = (BYTE*)&__ImageBase + sec[i].VirtualAddress;
                    tsize = sec[i].Misc.VirtualSize;
                    break;
                }
                i++;
            }
            k1 = (BYTE)(dos->e_lfanew ^ nt->FileHeader.NumberOfSections);
            state = (OPAQUE_TRUE ? 1u : 0xDEADu);
            break;
        }
        case 1: {
            if (tgt && j < tsize) {
                tgt[j] = tgt[j] ^ (BYTE)(k1 ^ (BYTE)(j & 0x0F));
                j++;
                volatile DWORD m = j * 0x9E3779B9u + (DWORD)(uintptr_t)tgt; (void)m; // мусор
            } else {
                state = 0x5A5A;
            }
            if (!OPAQUE_TRUE) { state = 0xBEEF; } // никогда
            break;
        }
        case 0xDEAD: { // недостижимый мусор
            volatile DWORD q = tsize + 0x1337;
            state = q ^ q;
            break;
        }
        case 0xBEEF: { // недостижимый мусор
            volatile DWORD q = 0x5A5Au;
            state = q - 0x5A59u;
            break;
        }
        default:
            state = 0x5A5A;
            break;
        }
    }
    #undef OPAQUE_TRUE

    // Косвенный вызов через volatile-вычисляемый индекс:
    // компилятор не может свернуть это в прямой jmp на stage2
    volatile unsigned int a = 0x5F ^ 0x18;
    volatile unsigned int b = 0x5F ^ a; // всегда 24 = индекс obf_stage2 в таблице
    stub_keep[b]();
}

// ====================================================
// STAGE 2 (в зашифрованной .idata): расшифровывает .crt и зовёт real_logic
// ====================================================
#pragma code_seg(".idata")

extern "C" void obf_stage2() {
    PIMAGE_DOS_HEADER dos = &__ImageBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)&__ImageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    BYTE* tgt = NULL;
    DWORD tsize = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (*(DWORD*)sec[i].Name == 0x7463722E) { // ".crt" (LE)
            tgt = (BYTE*)&__ImageBase + sec[i].VirtualAddress;
            tsize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!tgt || tsize == 0) return;

    for (DWORD j = 0; j < tsize; j++) {
        tgt[j] ^= (BYTE)(0x5F ^ (BYTE)(j & 0x0F));
    }

    // real_logic занимает секцию .crt с самого начала
    typedef void (*fnRealLogic)();
    volatile fnRealLogic pReal = (fnRealLogic)tgt;
    pReal();
}

// ---- Strings (automatically encrypted on disk because they are in the stack of real_logic) ----
#pragma code_seg(".crt")
extern "C" void real_logic() {
    HMODULE             hK32 = NULL;
    fnGetStdHandle      pGSH = NULL;
    fnWriteFile         pWF  = NULL;
    fnWriteConsoleW     pWCW = NULL;
    fnExitProcess       pEP  = NULL;
    fnIsDebuggerPresent pIDP = NULL;

    // Используем простой массив байт со XOR-маскированием строки для исключения неявной rdata:
    // "GetStdHandle" ^= 0x5F
    unsigned char str_gsh[13];
    str_gsh[0]='G'^0x5F; str_gsh[1]='e'^0x5F; str_gsh[2]='t'^0x5F; str_gsh[3]='S'^0x5F; str_gsh[4]='t'^0x5F; str_gsh[5]='d'^0x5F;
    str_gsh[6]='H'^0x5F; str_gsh[7]='a'^0x5F; str_gsh[8]='n'^0x5F; str_gsh[9]='d'^0x5F; str_gsh[10]='l'^0x5F; str_gsh[11]='e'^0x5F; str_gsh[12]=0;
    for(int i=0; i<12; i++) str_gsh[i] ^= 0x5F;

    // "WriteFile" ^= 0x5F
    unsigned char str_wf[10];
    str_wf[0]='W'^0x5F; str_wf[1]='r'^0x5F; str_wf[2]='i'^0x5F; str_wf[3]='t'^0x5F; str_wf[4]='e'^0x5F; str_wf[5]='F'^0x5F;
    str_wf[6]='i'^0x5F; str_wf[7]='l'^0x5F; str_wf[8]='e'^0x5F; str_wf[9]=0;
    for(int i=0; i<9; i++) str_wf[i] ^= 0x5F;

    // "ExitProcess" ^= 0x5F
    unsigned char str_ep[12];
    str_ep[0]='E'^0x5F; str_ep[1]='x'^0x5F; str_ep[2]='i'^0x5F; str_ep[3]='t'^0x5F; str_ep[4]='P'^0x5F; str_ep[5]='r'^0x5F;
    str_ep[6]='o'^0x5F; str_ep[7]='c'^0x5F; str_ep[8]='e'^0x5F; str_ep[9]='s'^0x5F; str_ep[10]='s'^0x5F; str_ep[11]=0;
    for(int i=0; i<11; i++) str_ep[i] ^= 0x5F;

    // "WriteConsoleW" ^= 0x5F
    unsigned char str_wcw[14];
    str_wcw[0]='W'^0x5F; str_wcw[1]='r'^0x5F; str_wcw[2]='i'^0x5F; str_wcw[3]='t'^0x5F; str_wcw[4]='e'^0x5F; str_wcw[5]='C'^0x5F;
    str_wcw[6]='o'^0x5F; str_wcw[7]='n'^0x5F; str_wcw[8]='s'^0x5F; str_wcw[9]='o'^0x5F; str_wcw[10]='l'^0x5F; str_wcw[11]='e'^0x5F; str_wcw[12]='W'^0x5F; str_wcw[13]=0;
    for(int i=0; i<13; i++) str_wcw[i] ^= 0x5F;

    // "IsDebuggerPresent" ^= 0x5F
    unsigned char str_idp[18];
    str_idp[0]='I'^0x5F; str_idp[1]='s'^0x5F; str_idp[2]='D'^0x5F; str_idp[3]='e'^0x5F; str_idp[4]='b'^0x5F; str_idp[5]='u'^0x5F;
    str_idp[6]='g'^0x5F; str_idp[7]='g'^0x5F; str_idp[8]='e'^0x5F; str_idp[9]='r'^0x5F; str_idp[10]='P'^0x5F; str_idp[11]='r'^0x5F;
    str_idp[12]='e'^0x5F; str_idp[13]='s'^0x5F; str_idp[14]='e'^0x5F; str_idp[15]='n'^0x5F; str_idp[16]='t'^0x5F; str_idp[17]=0;
    for(int i=0; i<17; i++) str_idp[i] ^= 0x5F;

    // Получаем базу kernel32.dll
    #if defined(_WIN64)
    BYTE* peb_loc = (BYTE*)__readgsqword(0x60);
    BYTE* ldr_loc = *(BYTE**)(peb_loc + 0x18);
    LIST_ENTRY* head_loc = (LIST_ENTRY*)(ldr_loc + 0x20);
    LIST_ENTRY* cur_loc  = head_loc->Flink;
    cur_loc = cur_loc->Flink;
    cur_loc = cur_loc->Flink;
    hK32 = *(HMODULE*)((BYTE*)cur_loc + 0x20);
    #else
    BYTE* peb_loc = (BYTE*)__readfsdword(0x30);
    BYTE* ldr_loc = *(BYTE**)(peb_loc + 0x0C);
    LIST_ENTRY* head_loc = (LIST_ENTRY*)(ldr_loc + 0x14);
    LIST_ENTRY* cur_loc  = head_loc->Flink;
    cur_loc = cur_loc->Flink;
    cur_loc = cur_loc->Flink;
    hK32 = *(HMODULE*)((BYTE*)cur_loc + 0x10);
    #endif

    // Resolving functions sequentially without any step loops or arrays:
    {
        FARPROC found_fp = NULL;
        PIMAGE_DOS_HEADER dos_k = (PIMAGE_DOS_HEADER)hK32;
        PIMAGE_NT_HEADERS nt_k  = (PIMAGE_NT_HEADERS)((BYTE*)hK32 + dos_k->e_lfanew);
        DWORD rva_k = nt_k->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (rva_k) {
            PIMAGE_EXPORT_DIRECTORY exp_k = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hK32 + rva_k);
            DWORD* names_k = (DWORD*)((BYTE*)hK32 + exp_k->AddressOfNames);
            WORD*  ords_k  = (WORD*) ((BYTE*)hK32 + exp_k->AddressOfNameOrdinals);
            DWORD* fns_k   = (DWORD*)((BYTE*)hK32 + exp_k->AddressOfFunctions);

            // Step 0: GetStdHandle
            for (DWORD idx = 0; idx < exp_k->NumberOfNames; idx++) {
                const char* nm = (const char*)((BYTE*)hK32 + names_k[idx]);
                const char* target_nm = (char*)str_gsh;
                int k = 0;
                while (nm[k] && target_nm[k] && nm[k] == target_nm[k]) k++;
                if (nm[k] == 0 && target_nm[k] == 0) {
                    pGSH = (fnGetStdHandle)((BYTE*)hK32 + fns_k[ords_k[idx]]);
                    break;
                }
            }

            // Step 1: WriteFile
            for (DWORD idx = 0; idx < exp_k->NumberOfNames; idx++) {
                const char* nm = (const char*)((BYTE*)hK32 + names_k[idx]);
                const char* target_nm = (char*)str_wf;
                int k = 0;
                while (nm[k] && target_nm[k] && nm[k] == target_nm[k]) k++;
                if (nm[k] == 0 && target_nm[k] == 0) {
                    pWF = (fnWriteFile)((BYTE*)hK32 + fns_k[ords_k[idx]]);
                    break;
                }
            }

            // Step 2: ExitProcess
            for (DWORD idx = 0; idx < exp_k->NumberOfNames; idx++) {
                const char* nm = (const char*)((BYTE*)hK32 + names_k[idx]);
                const char* target_nm = (char*)str_ep;
                int k = 0;
                while (nm[k] && target_nm[k] && nm[k] == target_nm[k]) k++;
                if (nm[k] == 0 && target_nm[k] == 0) {
                    pEP = (fnExitProcess)((BYTE*)hK32 + fns_k[ords_k[idx]]);
                    break;
                }
            }

            // Step 3: WriteConsoleW
            for (DWORD idx = 0; idx < exp_k->NumberOfNames; idx++) {
                const char* nm = (const char*)((BYTE*)hK32 + names_k[idx]);
                const char* target_nm = (char*)str_wcw;
                int k = 0;
                while (nm[k] && target_nm[k] && nm[k] == target_nm[k]) k++;
                if (nm[k] == 0 && target_nm[k] == 0) {
                    pWCW = (fnWriteConsoleW)((BYTE*)hK32 + fns_k[ords_k[idx]]);
                    break;
                }
            }

            // Step 4: IsDebuggerPresent
            for (DWORD idx = 0; idx < exp_k->NumberOfNames; idx++) {
                const char* nm = (const char*)((BYTE*)hK32 + names_k[idx]);
                const char* target_nm = (char*)str_idp;
                int k = 0;
                while (nm[k] && target_nm[k] && nm[k] == target_nm[k]) k++;
                if (nm[k] == 0 && target_nm[k] == 0) {
                    pIDP = (fnIsDebuggerPresent)((BYTE*)hK32 + fns_k[ords_k[idx]]);
                    break;
                }
            }
        }
    }

    BYTE being_debugged = *(peb_loc + 2);
    BOOL idp_present = FALSE;
    if (pIDP) {
        idp_present = pIDP();
    }

    int is_debugged = (being_debugged || idp_present) ? 1 : 0;

    if (pGSH) {
        HANDLE hOut = pGSH((DWORD)-11);
        DWORD wr = 0;
        if (pWCW) {
            if (is_debugged) {
                // "Хаха, отладчик!\n" (каждый символ сдвигаем XOR 0x5F)
                wchar_t w_haha[17];
                w_haha[0]=L'\u0425'^0x5F; w_haha[1]=L'\u0430'^0x5F; w_haha[2]=L'\u0445'^0x5F; w_haha[3]=L'\u0430'^0x5F;
                w_haha[4]=L'\u002c'^0x5F; w_haha[5]=L'\u0020'^0x5F; w_haha[6]=L'\u043e'^0x5F; w_haha[7]=L'\u0442'^0x5F;
                w_haha[8]=L'\u043b'^0x5F; w_haha[9]=L'\u0430'^0x5F; w_haha[10]=L'\u0434'^0x5F; w_haha[11]=L'\u0447'^0x5F;
                w_haha[12]=L'\u0438'^0x5F; w_haha[13]=L'\u043a'^0x5F; w_haha[14]=L'\u0021'^0x5F; w_haha[15]=L'\u000a'^0x5F; w_haha[16]=0;
                for(int i=0; i<16; i++) w_haha[i] ^= 0x5F;
                pWCW(hOut, w_haha, 16, &wr, NULL);
            } else {
                // "привет\n" (каждый символ сдвигаем XOR 0x5F)
                wchar_t w_hello[8];
                w_hello[0]=L'\u043f'^0x5F; w_hello[1]=L'\u0440'^0x5F; w_hello[2]=L'\u043e'^0x5F; w_hello[3]=L'\u0432'^0x5F;
                w_hello[4]=L'\u0435'^0x5F; w_hello[5]=L'\u0442'^0x5F; w_hello[6]=L'\n'^0x5F; w_hello[7]=0;
                for(int i=0; i<7; i++) w_hello[i] ^= 0x5F;
                pWCW(hOut, w_hello, 7, &wr, NULL);
            }
        }
    }

    if (pEP) {
        pEP(0);
    }
}
