#pragma once

#pragma once
#pragma warning( disable : 4091 )

#include <Windows.h>
#include <stdint.h>
#include <intrin.h>

#if defined(_MSC_VER)
#define _FORCEINLINE_ __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
#define _FORCEINLINE_ inline __attribute__((__always_inline__))
#else
#define _FORCEINLINE_ inline
#endif

namespace win
{
#pragma warning(push)
#pragma warning(disable:4214)

    typedef struct _RTL_BALANCED_NODE
    {
        union
        {
            struct _RTL_BALANCED_NODE* Children[ 2 ];
            struct
            {
                struct _RTL_BALANCED_NODE* Left;
                struct _RTL_BALANCED_NODE* Right;
            };
        };

    #define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

        union
        {
            UCHAR Red : 1;
            UCHAR Balance : 2;
            ULONG_PTR ParentValue;
        };

    } RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

    typedef struct _RTL_RB_TREE
    {
        _RTL_BALANCED_NODE* Root;
        _RTL_BALANCED_NODE* Min;

    } RTL_RB_TREE, * PRTL_RB_TREE;

#pragma warning(pop)

#define RTL_BALANCED_NODE_GET_PARENT_POINTER(Node) \
    ((PRTL_BALANCED_NODE)((Node)->ParentValue & \
                          ~RTL_BALANCED_NODE_RESERVED_PARENT_MASK))

    struct LIST_ENTRY_T {
        const char* Flink;
        const char* Blink;
    };

    struct UNICODE_STRING_T {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t* Buffer;
    };

    struct RTL_USER_PROCESS_PARAMETERS_T {
        ULONG MaximumLength;
        ULONG Length;

        ULONG Flags;
        ULONG DebugFlags;

        handle_t ConsoleHandle;
        ULONG  ConsoleFlags;
        handle_t StandardInput;
        handle_t StandardOutput;
        handle_t StandardError;
    };

    struct PEB_LDR_DATA_T {
        unsigned long Length;
        unsigned long Initialized;
        const char* SsHandle;
        LIST_ENTRY_T  InLoadOrderModuleList;
    };

    typedef struct
    {
        uintptr_t fnCOPYDATA;					// 0  +0x0
        uintptr_t fnCOPYGLOBALDATA;            // 1  +0x8
        uintptr_t fnDWORD;                     // 2  +0x10
        uintptr_t fnNCDESTROY;                 // 3  +0x18
        uintptr_t fnDWORDOPTINLPMSG;           // 4  +0x20
        uintptr_t fnINOUTDRAG;                 // 5  +0x28
        uintptr_t fnGETTEXTLENGTHS_6;          // 6  +0x30
        uintptr_t fnINCNTOUTSTRING;            // 7  +0x38
        uintptr_t fnINCNTOUTSTRINGNULL;        // 8  +0x40
        uintptr_t fnINLPCOMPAREITEMSTRUCT;     // 9  +0x48
        uintptr_t fnINLPCREATESTRUCT;          // 10  +0x50
        uintptr_t fnINLPDELETEITEMSTRUCT;      // 11  +0x58
        uintptr_t fnINLPDRAWITEMSTRUCT;        // 12  +0x60
        uintptr_t fnINPGESTURENOTIFYSTRUCT_13; // 13  +0x68
        uintptr_t fnINPGESTURENOTIFYSTRUCT_14; // 14  +0x70
        uintptr_t fnINLPMDICREATESTRUCT;       // 15  +0x78
        uintptr_t fnINOUTLPMEASUREITEMSTRUCT;  // 16  +0x80
        uintptr_t fnINLPWINDOWPOS;             // 17  +0x88
        uintptr_t fnINOUTLPPOINT5_18;          // 18  +0x90
        uintptr_t fnINOUTLPSCROLLINFO;         // 19  +0x98
        uintptr_t fnINOUTLPRECT;               // 20  +0xA0
        uintptr_t fnINOUTNCCALCSIZE;           // 21  +0xA8
        uintptr_t fnINOUTLPPOINT5_22;          // 22  +0xB0
        uintptr_t fnINPAINTCLIPBRD;            // 23  +0xB8
        uintptr_t fnINSIZECLIPBRD;             // 24  +0xC0
        uintptr_t fnINDESTROYCLIPBRD;          // 25  +0xC8
        uintptr_t fnINSTRING_26;               // 26  +0xD0
        uintptr_t fnINSTRING_27;               // 27  +0xD8
        uintptr_t fnINDEVICECHANGE;            // 28  +0xE0
        uintptr_t fnPOWERBROADCAST;            // 29  +0xE8
        uintptr_t fnINOUTNEXTMENU;             // 30  +0xF0
        uintptr_t fnOUTDWORDDWORD_31;          // 31  +0xF8
        uintptr_t fnOUTDWORDDWORD_32;          // 32  +0x100
        uintptr_t fnOUTDWORDINDWORD;           // 33  +0x108
        uintptr_t fnOUTLPRECT;                 // 34  +0x110
        uintptr_t fnINCNTOUTSTRINGNULL_35;     // 35  +0x118
        uintptr_t fnINPGESTURENOTIFYSTRUCT_36; // 36  +0x120
        uintptr_t fnINCNTOUTSTRINGNULL_37;     // 37  +0x128
        uintptr_t fnSENTDDEMSG;                // 38  +0x130
        uintptr_t fnINOUTSTYLECHANGE;          // 39  +0x138
        uintptr_t fnHkINDWORD;                 // 40  +0x140
        uintptr_t fnHkINLPCBTACTIVATESTRUCT;   // 41  +0x148
        uintptr_t fnHkINLPCBTCREATESTRUCT;     // 42  +0x150
        uintptr_t fnHkINLPDEBUGHOOKSTRUCT;     // 43  +0x158
        uintptr_t fnHkINLPMOUSEHOOKSTRUCTEX;   // 44  +0x160
        uintptr_t fnHkINLPKBDLLHOOKSTRUCT;     // 45  +0x168
        uintptr_t fnHkINLPMSLLHOOKSTRUCT;      // 46  +0x170
        uintptr_t fnHkINLPMSG;                 // 47  +0x178
        uintptr_t fnHkINLPRECT;                // 48  +0x180
        uintptr_t fnHkOPTINLPEVENTMSG;         // 49  +0x188
        uintptr_t ClientCopyDDEIn1;            // 50  +0x190
        uintptr_t ClientCopyDDEIn2;            // 51  +0x198
        uintptr_t ClientCopyDDEOut1;           // 52  +0x1A0
        uintptr_t ClientCopyDDEOut2;           // 53  +0x1A8
        uintptr_t ClientCopyImage;             // 54  +0x1B0
        uintptr_t ClientEventCallback;         // 55  +0x1B8
        uintptr_t ClientFindMnemChar;          // 56  +0x1C0
        uintptr_t ClientFreeDDEHandle;         // 57  +0x1C8
        uintptr_t ClientFreeLibrary;           // 58  +0x1D0
        uintptr_t ClientGetCharsetInfo;        // 59  +0x1D8
        uintptr_t ClientGetDDEFlags;           // 60  +0x1E0
        uintptr_t ClientGetDDEHookData;        // 61  +0x1E8
        uintptr_t ClientGetListboxString;      // 62  +0x1F0
        uintptr_t ClientGetMessageMPH;         // 63  +0x1F8
        uintptr_t ClientLoadImage;             // 64  +0x200
        uintptr_t ClientLoadLibrary;           // 65  +0x208
        uintptr_t ClientLoadMenu;              // 66  +0x210
        uintptr_t ClientLoadLocalT1Fonts;      // 67  +0x218
        uintptr_t ClientPSMTextOut;            // 68  +0x220
        uintptr_t ClientLpkDrawTextEx;         // 69  +0x228
        uintptr_t ClientExtTextOutW;           // 70  +0x230
        uintptr_t ClientGetTextExtentPointW;   // 71  +0x238
        uintptr_t ClientCharToWchar;           // 72  +0x240
        uintptr_t ClientAddFontResourceW;      // 73  +0x248
        uintptr_t ClientThreadSetup;           // 74  +0x250
        uintptr_t ClientDeliverUserApc;        // 75  +0x258
        uintptr_t ClientNoMemoryPopup;         // 76  +0x260
        uintptr_t ClientMonitorEnumProc;       // 77  +0x268
        uintptr_t ClientCallWinEventProc;      // 78  +0x270
        uintptr_t ClientWaitMessageExMPH;      // 79  +0x278
        uintptr_t ClientWOWGetProcModule;      // 80  +0x280
        uintptr_t ClientWOWTask16SchedNotify;  // 81  +0x288
        uintptr_t ClientImmLoadLayout;         // 82  +0x290
        uintptr_t ClientImmProcessKey;         // 83  +0x298
        uintptr_t fnIMECONTROL;                // 84  +0x2A0
        uintptr_t fnINWPARAMDBCSCHAR;          // 85  +0x2A8
        uintptr_t fnGETTEXTLENGTHS_86;         // 86  +0x2B0
        uintptr_t fnINLPKDRAWSWITCHWND;        // 87  +0x2B8
        uintptr_t ClientLoadStringW;           // 88  +0x2C0
        uintptr_t ClientLoadOLE;               // 89  +0x2C8
        uintptr_t ClientRegisterDragDrop;      // 90  +0x2D0
        uintptr_t ClientRevokeDragDrop;        // 91  +0x2D8
        uintptr_t fnINOUTMENUGETOBJECT;        // 92  +0x2E0
        uintptr_t ClientPrinterThunk;          // 93  +0x2E8
        uintptr_t fnOUTLPCOMBOBOXINFO;         // 94  +0x2F0
        uintptr_t fnOUTLPSCROLLBARINFO;        // 95  +0x2F8
        uintptr_t fnINOUTNEXTMENU_96;          // 96  +0x300
        uintptr_t fnINLPUAHDRAWMENUITEM;       // 97  +0x308
        uintptr_t fnINOUTNEXTMENU_98;          // 98  +0x310
        uintptr_t fnINOUTLPUAHMEASUREMENUITEM; // 99  +0x318
        uintptr_t fnINOUTNEXTMENU_100;         // 100  +0x320
        uintptr_t fnOUTLPTITLEBARINFOEX;       // 101  +0x328
        uintptr_t fnTOUCH;                     // 102  +0x330
        uintptr_t fnGESTURE;                   // 103  +0x338
        uintptr_t fnINPGESTURENOTIFYSTRUCT_104;// 104  +0x340
        uintptr_t null_105;                    // 105  +0x348
        uintptr_t ButtonWndProcWorker;         // 106  +0x350
        uintptr_t ComboBoxWndProcWorker;       // 107  +0x358
        uintptr_t ListBoxWndProcWorker_108;    // 108  +0x360
        uintptr_t DefDlgProcWorker;            // 109  +0x368
        uintptr_t EditWndProcWorker;           // 110  +0x370
        uintptr_t ListBoxWndProcWorker_111;    // 111  +0x378
        uintptr_t MDIClientWndProcWorker;      // 112  +0x380
        uintptr_t StaticWndProcWorker;         // 113  +0x388
        uintptr_t ImeWndProcWorker;            // 114  +0x390
        uintptr_t DefWindowProcWorker;         // 115  +0x398
        uintptr_t CtfHookProcWorker;           // 116  +0x3A0
        uintptr_t null_117;                    // 117  +0x3A8
        uintptr_t null_118;                    // 118  +0x3B0
        uintptr_t null_119;                    // 119  +0x3B8
        uintptr_t ScrollBarWndProcW;           // 120  +0x3C0
        uintptr_t DefWindowProcW_121;          // 121  +0x3C8
        uintptr_t MenuWndProcW;                // 122  +0x3D0
        uintptr_t DesktopWndProcW;             // 123  +0x3D8
        uintptr_t DefWindowProcW_124;          // 124  +0x3E0
        uintptr_t DefWindowProcW_125;          // 125  +0x3E8
        uintptr_t DefWindowProcW_126;          // 126  +0x3F0
        uintptr_t ButtonWndProcW_127;          // 127  +0x3F8
        uintptr_t ComboBoxWndProcW;            // 128  +0x400
        uintptr_t ListBoxWndProcW_129;         // 129  +0x408
        uintptr_t DefDlgProcW;                 // 130  +0x410
        uintptr_t EditWndProcW;                // 131  +0x418
        uintptr_t ListBoxWndProcW_132;         // 132  +0x420
        uintptr_t MDIClientWndProcW;           // 133  +0x428
        uintptr_t StaticWndProcW;              // 134  +0x430
        uintptr_t ImeWndProcW;                 // 135  +0x438
        uintptr_t DefWindowProcW;              // 136  +0x440
        uintptr_t fnHkINLPCWPSTRUCTW;          // 137  +0x448
        uintptr_t fnHkINLPCWPRETSTRUCTW;       // 138  +0x450
        uintptr_t DispatchHookW;               // 139  +0x458
        uintptr_t DispatchDefWindowProcW;      // 140  +0x460
        uintptr_t DispatchClientMessage;       // 141  +0x468
        uintptr_t MDIActivateDlgProcW_142;     // 142  +0x470
        uintptr_t null_167;                    // 143  +0x478
        uintptr_t ScrollBarWndProcA;           // 144  +0x480
        uintptr_t DefWindowProcA_145;          // 145  +0x488
        uintptr_t MenuWndProcA;                // 146  +0x490
        uintptr_t DesktopWndProcA;             // 147  +0x498
        uintptr_t DefWindowProcA_148;          // 148  +0x4A0
        uintptr_t DefWindowProcA_149;          // 149  +0x4A8
        uintptr_t DefWindowProcA_150;          // 150  +0x4B0
        uintptr_t ButtonWndProcA_151;          // 151  +0x4B8
        uintptr_t ComboBoxWndProcA;            // 152  +0x4C0
        uintptr_t ListBoxWndProcA_153;         // 153  +0x4C8
        uintptr_t DefDlgProcA;                 // 154  +0x4D0
        uintptr_t EditWndProcA;                // 155  +0x4D8
        uintptr_t ListBoxWndProcA_156;         // 156  +0x4E0
        uintptr_t MDIClientWndProcA;           // 157  +0x4E8
        uintptr_t StaticWndProcA;              // 158  +0x4F0
        uintptr_t ImeWndProcA;                 // 159  +0x4F8
        uintptr_t DefWindowProcA;              // 160  +0x500
        uintptr_t fnHkINLPCWPSTRUCTA;          // 161  +0x508
        uintptr_t fnHkINLPCWPRETSTRUCTA;       // 162  +0x510
        uintptr_t DispatchHookA;               // 163  +0x518
        uintptr_t DispatchDefWindowProcA;      // 164  +0x520
        uintptr_t DispatchClientMessage_165;   // 165  +0x528
        uintptr_t MDIActivateDlgProcW_166;     // 166  +0x530

    } KERNEL_CALLBACK_TABLE_64;

    struct PEB_T {
        union
        {
            struct
            {
                unsigned char InheritedAddressSpace;
                unsigned char ReadImageFileExecOptions;
                unsigned char BeingDebugged;

                union
                {
                    unsigned char BitField;

                    struct
                    {
                        unsigned char ImageUsesLargePages : 1;
                        unsigned char IsProtectedProcess : 1;
                        unsigned char IsImageDynamicallyRelocated : 1;
                        unsigned char SkipPatchingUser32Forwarders : 1;
                        unsigned char IsPackagedProcess : 1;
                        unsigned char IsAppContainer : 1;
                        unsigned char IsProtectedProcessLight : 1;
                        unsigned char SpareBits : 1;
                    };
                };
            };

            void* Data00;
        };

        uintptr_t Mutant;
        uintptr_t ImageBaseAddress;

        PEB_LDR_DATA_T* Ldr;
        RTL_USER_PROCESS_PARAMETERS_T* ProcessParameters;
        void* subsystem_data;
        void* ProcessHeap;
        ULONGLONG FastPebLock;                                                  //0x38
        ULONGLONG AtlThunkSListPtr;                                             //0x40
        ULONGLONG IFEOKey;                                                      //0x48
        union
        {
            ULONG CrossProcessFlags;                                            //0x50
            struct
            {
                ULONG ProcessInJob : 1;                                           //0x50
                ULONG ProcessInitializing : 1;                                    //0x50
                ULONG ProcessUsingVEH : 1;                                        //0x50
                ULONG ProcessUsingVCH : 1;                                        //0x50
                ULONG ProcessUsingFTH : 1;                                        //0x50
                ULONG ProcessPreviouslyThrottled : 1;                             //0x50
                ULONG ProcessCurrentlyThrottled : 1;                              //0x50
                ULONG ProcessImagesHotPatched : 1;                                //0x50
                ULONG ReservedBits0 : 24;                                         //0x50
            };
        };
        UCHAR Padding1[ 4 ];                                                      //0x54
        union
        {
            KERNEL_CALLBACK_TABLE_64* KernelCallbackTable;                      //0x58
            ULONGLONG UserSharedInfoPtr;                                        //0x58
        };
    };

    struct LDR_DATA_TABLE_ENTRY_T {
        LIST_ENTRY_T InLoadOrderLinks;
        LIST_ENTRY_T InMemoryOrderLinks;
        LIST_ENTRY_T InInitializationOrderLinks;
        const char* DllBase;
        const char* EntryPoint;
        union {
            unsigned long SizeOfImage;
            const char* _dummy;
        };
        UNICODE_STRING_T FullDllName;
        UNICODE_STRING_T BaseDllName;

        _FORCEINLINE_ const LDR_DATA_TABLE_ENTRY_T* load_order_next() const noexcept
        {
            return reinterpret_cast< const LDR_DATA_TABLE_ENTRY_T* >( InLoadOrderLinks.Flink );
        }
    };

    struct IMAGE_DOS_HEADER { // DOS .EXE header
        unsigned short e_magic; // Magic number
        unsigned short e_cblp; // Bytes on last page of file
        unsigned short e_cp; // Pages in file
        unsigned short e_crlc; // Relocations
        unsigned short e_cparhdr; // Size of header in paragraphs
        unsigned short e_minalloc; // Minimum extra paragraphs needed
        unsigned short e_maxalloc; // Maximum extra paragraphs needed
        unsigned short e_ss; // Initial (relative) SS value
        unsigned short e_sp; // Initial SP value
        unsigned short e_csum; // Checksum
        unsigned short e_ip; // Initial IP value
        unsigned short e_cs; // Initial (relative) CS value
        unsigned short e_lfarlc; // File address of relocation table
        unsigned short e_ovno; // Overlay number
        unsigned short e_res[ 4 ]; // Reserved words
        unsigned short e_oemid; // OEM identifier (for e_oeminfo)
        unsigned short e_oeminfo; // OEM information; e_oemid specific
        unsigned short e_res2[ 10 ]; // Reserved words
        long           e_lfanew; // File address of new exe header
    };

    struct IMAGE_FILE_HEADER {
        unsigned short Machine;
        unsigned short NumberOfSections;
        unsigned long  TimeDateStamp;
        unsigned long  PointerToSymbolTable;
        unsigned long  NumberOfSymbols;
        unsigned short SizeOfOptionalHeader;
        unsigned short Characteristics;
    };

    struct IMAGE_EXPORT_DIRECTORY {
        unsigned long  Characteristics;
        unsigned long  TimeDateStamp;
        unsigned short MajorVersion;
        unsigned short MinorVersion;
        unsigned long  Name;
        unsigned long  Base;
        unsigned long  NumberOfFunctions;
        unsigned long  NumberOfNames;
        unsigned long  AddressOfFunctions; // RVA from base of image
        unsigned long  AddressOfNames; // RVA from base of image
        unsigned long  AddressOfNameOrdinals; // RVA from base of image
    };

    struct IMAGE_DATA_DIRECTORY {
        unsigned long VirtualAddress;
        unsigned long Size;
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        unsigned short       Magic;
        unsigned char        MajorLinkerVersion;
        unsigned char        MinorLinkerVersion;
        unsigned long        SizeOfCode;
        unsigned long        SizeOfInitializedData;
        unsigned long        SizeOfUninitializedData;
        unsigned long        AddressOfEntryPoint;
        unsigned long        BaseOfCode;
        unsigned long long   ImageBase;
        unsigned long        SectionAlignment;
        unsigned long        FileAlignment;
        unsigned short       MajorOperatingSystemVersion;
        unsigned short       MinorOperatingSystemVersion;
        unsigned short       MajorImageVersion;
        unsigned short       MinorImageVersion;
        unsigned short       MajorSubsystemVersion;
        unsigned short       MinorSubsystemVersion;
        unsigned long        Win32VersionValue;
        unsigned long        SizeOfImage;
        unsigned long        SizeOfHeaders;
        unsigned long        CheckSum;
        unsigned short       Subsystem;
        unsigned short       DllCharacteristics;
        unsigned long long   SizeOfStackReserve;
        unsigned long long   SizeOfStackCommit;
        unsigned long long   SizeOfHeapReserve;
        unsigned long long   SizeOfHeapCommit;
        unsigned long        LoaderFlags;
        unsigned long        NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        unsigned short       Magic;
        unsigned char        MajorLinkerVersion;
        unsigned char        MinorLinkerVersion;
        unsigned long        SizeOfCode;
        unsigned long        SizeOfInitializedData;
        unsigned long        SizeOfUninitializedData;
        unsigned long        AddressOfEntryPoint;
        unsigned long        BaseOfCode;
        unsigned long        BaseOfData;
        unsigned long        ImageBase;
        unsigned long        SectionAlignment;
        unsigned long        FileAlignment;
        unsigned short       MajorOperatingSystemVersion;
        unsigned short       MinorOperatingSystemVersion;
        unsigned short       MajorImageVersion;
        unsigned short       MinorImageVersion;
        unsigned short       MajorSubsystemVersion;
        unsigned short       MinorSubsystemVersion;
        unsigned long        Win32VersionValue;
        unsigned long        SizeOfImage;
        unsigned long        SizeOfHeaders;
        unsigned long        CheckSum;
        unsigned short       Subsystem;
        unsigned short       DllCharacteristics;
        unsigned long        SizeOfStackReserve;
        unsigned long        SizeOfStackCommit;
        unsigned long        SizeOfHeapReserve;
        unsigned long        SizeOfHeapCommit;
        unsigned long        LoaderFlags;
        unsigned long        NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
    };

    struct IMAGE_NT_HEADERS {
        unsigned long     Signature;
        IMAGE_FILE_HEADER FileHeader;
#ifdef _WIN64
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
    };

    struct CLIENT_ID_T
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    };

    struct ACTIVATION_CONTEXT_STACK_T
    {
        PVOID ActiveFrame;
        LIST_ENTRY FrameListCache;
        ULONG Flags;
        ULONG NextCookieSequenceNumber;
        ULONG StackId;
    };

    struct GDI_TEB_BATCH_T
    {
        ULONG Offset;
        HANDLE HDC;
        ULONG Buffer[ 310 ];
    };

    struct TEB_ACTIVE_FRAME_CONTEXT_T
    {
        ULONG Flags;
        LPSTR FrameName;
    };

    struct TEB_ACTIVE_FRAME_T
    {
        ULONG Flags;
        TEB_ACTIVE_FRAME_T* Previous;
        TEB_ACTIVE_FRAME_CONTEXT_T* Context;
    };
#define NB_HOOKS (WH_MAXHOOK - WH_MINHOOK + 1)

    struct DESKTOPINFO_T
    {
        PVOID pvDesktopBase;
        PVOID pvDesktopLimit;
        struct _WND* spwnd;
        DWORD fsHooks;
        LIST_ENTRY aphkStart[ NB_HOOKS ];

        HWND hTaskManWindow;
        HWND hProgmanWindow;
        HWND hShellWindow;
        struct _WND* spwndShell;
        struct _WND* spwndBkGnd;

        struct _PROCESSINFO* ppiShellProcess;

        union
        {
            UINT Dummy;
            struct
            {
                UINT LastInputWasKbd : 1;
            };
        };

        WCHAR szDesktopName[ 1 ];
    };

    typedef struct HEAD_T
    {
        HANDLE h;
        DWORD cLockObj;
    };

    typedef struct THROBJHEAD_T
    {
        HEAD_T head;
        struct _THREADINFO* pti;
    };

    typedef struct THRDESKHEAD_T
    {
        THROBJHEAD_T throbject;
        struct _DESKTOP* rpdesk;
        PVOID pSelf;
    };

    typedef struct HOOK_T
    {
        THRDESKHEAD_T head;
        struct HOOK_T* phkNext; /* This is for user space. */
        int HookId; /* Hook table index */
        ULONG_PTR offPfn;
        ULONG flags; /* Some internal flags */
        INT_PTR ihmod;
        struct _THREADINFO* ptiHooked;
        struct _DESKTOP* rpdesk;
        /* ReactOS */
        LIST_ENTRY Chain; /* Hook chain entry */
        HOOKPROC Proc; /* Hook function */
        BOOLEAN Ansi; /* Is it an Ansi hook? */
        UNICODE_STRING_T ModuleName; /* Module name for global hooks */
    };

    typedef struct WND_T
    {
        THRDESKHEAD_T head;

        /* These fields should be moved in the WW at some point. */
        /* Plese do not change them to keep the same layout with WW. */
        DWORD state;
        DWORD state2;
        /* Extended style. */
        DWORD ExStyle;
        /* Style. */
        DWORD style;
        /* Handle of the module that created the window. */
        HINSTANCE hModule;
        DWORD fnid;

        struct _WND* spwndNext;
        struct _WND* spwndPrev;
        struct _WND* spwndParent;
        struct _WND* spwndChild;
        struct _WND* spwndOwner;
        RECT rcWindow;
        RECT rcClient;
        WNDPROC lpfnWndProc;
        // more but struct is big
    };

    struct CALLBACKWND_T
    {
        HWND hWnd;
        struct WND_T* pWnd;
        PVOID pActCtx;
    };

    struct CLIENTTHREADINFO_T
    {
        DWORD CTI_flags;
        WORD fsChangeBits;
        WORD fsWakeBits;
        WORD fsWakeBitsJournal;
        WORD fsWakeMask;
        ULONG timeLastRead; // Last time the message queue was read.
        DWORD dwcPumpHook;
    };

    struct CLIENTINFO_T
    {
        uint64_t CI_Flags; //0x0000
        uint64_t cSpins; //0x0008
        uint32_t dwExpWinVer; //0x0010
        uint32_t dwCompatFlags; //0x0014
        uint32_t dwCompatFlags2; //0x0018
        uint32_t dwTIFlags; //0x001C
        void* pDesktopInfo; //0x0020
        uint64_t ulClientDelta; //0x0028
        void* phkCurrent; //0x0030
        uint32_t fsHooks; //0x0038
        uint32_t buff; //0x003C
        uint64_t hWnd; //0x0040
        uint64_t pWnd; //0x0048
        uint64_t pActCtx; //0x0050
        uint32_t dwHookCurrent; //0x0058
        int32_t cInDDEMLCallback; //0x005C
        void* pClientThreadInfo; //0x0060
        uint64_t dwHookData; //0x0068
        uint32_t dwKeyCache; //0x0070
        uint64_t afKeyState; //0x0074
        uint32_t dwAsyncKeyCache; //0x007C
        uint64_t afAsyncKeyState; //0x0080
        uint64_t afAsyncKeyStateRecentDown; //0x0088
        uint64_t hKL; //0x0090
        uint16_t CodePage; //0x0098
        uint16_t achDbcsCF; //0x009A
        uint32_t msg_hwnd; //0x009C
        uint32_t msg_message; //0x00A0
        uint64_t wParam; //0x00A4
        uint64_t lParam; //0x00AC
        uint32_t time; //0x00B4
        int32_t msg_point_x; //0x00B8
        int32_t msg_point_y; //0x00BC
        void* lpdwRegisteredClasses; //0x00C0
        char pad_00C8[ 280 ]; //0x00C8
    }; //Size: 0x0238

    constexpr size_t lol = sizeof( CLIENTINFO_T );


    //0x1850 bytes (sizeof)
    struct TEB_T
    {
        struct _NT_TIB NtTib;                                                   //0x0
        VOID* EnvironmentPointer;                                               //0x38
        struct CLIENT_ID_T ClientId;                                             //0x40
        VOID* ActiveRpcHandle;                                                  //0x50
        VOID* ThreadLocalStoragePointer;                                        //0x58
        struct _PEB* ProcessEnvironmentBlock;                                   //0x60
        ULONG LastErrorValue;                                                   //0x68
        ULONG CountOfOwnedCriticalSections;                                     //0x6c
        VOID* CsrClientThread;                                                  //0x70
        VOID* Win32ThreadInfo;                                                  //0x78
        ULONG User32Reserved[ 26 ];                                               //0x80
        ULONG UserReserved[ 5 ];                                                  //0xe8
        VOID* WOW32Reserved;                                                    //0x100
        ULONG CurrentLocale;                                                    //0x108
        ULONG FpSoftwareStatusRegister;                                         //0x10c
        VOID* ReservedForDebuggerInstrumentation[ 16 ];                           //0x110
        VOID* SystemReserved1[ 30 ];                                              //0x190
        CHAR PlaceholderCompatibilityMode;                                      //0x280
        UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
        CHAR PlaceholderReserved[ 10 ];                                           //0x282
        ULONG ProxiedProcessId;                                                 //0x28c
        struct ACTIVATION_CONTEXT_STACK_T _ActivationStack;                      //0x290
        UCHAR WorkingOnBehalfTicket[ 8 ];                                         //0x2b8
        LONG ExceptionCode;                                                     //0x2c0
        UCHAR Padding0[ 4 ];                                                      //0x2c4
        struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x2c8
        ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
        ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
        ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
        ULONG TxFsContext;                                                      //0x2e8
        UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
        UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
        UCHAR Padding1[ 2 ];                                                      //0x2ee
        struct GDI_TEB_BATCH_T GdiTebBatch;                                      //0x2f0
        struct CLIENT_ID_T RealClientId;                                         //0x7d8
        VOID* GdiCachedProcessHandle;                                           //0x7e8
        ULONG GdiClientPID;                                                     //0x7f0
        ULONG GdiClientTID;                                                     //0x7f4
        VOID* GdiThreadLocalInfo;                                               //0x7f8
        CLIENTINFO_T Win32ClientInfo;                                          //0x800
        VOID* glDispatchTable[ 233 ];                                             //0x9f0
        ULONGLONG glReserved1[ 29 ];                                              //0x1138
        VOID* glReserved2;                                                      //0x1220
        VOID* glSectionInfo;                                                    //0x1228
        VOID* glSection;                                                        //0x1230
        VOID* glTable;                                                          //0x1238
        VOID* glCurrentRC;                                                      //0x1240
        VOID* glContext;                                                        //0x1248
        ULONG LastStatusValue;                                                  //0x1250
        UCHAR Padding2[ 4 ];                                                      //0x1254
        struct UNICODE_STRING_T StaticUnicodeString;                             //0x1258
        WCHAR StaticUnicodeBuffer[ 261 ];                                         //0x1268
        UCHAR Padding3[ 6 ];                                                      //0x1472
        VOID* DeallocationStack;                                                //0x1478
        VOID* TlsSlots[ 64 ];                                                     //0x1480
        struct _LIST_ENTRY TlsLinks;                                            //0x1680
        VOID* Vdm;                                                              //0x1690
        VOID* ReservedForNtRpc;                                                 //0x1698
        VOID* DbgSsReserved[ 2 ];                                                 //0x16a0
        ULONG HardErrorMode;                                                    //0x16b0
        UCHAR Padding4[ 4 ];                                                      //0x16b4
        VOID* Instrumentation[ 11 ];                                              //0x16b8
        struct _GUID ActivityId;                                                //0x1710
        VOID* SubProcessTag;                                                    //0x1720
        VOID* PerflibData;                                                      //0x1728
        VOID* EtwTraceData;                                                     //0x1730
        VOID* WinSockData;                                                      //0x1738
        ULONG GdiBatchCount;                                                    //0x1740
        union
        {
            struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
            ULONG IdealProcessorValue;                                          //0x1744
            struct
            {
                UCHAR ReservedPad0;                                             //0x1744
                UCHAR ReservedPad1;                                             //0x1745
                UCHAR ReservedPad2;                                             //0x1746
                UCHAR IdealProcessor;                                           //0x1747
            };
        };
        ULONG GuaranteedStackBytes;                                             //0x1748
        UCHAR Padding5[ 4 ];                                                      //0x174c
        VOID* ReservedForPerf;                                                  //0x1750
        VOID* ReservedForOle;                                                   //0x1758
        ULONG WaitingOnLoaderLock;                                              //0x1760
        UCHAR Padding6[ 4 ];                                                      //0x1764
        VOID* SavedPriorityState;                                               //0x1768
        ULONGLONG ReservedForCodeCoverage;                                      //0x1770
        VOID* ThreadPoolData;                                                   //0x1778
        VOID** TlsExpansionSlots;                                               //0x1780
        struct _CHPEV2_CPUAREA_INFO* ChpeV2CpuAreaInfo;                         //0x1788
        VOID* Unused;                                                           //0x1790
        ULONG MuiGeneration;                                                    //0x1798
        ULONG IsImpersonating;                                                  //0x179c
        VOID* NlsCache;                                                         //0x17a0
        VOID* pShimData;                                                        //0x17a8
        ULONG HeapData;                                                         //0x17b0
        UCHAR Padding7[ 4 ];                                                    //0x17b4
        VOID* CurrentTransactionHandle;                                         //0x17b8
        struct _TEB_ACTIVE_FRAME* ActiveFrame;                                  //0x17c0
        VOID* FlsData;                                                          //0x17c8
        VOID* PreferredLanguages;                                               //0x17d0
        VOID* UserPrefLanguages;                                                //0x17d8
        VOID* MergedPrefLanguages;                                              //0x17e0
        ULONG MuiImpersonation;                                                 //0x17e8
        union
        {
            volatile USHORT CrossTebFlags;                                      //0x17ec
            USHORT SpareCrossTebBits : 16;                                      //0x17ec
        };
        union
        {
            USHORT SameTebFlags;                                                //0x17ee
            struct
            {
                USHORT SafeThunkCall : 1;                                       //0x17ee
                USHORT InDebugPrint : 1;                                        //0x17ee
                USHORT HasFiberData : 1;                                        //0x17ee
                USHORT SkipThreadAttach : 1;                                    //0x17ee
                USHORT WerInShipAssertCode : 1;                                 //0x17ee
                USHORT RanProcessInit : 1;                                      //0x17ee
                USHORT ClonedThread : 1;                                        //0x17ee
                USHORT SuppressDebugMsg : 1;                                    //0x17ee
                USHORT DisableUserStackWalk : 1;                                //0x17ee
                USHORT RtlExceptionAttached : 1;                                //0x17ee
                USHORT InitialThread : 1;                                       //0x17ee
                USHORT SessionAware : 1;                                        //0x17ee
                USHORT LoadOwner : 1;                                           //0x17ee
                USHORT LoaderWorker : 1;                                        //0x17ee
                USHORT SkipLoaderInit : 1;                                      //0x17ee
                USHORT SkipFileAPIBrokering : 1;                                //0x17ee
            };
        };
        VOID* TxnScopeEnterCallback;                                            //0x17f0
        VOID* TxnScopeExitCallback;                                             //0x17f8
        VOID* TxnScopeContext;                                                  //0x1800
        ULONG LockCount;                                                        //0x1808
        LONG WowTebOffset;                                                      //0x180c
        VOID* ResourceRetValue;                                                 //0x1810
        VOID* ReservedForWdf;                                                   //0x1818
        ULONGLONG ReservedForCrt;                                               //0x1820
        struct _GUID EffectiveContainerId;                                      //0x1828
        ULONGLONG LastSleepCounter;                                             //0x1838
        ULONG SpinCallCount;                                                    //0x1840
        UCHAR Padding8[ 4 ];                                                    //0x1844
        ULONGLONG ExtendedFeatureDisableMask;                                   //0x1848
    };


} // namespace win