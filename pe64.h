#ifndef __PE64_DEROKO__
#define __PE64_DEROKO__

#ifdef __LINUX__
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE                 0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x454C      // LE
#define IMAGE_VXD_SIGNATURE                 0x454C      // LE
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
  

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
#endif

typedef struct{
	//pe signature 
    DWORD	pe_signature;
    //file header
    WORD            pe_machine;//      dw      ?
    WORD            pe_numberofsections;// dw  ?
    DWORD           pe_timedatestamp;//    dd  ?
    DWORD           pe_pointertosymboltable;// dd      ?
    DWORD           pe_numberofsymbols;//      dd      ?
    WORD            pe_sizeofoptionalheader;// dw      ?
    WORD            pe_characteristics;//      dw      ?
    //optinaol header...
    WORD            pe_magic;//        dw      ?
    BYTE            pe_majorlinkerversion;//   db      ?
    BYTE            pe_minorlinkerversion;//   db      ?
    DWORD           pe_sizeofcode;//           dd      ?
    DWORD           pe_sizeofinitializeddata;// dd     ?
    DWORD           pe_sizeofuninitializeddata;// dd   ?
    DWORD           pe_addressofentrypoint;//  dd      ?
    DWORD           pe_baseofcode;//           dd      ?
    ULONGLONG       pe_imagebase;//            dq      ?
    DWORD           pe_sectionalignment;//     dd      ?
    DWORD           pe_filealignment;//        dd      ?
    WORD            pe_majoroperatingsystemversion;//  dw ?
    WORD            pe_minoroperatingsystemversion;//  dw ?
    WORD            pe_majorimageversion;//    dw      ?
    WORD            pe_minorimageversion;//    dw      ?
    WORD            pe_majorsubsystemversion;//  dw    ?
    WORD            pe_minorsubsystemversion;//  dw    ?
    DWORD           pe_win32versionvalue;//    dd      ?
    DWORD           pe_sizeofimage;//          dd      ?
    DWORD           pe_sizeofheaders;//        dd      ?
    DWORD           pe_checksum;//             dd      ?
    WORD            pe_subsystem;//            dw      ?
    WORD            pe_dllcharacteristics;//   dw      ?
    ULONGLONG       pe_sizeofstackreserve;//   dq      ?
    ULONGLONG       pe_sizeofstackcommit;//    dq      ?
    ULONGLONG       pe_sizeofheapreserve;//    dq      ?
    ULONGLONG       pe_sizeofheapcommit;//     dq      ?
    DWORD           pe_loadflags;//            dd      ?
    DWORD           pe_numberofrvaandsizes;//  dd      ?
    //data directories...
    DWORD            pe_export;//               dd      ?
    DWORD            pe_exportsize;//           dd      ?
    DWORD            pe_import;//               dd      ?
    DWORD            pe_importsize;//           dd      ?
    DWORD            pe_resource;//             dd      ?
    DWORD            pe_resourcesize;//         dd      ?
    DWORD            pe_exception;//            dd      ?
    DWORD            pe_exceptionsize;//        dd      ?
    DWORD            pe_security;//		    dd      ?
    DWORD            pe_securitysize;//         dd      ?
    DWORD            pe_reloc;//                dd      ?
    DWORD            pe_relocsize;//            dd      ?
    DWORD            pe_debug;//                dd      ?
    DWORD            pe_debugsize;//            dd      ?
    DWORD            pe_architecture;//         dd      ?
    DWORD            pe_architecturesize;//     dd      ?
    DWORD            pe_globalptr;//            dd      ?
    DWORD            pe_globalptrsize;//        dd      ?
    DWORD            pe_tls;//                  dd      ?
    DWORD            pe_tlssize;//              dd      ?
    DWORD            pe_loadconfig;//           dd      ?
    DWORD            pe_loadconfigsize;//       dd      ?
    DWORD            pe_boundimport;//          dd      ?
    DWORD            pe_boundimportsize;//      dd      ?
    DWORD            pe_iat;//                  dd      ?
    DWORD            pe_iatsize;//              dd      ?
    DWORD            pe_delayimport;//          dd      ?
    DWORD            pe_delayimportsize;//      dd      ?
    DWORD            pe_comdescriptor;//        dd      ?
    DWORD            pe_comdescriptorsize;//    dd      ?
}PEHEADER64, *PPEHEADER64;

typedef struct{
	//pe signature 
    DWORD	pe_signature;
    //file header
    WORD            pe_machine;//      dw      ?
    WORD            pe_numberofsections;// dw  ?
    DWORD           pe_timedatestamp;//    dd  ?
    DWORD           pe_pointertosymboltable;// dd      ?
    DWORD           pe_numberofsymbols;//      dd      ?
    WORD            pe_sizeofoptionalheader;// dw      ?
    WORD            pe_characteristics;//      dw      ?
    //optinaol header...
    WORD            pe_magic;//        dw      ?
    BYTE            pe_majorlinkerversion;//   db      ?
    BYTE            pe_minorlinkerversion;//   db      ?
    DWORD           pe_sizeofcode;//           dd      ?
    DWORD           pe_sizeofinitializeddata;// dd     ?
    DWORD           pe_sizeofuninitializeddata;// dd   ?
    DWORD           pe_addressofentrypoint;//  dd      ?
    DWORD           pe_baseofcode;//           dd      ?
    DWORD           pe_baseofdata;
    DWORD           pe_imagebase;//            dq      ?
    DWORD           pe_sectionalignment;//     dd      ?
    DWORD           pe_filealignment;//        dd      ?
    WORD            pe_majoroperatingsystemversion;//  dw ?
    WORD            pe_minoroperatingsystemversion;//  dw ?
    WORD            pe_majorimageversion;//    dw      ?
    WORD            pe_minorimageversion;//    dw      ?
    WORD            pe_majorsubsystemversion;//  dw    ?
    WORD            pe_minorsubsystemversion;//  dw    ?
    DWORD           pe_win32versionvalue;//    dd      ?
    DWORD           pe_sizeofimage;//          dd      ?
    DWORD           pe_sizeofheaders;//        dd      ?
    DWORD           pe_checksum;//             dd      ?
    WORD            pe_subsystem;//            dw      ?
    WORD            pe_dllcharacteristics;//   dw      ?
    DWORD           pe_sizeofstackreserve;//   dq      ?
    DWORD           pe_sizeofstackcommit;//    dq      ?
    DWORD           pe_sizeofheapreserve;//    dq      ?
    DWORD           pe_sizeofheapcommit;//     dq      ?
    DWORD           pe_loadflags;//            dd      ?
    DWORD           pe_numberofrvaandsizes;//  dd      ?
    //data directories...
    DWORD            pe_export;//               dd      ?
    DWORD            pe_exportsize;//           dd      ?
    DWORD            pe_import;//               dd      ?
    DWORD            pe_importsize;//           dd      ?
    DWORD            pe_resource;//             dd      ?
    DWORD            pe_resourcesize;//         dd      ?
    DWORD            pe_exception;//            dd      ?
    DWORD            pe_exceptionsize;//        dd      ?
    DWORD            pe_security;//		    dd      ?
    DWORD            pe_securitysize;//         dd      ?
    DWORD            pe_reloc;//                dd      ?
    DWORD            pe_relocsize;//            dd      ?
    DWORD            pe_debug;//                dd      ?
    DWORD            pe_debugsize;//            dd      ?
    DWORD            pe_architecture;//         dd      ?
    DWORD            pe_architecturesize;//     dd      ?
    DWORD            pe_globalptr;//            dd      ?
    DWORD            pe_globalptrsize;//        dd      ?
    DWORD            pe_tls;//                  dd      ?
    DWORD            pe_tlssize;//              dd      ?
    DWORD            pe_loadconfig;//           dd      ?
    DWORD            pe_loadconfigsize;//       dd      ?
    DWORD            pe_boundimport;//          dd      ?
    DWORD            pe_boundimportsize;//      dd      ?
    DWORD            pe_iat;//                  dd      ?
    DWORD            pe_iatsize;//              dd      ?
    DWORD            pe_delayimport;//          dd      ?
    DWORD            pe_delayimportsize;//      dd      ?
    DWORD            pe_comdescriptor;//        dd      ?
    DWORD            pe_comdescriptorsize;//    dd      ?
}PEHEADER32, *PPEHEADER32;

typedef struct{
        BYTE	sh_name[8];
        DWORD   sh_virtualsize;//         dd      ?
        DWORD	sh_virtualaddress;//       dd      ?
        DWORD	sh_sizeofrawdata;//        dd      ?
        DWORD	sh_pointertorawdata;//     dd      ?
        DWORD	sh_pointertorelocations;// dd      ?
        DWORD	sh_pointertolinenumbers;// dd      ?
        WORD	sh_numberofrelocations;//  dw      ?
        WORD	sh_numberoflinenumbers;//  dw      ?
        DWORD	sh_characteristics;//      dd      ?
}SECTION_HEADER, *PSECTION_HEADER;


typedef struct{
	ULONG Characteristics;
	ULONG TimeDataStamp;
	USHORT  MajorVersion;
	USHORT  MinorVersion;
	USHORT  NumberOfNameEntries;
	USHORT  NumberOfIdEntries;
}RES_DIR, *PRES_DIR;

typedef struct{
	union{
		ULONG NameRva;			
		ULONG Id;
	};
	union{
		ULONG DataEntryRva;
		ULONG SubDirectoryRva;
	};
}RES_DIR_ENTRY, *PRES_DIR_ENTRY;

typedef struct{
	ULONG DataRva;
	ULONG Size;
	ULONG CodePage;
	ULONG Reserved;
}RES_DATA_ENTRY, *PRES_DATA_ENTRY;

typedef struct{
	USHORT Length;
	USHORT UnicodeString;
}RES_STRING_ENTRY, *PRES_STRING_ENTRY;
#endif

