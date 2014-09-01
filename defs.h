#ifdef __NT__
#pragma warning(disable:4242)
#pragma warning(disable:4001)  
#include        <windows.h>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <nalt.hpp>
#include <pro.h>     
#include <netnode.hpp>
#include <name.hpp>

 
#ifdef __LINUX__
#define     MAX_PATH            260
typedef     void                VOID;
typedef     unsigned int        DWORD;
typedef     unsigned int        ULONG;
typedef     int                 LONG;
typedef     unsigned long       ULONG_PTR;
typedef     unsigned short      WORD;
typedef     unsigned short      USHORT;
typedef     unsigned char       BYTE;
typedef     unsigned char       UCHAR;
typedef     unsigned long long  ULONGLONG;
typedef     unsigned int        BOOL;

typedef     void          *     PVOID;
typedef     unsigned char *     PUCHAR;
typedef     unsigned char *     PBYTE;
typedef     unsigned short*     PUSHORT;
typedef     unsigned int  *     PULONG;
typedef     long          *     PLONG;
typedef     unsigned long *     PULONG_PTR;

#define     TRUE                1
#define     FALSE               0
#endif

#include "pe64.h"


#define RSRC_EXTRACT_SAVEDATA           1
#define RSRC_EXTRACT_JMPTODATA          2  
#define RSRC_EXTRACT_SAVEALLDATA        3


typedef struct _RESOURCE_LIST{
        char    *szType;
        char    *szName;
        char    *szLang;
        PVOID   data;
        DWORD   rva;
        DWORD   raw;
        DWORD   size;       
}RESOURCE_LIST, *PRESOURCE_LIST;


extern PIMAGE_DOS_HEADER       pmz; 
#ifndef __EA64__
extern PPEHEADER32             pe32;    
#else
extern PPEHEADER64             pe32;
#endif
extern PSECTION_HEADER         section;
extern FILE                    *pfile;
extern ULONG                   dwFileSize;
extern PRESOURCE_LIST          g_res_list;
extern ULONG_PTR               pmem;
extern ULONG_PTR               resBase;
extern ULONG                   resraw;
extern DWORD                   g_num_of_entries;
extern PRESOURCE_LIST          g_res_list;

ULONG   rva2raw(ULONG rva);
ULONG   idaPopulateResources();

//#undef msg
//#define msg

#define G_RT_CURSOR       "RT_CURSOR"             //#define RT_CURSOR           MAKEINTRESOURCE(1)
#define G_RT_BITMAP       "RT_BITMAP"             //#define RT_BITMAP           MAKEINTRESOURCE(2)
#define G_RT_ICON         "RT_ICON"               //#define RT_ICON             MAKEINTRESOURCE(3)
#define G_RT_MENU         "RT_MENU"               //#define RT_MENU             MAKEINTRESOURCE(4)
#define G_RT_DIALOG       "RT_DIALOG"             //#define RT_DIALOG           MAKEINTRESOURCE(5)
#define G_RT_STRING       "RT_STRING"             //#define RT_STRING           MAKEINTRESOURCE(6)
#define G_RT_FONTDIR      "RT_FONTDIR"            //#define RT_FONTDIR          MAKEINTRESOURCE(7)
#define G_RT_FONT         "RT_FONT"               //#define RT_FONT             MAKEINTRESOURCE(8)
#define G_RT_ACCELERATOR  "RT_ACCELERATOR"        //#define RT_ACCELERATOR      MAKEINTRESOURCE(9)
#define G_RT_RCDATA       "RT_RCDATA"             //#define RT_RCDATA           MAKEINTRESOURCE(10)    
#define G_RT_MESSAGETABLE "RT_MESSAGETABLE"       //#define RT_MESSAGETABLE     MAKEINTRESOURCE(11)
                                                //#define DIFFERENCE     11 
#define G_RT_GROUP_CURSOR "RT_GROUP_CURSOR"       //#define RT_GROUP_CURSOR MAKEINTRESOURCE((ULONG_PTR)RT_CURSOR + DIFFERENCE) (12)    
#define G_RT_GROUP_ICON   "RT_GROUP_ICON"         //#define RT_GROUP_ICON   MAKEINTRESOURCE((ULONG_PTR)RT_ICON + DIFFERENCE)   (14)
#define G_RT_VERSION      "RT_VERSION"            //#define RT_VERSION      MAKEINTRESOURCE(16)                              
#define G_RT_DLGINCLUDE   "RT_DLGINCLUDE"         //#define RT_DLGINCLUDE   MAKEINTRESOURCE(17)                                                               
#define G_RT_PLUGPLAY     "RT_PLUGPLAY"           //#define RT_PLUGPLAY     MAKEINTRESOURCE(19)                               
#define G_RT_VXD          "RT_VXD"                //#define RT_VXD          MAKEINTRESOURCE(20)                               
#define G_RT_ANICURSOR    "RT_ANICURSOR"          //#define RT_ANICURSOR    MAKEINTRESOURCE(21)                               
#define G_RT_ANIICON      "RT_ANIICON"            //#define RT_ANIICON      MAKEINTRESOURCE(22)                                                                
#define G_RT_HTML         "RT_HTML"               //#define RT_HTML         MAKEINTRESOURCE(23)                                                                              
#define G_RT_MANIFEST     "RT_MANIFEST"           //#define RT_MANIFEST     MAKEINTRESOURCE(24)  

       