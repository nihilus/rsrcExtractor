/******************************************************************************
 * This code deals with resource extracting. Note that these funcstion are c/p
 * as resource walking logic is always the same. All of this could have been 
 * done as one recursive function, but, who cares...
 *
 *                                                   (c) 2011 deroko of ARTeam
 ******************************************************************************/
#include        "defs.h"

ULONG   rva2raw(ULONG rva){
        ULONG   index;
        
        for (index = 0; index < pe32->pe_numberofsections; index++)
                if (section[index].sh_virtualaddress <= rva && rva < (section[index].sh_virtualaddress + ((section[index].sh_virtualsize == 0) ? section[index].sh_sizeofrawdata : section[index].sh_virtualsize)))
                        if (section[index].sh_pointertorawdata <= dwFileSize)
                                return rva - section[index].sh_virtualaddress + section[index].sh_pointertorawdata;
        return 0xFFFFFFFF;        
}

static void    u2a(char *ansi, unsigned short *us, size_t len){
        size_t count;
        if (ansi == NULL || len == 0 || us == NULL) return;
                
        while (len != 0 && *us != 0){
                *ansi = *us;
                ansi++;
                us++;
                len--;
        }
}

static PVOID   g_szType;
static BOOL    b_nametype;
static PVOID   g_szName;
static BOOL    b_namename;
static PVOID   g_szLang;
static BOOL    b_namelang;

static const char  *typeidtostring[]  = {
        NULL,                          //0
        G_RT_CURSOR,                   //1                      
        G_RT_BITMAP,                   //2
        G_RT_ICON,                     //3
        G_RT_MENU,                     //4
        G_RT_DIALOG,                   //5
        G_RT_STRING,                   //6
        G_RT_FONTDIR,                  //7
        G_RT_FONT,                     //8
        G_RT_ACCELERATOR,              //9
        G_RT_RCDATA,                   //10
        G_RT_MESSAGETABLE,             //11
        G_RT_GROUP_CURSOR,             //12
        NULL,                          //13
        G_RT_GROUP_ICON,               //14
        NULL,                          //15
        G_RT_VERSION,                  //16
        G_RT_DLGINCLUDE,               //17 
        NULL,                          //18
        G_RT_PLUGPLAY,                 //19
        G_RT_VXD,                      //20
        G_RT_ANICURSOR,                //21
        G_RT_ANIICON,                  //22
        G_RT_HTML,                     //23
        G_RT_MANIFEST                  //24 
};

static PVOID   ExtractNameOrId(PRES_DIR_ENTRY pResDirEntry, BOOL *b_ok, BOOL *b_name){                
        PVOID   ret = NULL;
        PRES_STRING_ENTRY pResStringEntry;
        
        // This is not docummented in PE-Coff specification, but all string RVAs (relative to resource base),
        // have high bit set. So we use it to search for string. Better solution would be to check 
        // NumberOfNameEntries and NumberOfIdEntries to know which one is which      
        if (pResDirEntry->NameRva & 0x80000000){
                //go for that name...
                pResStringEntry = (PRES_STRING_ENTRY)((pResDirEntry->NameRva & 0x7FFFFFFF) + resBase);
                //extract string... (check first if string is in exe files...)
                if (((ULONG_PTR)pResStringEntry + sizeof(RES_STRING_ENTRY) - resBase) < dwFileSize){
                        //we now try to extract data... otherwise we mark type as <Invalid Type> 
                        //check if <Name Length is out of the file image>       
                        if (((ULONG_PTR)&pResStringEntry->UnicodeString + pResStringEntry->Length * sizeof(USHORT) - resBase) > dwFileSize){
                                *b_ok = FALSE;
                        }else if (pResStringEntry->Length == 0){        //?! Well we just skip entry... (damaged resources?!?!)
                                *b_ok = FALSE;        
                        }else{
                                ret = qalloc(pResStringEntry->Length + 1);
                                if (!ret){
                                        msg("%s -- Failed to allocate memory for resource name, requested mem = %.08X\n", __FUNCTION__, pResStringEntry->Length);
                                        *b_ok = FALSE;
                                }else{
                                        memset(ret, 0, pResStringEntry->Length + 1);
                                        u2a((char *)ret, &pResStringEntry->UnicodeString, pResStringEntry->Length);        
                                        *b_ok   = TRUE;
                                        *b_name = TRUE;
                                }
                        }
                }
        }else{
                ret = (PVOID)pResDirEntry->Id;
                *b_ok   = TRUE;
                *b_name = FALSE;
        }               
        return ret;
}

static char    *ConvertIdToName(DWORD   id){
        if (id < 25)
                return (char *)typeidtostring[id];
        return NULL;        
}

static ULONG   FillResourceList(PRESOURCE_LIST pres, PVOID lpData, ULONG rva, DWORD dwDataSize){
        char    szBuffer[MAXSTR];
        char    *name;
        
        pres->raw  = (ULONG_PTR)lpData - pmem;
        pres->rva  = rva;
        pres->size = dwDataSize;
        pres->data = qalloc(pres->size);
        memcpy(pres->data, lpData, pres->size);                
        
        //fill info about name etc...
        if (!b_nametype){
                name = ConvertIdToName((DWORD)g_szType);
                if (name == NULL){
                        memset(szBuffer, 0, sizeof(szBuffer));
                        qsnprintf(szBuffer, MAXSTR, "%d", g_szType);
                        name = szBuffer;
                }
        }else{
                name = (char *)g_szType;
        }

        pres->szType = (char *)qalloc(strlen(name) + 1);
        memset(pres->szType, 0, strlen(name) + 1);
        memcpy(pres->szType, name, strlen(name));
        
        if (!b_namename){
                memset(szBuffer, 0, sizeof(szBuffer));
                qsnprintf(szBuffer, MAXSTR, "%d", g_szName);
                name = szBuffer;
        }else{
                name = (char *)g_szName;
        }
                
        pres->szName = (char *)qalloc(strlen(name) + 1);
        memset(pres->szName, 0, strlen(name) + 1);
        memcpy(pres->szName, name, strlen(name));
        
        if (!b_namelang){
                memset(szBuffer, 0, sizeof(szBuffer));
                qsnprintf(szBuffer, MAXSTR, "%d", g_szLang);
                name = szBuffer;
        }else{
                name = (char *)g_szLang;
        }
               
        pres->szLang = (char *)qalloc(strlen(name) + 1);
        memset(pres->szLang, 0, strlen(name) + 1);
        memcpy(pres->szLang, name, strlen(name));
        return 0;
}

// All of these 3 functions are more or less the same, as logic of processing
// resources is same for all data directories, except in last one we search
// for DATA entry...
static ULONG   idaPopulateResourceLang(ULONG_PTR resBase,PRES_DIR pResDir){
        PRES_DIR        pSubResDir;
        PRES_DIR_ENTRY  pResDirEntry;
        PRES_DATA_ENTRY pResDataEntry;
        DWORD           dwNumberOfEntries;
        BOOL            b_ok, b_name;
        DWORD           dwDataRaw;
        
        dwNumberOfEntries = pResDir->NumberOfNameEntries + pResDir->NumberOfIdEntries;
        if ((ULONG_PTR)pResDir - pmem + sizeof(RES_DIR) + sizeof(RES_DIR_ENTRY) * dwNumberOfEntries > dwFileSize) return 0;
        
        pResDirEntry = (PRES_DIR_ENTRY)((ULONG_PTR)pResDir + sizeof(RES_DIR));   

        while (dwNumberOfEntries){
                g_szLang = ExtractNameOrId(pResDirEntry, &b_ok, &b_name);
                if (!b_ok) goto __NextEntry;
                b_namelang = b_name;
                //check if next entry is 
                if (pResDirEntry->SubDirectoryRva & 0x80000000){
                        //report error here and continue, as next in Type is actually DataEntry (this is wrong!!!! in normal file)        
                        msg("[ERROR] %s -- SubDirectoryRva set as SubDir, offset in file : %.08X\n", __FUNCTION__, (ULONG_PTR)pResDirEntry - pmem);                                                                                                
                        if (b_name)
                                msg("[ERROR] %s -- Lang name (name) : %s\n", __FUNCTION__, g_szLang);
                        else
                                msg("[ERROR] %s -- Lang name (id)   : %d\n", __FUNCTION__, g_szLang);
                        goto __NextEntry;                                                                                                                 
                }
                
                pResDataEntry = (PRES_DATA_ENTRY)(resBase + pResDirEntry->DataEntryRva);
                
                //check if data entry is in file actually
                if ((ULONG_PTR)pResDataEntry - pmem + sizeof(RES_DATA_ENTRY) > dwFileSize) goto __NextEntry;
                
                //check if data actually is in the file
                dwDataRaw = rva2raw(pResDataEntry->DataRva);
                if (dwDataRaw == 0xFFFFFFFF) goto __NextEntry;
                if (dwDataRaw + pResDataEntry->Size > dwFileSize) goto __NextEntry;
                //msg("Data at : %.08X size : %.08X\n", dwDataRaw, pResDataEntry->Size);
                //now we can get data back and increment original var...
                if (!g_res_list){
                        g_res_list = (PRESOURCE_LIST)qalloc(sizeof(RESOURCE_LIST));       
                        FillResourceList(g_res_list, (void *)(dwDataRaw + pmem), pResDataEntry->DataRva, pResDataEntry->Size);
                        g_num_of_entries = 1;
                }else{
                        g_res_list = (PRESOURCE_LIST)qrealloc(g_res_list, (g_num_of_entries + 1) * sizeof(RESOURCE_LIST));
                        FillResourceList(&g_res_list[g_num_of_entries], (void *)(dwDataRaw + pmem), pResDataEntry->DataRva, pResDataEntry->Size);
                        g_num_of_entries++;
                }
__NextEntry:    
                if (b_name && b_ok){
                        qfree(g_szName);
                }                                  
                pResDirEntry++;
                dwNumberOfEntries--;        
        }
        return 0;
}

static ULONG   idaPopulateResourceName(ULONG_PTR resBase,PRES_DIR pResDir){
        PRES_DIR        pSubResDir;
        PRES_DIR_ENTRY  pResDirEntry;
        DWORD           dwNumberOfEntries;
        BOOL            b_ok, b_name;
        
        dwNumberOfEntries = pResDir->NumberOfNameEntries + pResDir->NumberOfIdEntries;
        if ((ULONG_PTR)pResDir - pmem + sizeof(RES_DIR) + sizeof(RES_DIR_ENTRY) * dwNumberOfEntries > dwFileSize) return 0;
        
        pResDirEntry = (PRES_DIR_ENTRY)((ULONG_PTR)pResDir + sizeof(RES_DIR));   

        while (dwNumberOfEntries){
                g_szName = ExtractNameOrId(pResDirEntry, &b_ok, &b_name);
                if (!b_ok) goto __NextEntry;
                b_namename = b_name;
                if (!(pResDirEntry->SubDirectoryRva & 0x80000000)){
                        //report error here and continue, as next in Name is actually DataEntry (this is wrong!!!! in normal file)        
                        msg("[ERROR] %s -- SubDirectoryRva set as DataEntry offset in file : %.08X\n", __FUNCTION__, (ULONG_PTR)pResDirEntry - pmem);                                                                                                
                        if (b_name)
                                msg("[ERROR] %s -- Name name (name) : %s\n", __FUNCTION__, g_szName);
                        else
                                msg("[ERROR] %s -- Name name (id)   : %d\n", __FUNCTION__, g_szName);
                        goto __NextEntry;                                                                                                                 
                }
                
                //check if RES_DIR is actually in this file...
                pSubResDir = (PRES_DIR)(resBase + (pResDirEntry->SubDirectoryRva & 0x7FFFFFFF));
                if ((ULONG_PTR)pSubResDir + sizeof(RES_DIR) - pmem > dwFileSize){
                        msg("[ERROR] %s -- SubDirectoryEntry at offset : %.08X is out of file size\n", __FUNCTION__, (ULONG_PTR)pSubResDir - pmem);
                        if (b_name)
                                msg("[ERROR] %s -- Name name (name) : %s\n", __FUNCTION__, g_szName);
                        else
                                msg("[ERROR] %s -- Name name (id)   : %d\n", __FUNCTION__, g_szName);
                        goto __NextEntry;
                }
                
                //everything seems kewl... we go for Lang in this type...
                idaPopulateResourceLang(resBase, pSubResDir);
__NextEntry:    
                if (b_name && b_ok){
                        qfree(g_szName);
                }                                  
                pResDirEntry++;
                dwNumberOfEntries--;        
        }
        return 0;
}

ULONG   idaPopulateResources(){    
        PRES_DIR          pResDir, pSubResDir;
        PRES_DIR_ENTRY    pResDirEntry;
        DWORD             dwNumberOfEntries;
        BOOL              b_ok, b_name;
        
        pResDir = (PRES_DIR)resBase;
        if (resraw + sizeof(RES_DIR) > dwFileSize) return 0;
        
        dwNumberOfEntries = pResDir->NumberOfNameEntries + pResDir->NumberOfIdEntries;
        
        if ((resraw + sizeof(RES_DIR) + sizeof(RES_DIR_ENTRY) * dwNumberOfEntries) > dwFileSize) return 0;
        
        pResDirEntry = (PRES_DIR_ENTRY)((ULONG_PTR)pResDir + sizeof(RES_DIR));
        
        //every RES_DIR_ENTRY is stored in global_var so we know what actually is going on...
        while (dwNumberOfEntries){
                g_szType = ExtractNameOrId(pResDirEntry, &b_ok, &b_name);
                if (!b_ok) goto __NextEntry;
                b_nametype = b_name;
                if (!(pResDirEntry->SubDirectoryRva & 0x80000000)){
                        //report error here and continue, as next in Type is actually DataEntry (this is wrong!!!! in normal file)        
                        msg("[ERROR] %s --  SubDirectoryRva set as DataEntry offset in file : %.08X\n", __FUNCTION__, (ULONG_PTR)pResDirEntry - pmem);                                                                                                
                        if (b_name)
                                msg("[ERROR] %s -- Type name (name) : %s\n", __FUNCTION__, g_szType);
                        else
                                msg("[ERROR] %s -- Type name (id)   : %d\n", __FUNCTION__, g_szType);
                        goto __NextEntry;                                                                                                                 
                }
                
                //check if RES_DIR is actually in this file...
                pSubResDir = (PRES_DIR)(resBase + (pResDirEntry->SubDirectoryRva & 0x7FFFFFFF));
                if ((ULONG_PTR)pSubResDir + sizeof(RES_DIR) - pmem > dwFileSize){
                        msg("[ERROR] %s -- SubDirectoryEntry at offset : %.08X is out of file size\n", __FUNCTION__, (ULONG_PTR)pSubResDir - pmem);
                        if (b_name)
                                msg("[ERROR] %s -- Type name (name) : %s\n", __FUNCTION__, g_szType);
                        else
                                msg("[ERROR] %s -- Type name (id)   : %d\n", __FUNCTION__, g_szType);
                        goto __NextEntry;
                }
                
                //everything seems kewl... we go for Name in this type...
                idaPopulateResourceName(resBase, pSubResDir);
__NextEntry:    
                if (b_name && b_ok){
                        qfree(g_szType);
                }                                  
                pResDirEntry++;
                dwNumberOfEntries--;        
        }
        
        return dwNumberOfEntries;        
}


