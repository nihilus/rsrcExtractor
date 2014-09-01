/******************************************************************************
 *                      rsrcExtractor IDA plugin
 *                                      derok of ARTeam
 *
 * One of the things I always missed in IDA is parsing of resources. IDA has 
 * option to load resources, but it's nothing more than dummy data.
 * This plugin allows us to load resources from file on disk, and see their
 * structure. First time you use plugin on existing database you must have
 * that file on disk, as only 1st time I'm using file on disk to parse resources
 * and store them into netnodes, which allows ppl to share database with full
 * resource layout without need to distribute original file.
 *
 * To use plugin, just press 'P' and you should see resource layout. Before loading
 * file, it's smart to select "Load Resources" in IDA, thus Jump to Data option
 * will actually work, and you will be able to inspect resources in IDA without
 * saving them to the disk.
 *
 *                                             (c) 2011 deroko of ARTeam
 *******************************************************************************/
#include        "defs.h"

static const char    *header[] =       {
        "Type",
        "Name",
        "Lang",
        "Data"
};

static int widths[] = {20, 20, 5, 40};
static const char *popups[] = {"Save data", "Jmp to data", "Save all", NULL};
static uint32  g_dwCommand = 0;
static const char *szform = 
        "STARTITEM 0\n"
        "Choose directory to save all resources : \n\n"
        "<Output directory:F:1:32::>\n";
/*********************************************************
 * Define some global vars, as I will be using these from
 * different functions...
 *********************************************************/
PIMAGE_DOS_HEADER       pmz     = NULL;
#ifndef __EA64__
PPEHEADER32             pe32    = NULL;
#else
PPEHEADER64             pe32    = NULL;
#endif
PSECTION_HEADER         section = NULL;
FILE                    *pfile  = NULL;
ULONG                   dwFileSize;
ULONG_PTR               pmem;   //ida is always 32bits so this is always 32 bits...
ULONG_PTR               resBase;
ULONG                   resraw;
DWORD                   g_num_of_entries;
PRESOURCE_LIST          g_res_list;

static ULONG  ReadNetNodesToList(){
        uint32          index, netnode_index;
        char            buffer[MAXNAMESIZE];
        uint32          size, copy_size;
        PVOID           pdata;
        uint32          slen;
        
        netnode         n("$ rsrcExtractorNetNode"); //, 0, false);
        if (n == BADNODE){
                msg("%s - plugin netnode not found\n", __FUNCTION__);
                return 1;
        }
        
        g_num_of_entries = n.altval(0);
        if (g_num_of_entries == 0){
                msg("%s -- no resources for this database\n", __FUNCTION__);
                return 1;
        }
        
        for (index = 0; index < g_num_of_entries; index++){
                memset(buffer, 0, sizeof(buffer));
                qsnprintf(buffer, MAXNAMESIZE, "$ rsrcExtractorNetNode_%d", index);
                
                netnode ndata(buffer, 0, false);
                if (ndata == BADNODE){
                        msg("%s -- opeing netnode for data reading failed...\n", __FUNCTION__);
                        continue;
                }
                
                if (g_res_list == NULL){
                        g_res_list = (PRESOURCE_LIST)qalloc(sizeof(RESOURCE_LIST));
                }else{
                        g_res_list = (PRESOURCE_LIST)qrealloc(g_res_list, (index + 1) * sizeof(RESOURCE_LIST));
                }
                
                g_res_list[index].raw  = ndata.altval(0);
                g_res_list[index].rva  = ndata.altval(1);
                g_res_list[index].size = ndata.altval(2);
                
                slen = ndata.supval(0, NULL, 0);
                g_res_list[index].szType = (char *)qalloc(slen+1);
                memset(g_res_list[index].szType, 0, slen);
                ndata.supval(0, g_res_list[index].szType, slen);
                
                slen = ndata.supval(1, NULL, 0);
                g_res_list[index].szName = (char *)qalloc(slen+1);
                memset(g_res_list[index].szName, 0, slen);
                ndata.supval(1, g_res_list[index].szName, slen);
                
                slen = ndata.supval(2, NULL, 0);
                g_res_list[index].szLang = (char *)qalloc(slen+1);
                memset(g_res_list[index].szLang, 0, slen);
                ndata.supval(2, g_res_list[index].szLang, slen);
                
                pdata = g_res_list[index].data = qalloc(g_res_list[index].size);
                
                size = g_res_list[index].size;
                netnode_index = 3;
                
                while (size != 0){
                        copy_size = (size > MAXSPECSIZE) ? MAXSPECSIZE : size;
                        
                        ndata.supval(netnode_index, pdata, copy_size);
                        
                        size -= copy_size;
                        pdata = (void *)((ULONG_PTR)pdata + copy_size);
                }
        }  
        return 0; 
}

//we are using one index netnode (to tell us where is data)
//and for each resource we create one netnode with their index
//
static VOID    BuildAndStoreNetnodes(){
        uint32          index, netnode_index;
        char            buffer[MAXNAMESIZE];
        uint32          size, copy_size;
        PVOID           pdata;
        
        netnode         n("$ rsrcExtractorNetNode", 0, true);       
        if (n == BADNODE) return;
        //at index 0 we store how many entries are there
        n.altset(0, g_num_of_entries);
        
        //no entries, well we can't do much about it... huh... so we just exit...
        if (g_res_list == NULL) return; 
                
        //every new netnode is set like this
        //name " $ rsrcExtractorNetNode %d" where %d is index used in g_res_list
        //index 0 altval = RAW from g_res_list
        //index 1 altval = RVA from g_res_list
        //index 2 altval = SIZE from g_res_list
        //index 0 supval = type of resource
        //index 1 supval = name of resource
        //index 2 supval = lang of resource
        //index 3-n      = data  
        for (index = 0; index < g_num_of_entries; index++){
                memset(buffer, 0, sizeof(buffer));
                qsnprintf(buffer, MAXNAMESIZE, "$ rsrcExtractorNetNode_%d", index);                        
                
                netnode ndata(buffer, 0, true);
                if (ndata == BADNODE){
                        msg("%s -- creating netnode for data storage failed...\n", __FUNCTION__);
                        continue;
                }
                ndata.altset(0, g_res_list[index].raw);
                ndata.altset(1, g_res_list[index].rva);
                ndata.altset(2, g_res_list[index].size);  
                
                ndata.supset(0, g_res_list[index].szType);
                ndata.supset(1, g_res_list[index].szName);
                ndata.supset(2, g_res_list[index].szLang);
                size  = ndata.altval(2);
                
                netnode_index = 3;                 
                pdata = g_res_list[index].data;
                
                while (size){
                        copy_size = (size > MAXSPECSIZE) ? MAXSPECSIZE : size;
                        ndata.supset(netnode_index, pdata, copy_size);
                        size -= copy_size;
                        netnode_index++;         
                        pdata = (void *)((ULONG_PTR)pdata + copy_size);
                }
                 
        }
        
}

static void idaapi desc(void *obj,uint32 n,char * const *arrptr)
{
        char    szBuffer[MAXSTR];
        uint32  index = n - 1;
        
        if ( n == 0 ){
                for ( int i=0; i < qnumber(header); i++ )
                        qstrncpy(arrptr[i], header[i], MAXSTR);
                return;
        }
        
        if (g_num_of_entries == 0) return;
        
        qstrncpy(arrptr[0], g_res_list[index].szType, MAXSTR);
        qstrncpy(arrptr[1], g_res_list[index].szName, MAXSTR);
        qstrncpy(arrptr[2], g_res_list[index].szLang, MAXSTR);
        qsnprintf(arrptr[3], MAXSTR, "Offset in file : %.08X RVA : %.08X Size in bytes : %d", g_res_list[index].raw,
                                                                                              g_res_list[index].rva,
                                                                                              g_res_list[index].size);  
}

static uint32 idaapi sizer(void *obj)
{
        return g_num_of_entries;
}

//we use this as "Jmp to data function";
static uint32 idaapi del(void *obj, uint32 n){
        g_dwCommand = RSRC_EXTRACT_JMPTODATA;
        return 1;
}

//we use this as "Save as function"
static void ins(void *obj){
        g_dwCommand = RSRC_EXTRACT_SAVEDATA;
        return;
}

static uint32 idaapi update(void *obj, uint32 n){
        char    buffer[MAXSTR];
        char    filename[MAXSTR];
        char    *szFileToSave;
        ULONG   index = n - 1;
        FILE    *psave;
        
        if (g_num_of_entries == 0) return 0;
        if (g_res_list == NULL) return 0;
        
        memset(buffer, 0, sizeof(buffer));
        
        if (g_dwCommand == RSRC_EXTRACT_SAVEDATA){
                //qsnprintf(buffer, MAXSTR, "update at : %d - save data\n", n);
                szFileToSave = askfile_c(true, "*.bin", "Save resource to file : ");
                if (szFileToSave != NULL){
                        if (index < g_num_of_entries){
                                psave = qfopen(szFileToSave, "w");
                                if (psave){
                                        qfwrite(psave, g_res_list[index].data, g_res_list[index].size);
                                        qfclose(psave);
                                }else{
                                        msg("%s -- Failed to open file : %s for save\n", __FUNCTION__, szFileToSave);
                                }
                         }
                }
        }else if (g_dwCommand == RSRC_EXTRACT_JMPTODATA){
                //qsnprintf(buffer, MAXSTR, "update at : %d - jump to data\n", n);  
                //NOT IMPLEMENTED...  
                if (!jumpto(g_res_list[index].rva + get_imagebase()))
                        msg("rsrcExtractor - jumpto failed\n");   
        }else if (g_dwCommand == RSRC_EXTRACT_SAVEALLDATA){
                memset(buffer, 0, sizeof(buffer));
                if (!g_res_list) goto __Exit0;
                if (AskUsingForm_c(szform, buffer)){
                        //now we just dump_all_resources...
                        for (index = 0; index < g_num_of_entries; index++){
                                memset(filename, 0, MAXSTR);
                                #ifdef __LINUX__
                                qsnprintf(filename, MAXSTR, "%s/%s_%s_%s.bin", buffer,
                                                                               g_res_list[index].szType,
                                                                               g_res_list[index].szName,
                                                                               g_res_list[index].szLang);        
                                #else
                                qsnprintf(filename, MAXSTR, "%s\\%s_%s_%s.bin", buffer,
                                                                               g_res_list[index].szType,
                                                                               g_res_list[index].szName,
                                                                               g_res_list[index].szLang);
                                #endif
                                psave = qfopen(filename, "w");
                                if (!psave){
                                        msg("Saveing All Resources : Failed to create file : %s\n", __FUNCTION__, filename);
                                        continue;
                                }
                                qfwrite(psave, g_res_list[index].data, g_res_list[index].size);
                                qfclose(psave);
                        }
                        msg("Saving All Resources : DONE!\n");
                }
        }
        //msg(buffer);
__Exit0:        
        g_dwCommand = 0;
        
        return n;
}

static void idaapi edit(void *obj, uint32 n){
        g_dwCommand = RSRC_EXTRACT_SAVEALLDATA;
        return;
}

static void idaapi enter(void *obj, uint32 n){
        return;
}

static void idaapi destroy(void *obj){
        return;
} 

static int buildChooser(){
        int   ret;
        ret = choose2(0, -1, -1, -1, -1,
                      NULL,
                      qnumber(header),
                      widths,
                      sizer,
                      desc,
                      "Resource Listing",
                      -1,
                      0,
                      del,
                      ins,
                      update,
                      edit, //edit,
                      enter, //enter,
                      destroy, //destroy,
                      popups,
                      NULL);   
        if (ret != 0)
                msg("%s -- Failed to create window...\n", __FUNCTION__);           
        return ret;  
}


int idaapi init(void){
        g_dwCommand = 0;
        g_num_of_entries = 0;
        //support only for PE32 (PE32+ will be added shorty)
        if (ph.id != PLFM_386 && inf.filetype != f_PE)
                return PLUGIN_SKIP;
        return PLUGIN_OK;
}

void idaapi term(void){
        DWORD   index;
        if (g_num_of_entries != 0 && g_res_list != NULL){
                for (index = 0; index < g_num_of_entries; index++){
                        qfree(g_res_list[index].data);
                        qfree(g_res_list[index].szType);
                        qfree(g_res_list[index].szName);
                        qfree(g_res_list[index].szLang);   
                }
                memset(g_res_list, 0, g_num_of_entries * sizeof(RESOURCE_LIST));
                qfree(g_res_list);
        }
}
/*************************************************************
 * We need to see if we want to get resources from file, or 
 * from database, and populate them
 *************************************************************/
void idaapi run(int arg)
{
        char    szFileName[MAX_PATH + MAX_PATH];
        int     ret;
        ULONG   dwFileSizeRaw, index;
        
        msg("Imagebase at : %.08X\n", get_imagebase());
        
        if (g_num_of_entries != 0) goto __BuildWindow;
        
        if (0 == ReadNetNodesToList()) goto __BuildWindow;
               
        memset(szFileName, 0, sizeof(szFileName));
        get_input_file_path(szFileName, sizeof(szFileName));
        
        pfile = qfopen(szFileName, "rb");
        if (!pfile) goto __Exit0;
        
        //add check that user is prompted to select input file in case we can't locate it
        //eg. db shara, where 1st user forgot to run plugin... heh, shit happens...
                
        dwFileSize = efilelength(pfile);
        pmem = (ULONG_PTR)qalloc(dwFileSize);   
        if (!pmem) goto __Exit0;    
        qfread(pfile, (void *)pmem, dwFileSize);
 
        pmz  = (PIMAGE_DOS_HEADER)pmem;

        //check if we can access data here at all...
        if (pmz->e_magic != IMAGE_DOS_SIGNATURE) goto __Exit0;
        if (pmz->e_lfanew > 0x1000) goto __Exit0;
        if (pmz->e_lfanew > dwFileSize-sizeof(PEHEADER32)) goto __Exit0;
        
        //check pe32 signature
        #ifndef __EA64__
        pe32 = (PPEHEADER32)(pmem + pmz->e_lfanew);
        #else
        pe32 = (PPEHEADER64)(pmem + pmz->e_lfanew);
        #endif
        if (pe32->pe_signature != IMAGE_NT_SIGNATURE) goto __Exit0;

        //check if we have enough file data size to actually access sections, if not, we bail out...        
        if ((pe32->pe_numberofsections * sizeof(SECTION_HEADER) + ((ULONG)pe32 + pe32->pe_sizeofheaders - pmem)) > dwFileSize) goto __Exit0;

        section = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader);

        //are there any resources? If not we bail out...
        if (pe32->pe_resource == 0) goto __Exit0;
        
        
        //determine actual size of a file based on sh_pointertorawdata and sh_sizeofrawdata. We need this
        //as total file size can include overlay
        dwFileSizeRaw = 0;
        for (index = 0; index < pe32->pe_numberofsections; index++){
                if (section[index].sh_sizeofrawdata == 0) continue;     //empty .bss section... skip it...
                dwFileSizeRaw = (section[index].sh_pointertorawdata + section[index].sh_sizeofrawdata > dwFileSizeRaw) ? section[index].sh_pointertorawdata + section[index].sh_sizeofrawdata : dwFileSizeRaw;               
        }
        
        //if dwFileSizeRaw is bigger, then there is something wrong with this file, so we go for original dwFileSize;
        dwFileSize = (dwFileSizeRaw > dwFileSize) ? dwFileSize : dwFileSizeRaw;
        
        resBase = resraw = rva2raw(pe32->pe_resource);
        if (resBase == 0xFFFFFFFF) goto __Exit0;
        if (resBase > dwFileSize) goto __Exit0;
        
        resBase += pmem;

        idaPopulateResources();
        
        //now is time to build netnodes to represent our data accross databases... Any other way?!?! Huh...
        BuildAndStoreNetnodes();   
__BuildWindow:        
        if (buildChooser() != 0)
                msg("%s -- Failed to build resource view\n", __FUNCTION__);      
__Exit0:
        if (pmem){
                qfree((void *)pmem);
                pmz = NULL;
                pe32= NULL;
                section = NULL; 
                pmem = 0;      
                
        }
        if (pfile){
                eclose(pfile);
                pfile = NULL;
        }
}


plugin_t PLUGIN =
{
        IDP_INTERFACE_VERSION,
        0,
        init,                 
        term,                 
        run,                  
        NULL,
        NULL, 
        "rsrcExtractor",
        "P"
};


