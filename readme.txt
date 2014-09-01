                        rsrcExtractor plugin
                                        (c) 2011 deroko of ARTeam
                                        
        I was always bothered that IDA doesn't have code which can parse
resources. After a while (several years!?) I've decided to write it. IDA
by default doesn't load resources, and when you select "Load Resources" 
it loads it as a data, which sometimes annoys me as I can't save data, or
simply jump to it to see what that data actually is.

How to compile:

On linux you need to modify Makefile and set LIBPATH to be path to your 
Linux IDA, and set INCLUDE to be path to IDA SDK include directory. Type
make and you should get your plugin up and running. This will create 
pluigns for IDA 32 and IDA 64 at the same time.

On windows, you will need to use WDK (I hate using Visual Studio), and set
TARGETLIBS to point to proper libraries for IDA32 and IDA64.

#for ida32
TARGETEXT=plw
C_DEFINES       =       $(C_DEFINES) /D__NT__ /DNDEBUG /D__IDP__ /DMAXSTR=1024
TARGETLIBS      =       $(SDK_LIB_PATH)\kernel32.lib\
                        Z:\idasdk61\lib\x86_win_vc_32\ida.lib


#for ida64
#TARGETEXT=p64
#C_DEFINES       =       $(C_DEFINES) /D__EA64__ /D__NT__ /DNDEBUG /D__IDP__ /DMAXSTR=1024
#TARGETLIBS      =       $(SDK_LIB_PATH)\kernel32.lib\
#                        Z:\idasdk61\lib\x86_win_vc_64\ida.lib

Depending on what you want to build (plugin for ida32 or for ida64) you will 
have to remove some comments, and comment out some parts. For ida32 leave as
is, for ida64 uncomment at line "for ida64" and comment out lines "for ida32".
That should be it. Also make sure that Makefile is not present in this folder
as WDK uses different makefile. All you need for WDK is "sources" file, and 
only type build or bld -w and it will give you plugins in .\i386 folder.

How to use it?

There are 2 ways how this plugin works:
1. First time you load file, use 'P' or Edit->Plugins->rsrcExtractor to get
   all resources. This will at the same time create netnodes in current 
   database, thus database can be shared with different users without need
   to share original file
2. Plugin will first check if netnodes are present in database, and if so,
   it will get resources from them, instead of looking for file on disk.
   This is useful, if you are sharing database without sharing actual file.
   
The best way plugin will work, is if you select "Load Resources", thus you
can actually use option "Jump to data" to view resources inside of IDA. I don't 
load resources in segments, nor I create new segments. It's possible that 
resources are malformed, and trying to load them into current database might
lead to data lose of already done work, thus use "Load Resources" option to
load (more or less) whole file into database.

2 more available options are "Save data" which saves selected resource to specified
file, and "Save all" which requires you to provide directory, where all data from
resources will be saved.

Hope you find it useful.

                                                (c) 2011 deroko of ARTeam

 