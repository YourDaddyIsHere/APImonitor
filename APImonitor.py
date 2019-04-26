import os,sys
import pefile
import sys
import ctypes
import pydasm
import struct
from socket import *

from pydbg import *
from pydbg.defines import *
import utils


#################################################################################
def event_handler_create_process (dbg):
    '''
    This is the default CREATE_PROCESS_DEBUG_EVENT handler.

    @rtype:  DWORD
    @return: Debug event continue status.
    '''

    dbg._log("event_handler_create_process()")
    print "process created"
    #hook_function_by_name(dbg,"WS2_32.dll","send")
    dbg.bp_set(entry_addr)
    #dbg.bp_set(0x100739D)
    print "EIP: "+str(hex(dbg.context.Eip))
    print "exception_address: "+str(hex(dbg.exception_address))

    # don't need this.
    dbg.close_handle(dbg.dbg.u.CreateProcessInfo.hFile)

    if not dbg.follow_forks:
        return DBG_CONTINUE

    if dbg.callbacks.has_key(CREATE_PROCESS_DEBUG_EVENT):
        #return dbg.callbacks[CREATE_PROCESS_DEBUG_EVENT](dbg)
        pass
    else:
        return DBG_CONTINUE
    return DBG_CONTINUE
##################################################################################
def my_event_handler_exit_process(dbg):
    print "exit process"
    #print "my pid is: "+str(dbg.my_pid)
    #print "EIP: %08x" % (dbg.context.Eip)+"        "+"ESP:%08x" %(dbg.context.Esp)
    disasm    = dbg.disasm(dbg.context.Eip)
    print "%08x: %s" % (dbg.context.Eip, dbg.disasm(dbg.context.Eip))
    dbg.set_debugger_active(True)
    handler_single_step(dbg)
##################################################################################
def handler_breakpoint (dbg):
    '''
    for module in dbg.iterate_modules():
        if module.szModule.lower().endswith(".exe"):
            begin = module.modBaseAddr
            end   = module.modBaseAddr + module.modBaseSize
            print "%s %08x -> %08x" % (module.szModule, begin, end)




        for tid in dbg.enumerate_threads():
            #print "    % 4d -> setting single step" % tid
            handle = dbg.open_thread(tid)
            #dbg.single_step(True, handle)
            dbg.close_handle(handle)
    '''
    
    #if it is the entry point of the .exe file, we need to do something
    if dbg.context.Eip == entry_addr:
        on_entry_point(dbg)
        dbg.single_step(True)


    #dbg.single_step(True)
    #new_context = user_operate(dbg)
    return DBG_CONTINUE
####################################################################################
def handler_new_thread (dbg):
    print "thread created"
    print "EIP: "+str(hex(dbg.context.Eip))
    #print "exception_address: "+str(hex(dbg.exception_address))
    #dbg.single_step(True)
    #print "handler_new_thread return"
    #dbg.bp_set(entry_addr)
    #hook_function_by_name(dbg,"WS2_32.dll","WSASend")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASendTo")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","WSAConnect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    hook_function_by_name(dbg,"WS2_32.dll","WSASendTo",handler_hook_sendto)
    hook_function_by_name(dbg,"WS2_32.dll","WSASend",handler_hook_send)
    dbg.my_thread_counter=dbg.my_thread_counter+1
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")
    for module in dbg.iterate_modules():
        #print "module name is: "+str(module.szModule.lower())
        if module.szModule.lower().endswith(".exe"):
            begin = module.modBaseAddr
            end   = module.modBaseAddr + module.modBaseSize
            print "%s %08x -> %08x" % (module.szModule, begin, end)
    return DBG_CONTINUE
####################################################################################
def handler_single_step (dbg):
	#NOTE, softhook is removed once the handler function returns
	#(read the source code of pydbg if you want more details)
	#this mechanism is stupid, so, for keep my soft hooks in being,
	#I always set TF to trigger an single step Exception, 
	#and then set all hooks again in this handler function
	#YES YES...it is UGLY, but it works for now...

	#set all hooks again
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","WSAConnect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    hook_function_by_name(dbg,"WS2_32.dll","WSASendTo",handler_hook_sendto)
    hook_function_by_name(dbg,"WS2_32.dll","WSASend",handler_hook_send)
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")

    #well, print the current instructions in ASSEMBLY, so that we know where we are
    lines_display = 0
    instructions = dbg.disasm_around(dbg.context.Eip,num_inst=lines_display)
    for i in range(0,2*lines_display+1):
        if i==lines_display:
            #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            if str(instructions[i][1]).find("call [")>=0:
                callee_addr= instructions[i][1].replace('[','').replace(']','').replace('call ','')
                #print callee_addr
                if callee_addr in address_table_hex_str:
                    pass
                   #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"  "+str(address_table_hex_str[callee_addr])+"\n"
            #elif str(instructions[i][1]).find("call")>=0 :
                #print str(instructions[i][1])
                #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"  "+str(address_table_hex_str[callee_addr])+"\n"
                #pass
            elif str(instructions[i][1]).find("call")>=0:
                #print str(instructions[i][1])
                pass
                #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            #pass
        else:
            #print "       "+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            pass

    #dbg.single_step(True)

    return DBG_CONTINUE
###################################################################################
def on_entry_point(dbg):
	#first we need to save address of all functions in DLLs in a list
	#so we can find those functions by name later.
    update_function_table(dbg)
    print "the send in WS2_32.dll is at:"
    
    #ok, now we set soft hooks by specifying target functions' name and
    #handler functions' name (handler functions are specified by ourselves)
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","WSAConnect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    hook_function_by_name(dbg,"WS2_32.dll","WSASendTo",handler_hook_sendto)
    hook_function_by_name(dbg,"WS2_32.dll","WSASend",handler_hook_send)
    #print "%08x"%import_table["WS2_32.dll"]["send"]
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")
##################################################################################
def hook_function_by_name(dbg,dll_name,function_name,handler):
    #in this function, we add a hook to the a function given in parameter @function_name:
    hooks   = utils.hook_container()
    pointer_address = "%08x"%import_table[dll_name.lower()][function_name]
    pointer_address_hex = int(pointer_address, 16)
    hooks.add(dbg,pointer_address_hex,3,handler,None)
    #abc = 2222
    #print "abc"+abc
##################################################################################
def update_function_table(dbg):
    #now I just clean the address table, we may have a better strategy,
    #but it works...for now
    address_table = dict()
    address_table_str_hex = dict()
    GetModuleHandle = windll.kernel32.GetModuleHandleA
    GetProcAddress =windll.kernel32.GetProcAddress
    GetModuleHandle.argtypes = [c_char_p]
    GetModuleHandle.restype = c_int 
    GetProcAddress.argtypes=[c_int,c_char_p]
    GetProcAddress.restype = c_int

    for module in dbg.iterate_modules():
        print "now processing module: "+module.szModule.lower()
        if module.szModule.lower().find(".exe")<0:
            print module.szModule.lower();
            export_function_list = get_export_function_list(module.szModule.lower())
            for function in export_function_list:
                function_addr = GetProcAddress(GetModuleHandle(module.szModule.lower()),function)
                #now update import table
                if module.szModule.lower() not in import_table:
                    import_table[module.szModule.lower()] = dict()
                import_table[module.szModule.lower()][function] = function_addr
                #now update address table
                address_table[function_addr] = (module.szModule.lower(),function)
                address_table_hex_str[str(hex(function_addr))] = (module.szModule.lower(),function)

###################################################################################
def get_export_function_list(dll_name):

    path = "C:\\windows\\system32"
    filename = path+"\\"+dll_name
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    try:
        pe = pefile.PE(filename, fast_load=True)
    except:
        print "failed to open dll"
        return []
    pe.parse_data_directories(directories=d)

    print "# %s exports for 'Ordinals to Names' Hopper Script" % os.path.basename(filename)
    print "# Ordinal        Name"
    
    export_function_list = []
    if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
        print type(pe.DIRECTORY_ENTRY_EXPORT)
        exports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        #export_function_list = []
        for export in sorted(exports):
        #print "%-4d %s" % export
            print export[1]
            export_function_list.append(export[1])
        return export_function_list 

    else:
        return export_function_list
##################################################################################
def get_entry(pe):
    print "[entry]"
    print "#"*45
 
    off_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base_entry = pe.OPTIONAL_HEADER.ImageBase
    print "entry point offset: "+ "%10x" % off_entry
    print "entry point base: "+ "%10x" % base_entry
    print "entry point : "+ "%08x" % (base_entry+off_entry)
    entry_addr = base_entry+off_entry
    return entry_addr
###############################################################################
def handler_hook_connect(dbg,args):
    #this is the handler for the hook in connect() and WSAConnect()


    #well, let's print something on the screen to tell you this
    #handler function is successfully called
    dbg.my_hook_counter= dbg.my_hook_counter+1
    print "hook_connect!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

    #I need to explain here:
    #when the handler function is called, (that means we 
    #enter the first line of codes in the target function)
    #the stacks looks like:
    #ESP     -- > return address
    #ESP + 4 -- > parameter 1
    #ESP + 8 -- > parameter 2
    #ESP + 12 -- > parameter 3
    #ESP + 16 -- > ......

    #that means ALL parameters silently lies in stack (assuming stdcall)
    #so, what we need is read this parameters out of the stack
    #get_arg() provides convenience for that
    #get parameter 0, namely, the return address
    return_address = dbg.get_arg(index=0)

    #get the parameter 1, in connect() and WSAConnect(),it is a SOCKET
    socket = dbg.get_arg(index=1)

    #get the parameter 2, in connect() and WSAConnect(), it is the address of sockaddr struct
    pointer_sockaddr = dbg.get_arg(index=2)
    #the port number lies in the sa_data in sock_addr,
    #sa_data has an offset 2 in sock_addr
    #and the port has an offset 2 in sa_data
    #so, this is the way we access the port number
    port_str = dbg.read_process_memory(pointer_sockaddr+2,2)
    ip_str = dbg.read_process_memory(pointer_sockaddr+4,4)

    #well done! we have the port and the ip in string
    #now we need to get the hex
    #Note! we have little-endian big-endian issue here
    real_port_str=""
    for i in range(0,len(port_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_port_str += "%02x" % ord(port_str[i])
    print "the port string is: "+real_port_str

    real_ip_str = ""

    for i in range(0,len(ip_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_ip_str += "%02x" % ord(ip_str[i])
    real_ip_int = int(real_ip_str,16)

    #this should be the correct ip
    real_ip_str_final = inet_ntoa(struct.pack("!I",real_ip_int))
    print inet_ntoa(struct.pack("!I",real_ip_int))

    #this should be the correct port
    print "the port int is: "+str(int(real_port_str,16))

    #and here is the (ip,port) tuple
    addr = (real_ip_str_final,int(real_port_str,16))
    #add_dst_addr(addr)



    dbg.single_step(True)
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")


    return  DBG_CONTINUE
###############################################################################
def handler_hook_bind(dbg,args):
    dbg.my_hook_counter= dbg.my_hook_counter+1
    print "hook_bind!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    print "hook counter: "+ str(dbg.my_hook_counter)
    print "thread counter: "+str(dbg.my_thread_counter)

    return_address = dbg.get_arg(index=0)
    socket = dbg.get_arg(index=1)
    pointer_sockaddr = dbg.get_arg(index=2)
    port_str = dbg.read_process_memory(pointer_sockaddr+2,2)
    ip_str = dbg.read_process_memory(pointer_sockaddr+4,4)


    real_port_str=""
    for i in range(0,len(port_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_port_str += "%02x" % ord(port_str[i])
    print "the port string is: "+real_port_str

    real_ip_str = ""

    for i in range(0,len(ip_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_ip_str += "%02x" % ord(ip_str[i])
    real_ip_int = int(real_ip_str,16)
    print inet_ntoa(struct.pack("!I",real_ip_int))

    #this should be the correct port
    print "the port int is: "+str(int(real_port_str,16))
    dbg.single_step(True)


    return  DBG_CONTINUE 

###############################################################################
def handler_hook_sendto(dbg,args):
    print "sendto!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    dbg.single_step(True)
    return  DBG_CONTINUE 
###############################################################################
def handler_hook_send(dbg,args):
    print "send#################################################"
    dbg.single_step(True)
    return  DBG_CONTINUE 
###############################################################################
dbg = pydbg()

dbg.set_callback(EXCEPTION_BREAKPOINT,      handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP,     handler_single_step)
dbg.set_callback(CREATE_THREAD_DEBUG_EVENT, handler_new_thread)
dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT,my_event_handler_exit_process)
dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT,event_handler_create_process)
#dbg.set_callback(EXCEPTION_DEBUG_EVENT,handler_exception)
#dbg.set_callback(LOAD_DLL_DEBUG_EVENT,handler_load_dll)

#filename = "C:\\Windows\\System32\\notepad.exe"
filename = "C:\\Telegram Desktop\\Telegram.exe"
#filename = "C:\\Telegram Desktop\\Telegram.exe"
#filename = "E:\\tools\\thunder 9\\Program\\Thunder.exe"
#filename = "C:\\Program Files (x86)\\Thunder Network\\Thunder\\Program\\ThunderStart.exe"
#filename = "C:\\Users\\LCL\\Documents\\codes\\PracticalMalwareAnalysis-Labs.exe"

dbg.load(filename)
pe = pefile.PE(filename)
entry_addr = None
import_table = dict()
address_table = dict()
address_table_hex_str = dict()

dbg.my_hook_counter=0
dbg.my_thread_counter=0
#now we have a dict for all loaded library, but the address is not reliable, 
#when we reach the entry point (that means the PE loader has finished its job)
#we should get the correct address using getMouldeHandle and GetProcaddress
#NOTICE:when dealing with a sample with protector, the IAT is not completed before OEP,
#so this procedure can be delayed until we find oep

entry_addr=get_entry(pe)
dbg.bp_set(entry_addr)
#show_imports(pe)
#this is an old crap to save function address in DLLs, it is obsoleted
#record_functions(pe)

dbg.run()