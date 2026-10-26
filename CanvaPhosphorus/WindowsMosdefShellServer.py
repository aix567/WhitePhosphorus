from exploitutils import devlog
from WindowsConstants import keyDict
from WindowsConstants import accessDict

from MOSDEF.mosdefutils import sint32, sint64

SEND_RETURN = {64: "sendlonglong",
                  32: "sendint"
}

HANDLE_TYPE = {64: "long long",
               32: "int"
}

POINTER_TYPE = {64: "long long",
                 32: "int"
}

REMOTE_IMPORT_TYPE = {64: "local",
                      32: "remote"
}

class WindowsMosdefShellServer(object):
    def __init__(self, arch):
        global SEND_FUNCTIONS
        global POINTER_TYPE
        global REMOTE_IMPORT_TYPE
        
        self.bit_width = 64
        
        if arch.endswith("64"):
            self.bit_width = 64
        elif arch.endswith("32"):
            self.bit_width = 32
        else:
            self.bit_width = None

        self.send_return = SEND_RETURN[self.bit_width]
        self.read_return = self.readlonglong if self.bit_width == 64 else self.readint
        self.sign_t = sint32 if self.bit_width == 32 else sint64
        self.pointer_type = POINTER_TYPE[self.bit_width]
        self.return_type = POINTER_TYPE[self.bit_width]
        self.handle_type = HANDLE_TYPE[self.bit_width]
        self.import_type = REMOTE_IMPORT_TYPE[self.bit_width]


    def os_version_info(self, major=6):
        code = """
        #import "IMPORT_TYPE", "ntdll.dll|RtlGetVersion" as "RtlGetVersion"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #import "local", "sendblock" as "sendblock"
        #import "debug", "debug" as "debug"

        struct RTL_OSVERSIONINFOW {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            short szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            // it's possible there's 2 characters here, for padding? I hope not.
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        int main(){
           int ret;
           int size;
           struct RTL_OSVERSIONINFOW osvi;

           size = 288; // sizeof(RTL_OSVERSIONINFOW) + 4 (for whatever reason)

           // debug();

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           RtlGetVersion(&osvi);
           sendint(osvi.dwMajorVersion);
           sendint(osvi.dwMinorVersion);
           sendint(osvi.dwBuildNumber);
           sendint(osvi.dwPlatformId);
           sendblock(&osvi.szCSDVersion, 256);
        }
        """.replace("IMPORT_TYPE", self.import_type)

        self.clearfunctioncache()
        request=self.compile(code,{})
        self.sendrequest(request)
        version_info = {}
        version_info["major"] = self.readint()
        version_info["minor"] = self.readint()
        version_info["build"] = self.readint()
        version_info["platform"] = self.readint()

        sp_name = None
        sp_name_enc = self.readblock()
        self.leave()
        
        if all([byte == "\x00" for byte in sp_name_enc]):
            sp_name = None
        else:
            sp_name = sp_name_enc.decode("utf-16-le")
        
        version_info["service_pack"] = sp_name
        
        return version_info



    def get_integrity_level(self):
        vars = {}
        code = ("""
        #import "IMPORT_TYPE","kernel32.dll|GetCurrentProcess" as "GetCurrentProcess"
        #import "IMPORT_TYPE","kernel32.dll|GetLastError" as "GetLastError"
        #import "IMPORT_TYPE","kernel32.dll|OpenProcess" as "OpenProcess"
        #import "IMPORT_TYPE","advapi32.dll|OpenProcessToken" as "OpenProcessToken"
        #import "IMPORT_TYPE","advapi32.dll|GetSidSubAuthorityCount" as "GetSidSubAuthorityCount"
        #import "IMPORT_TYPE","advapi32.dll|GetSidSubAuthority" as "GetSidSubAuthority"
        #import "IMPORT_TYPE","advapi32.dll|GetTokenInformation" as "GetTokenInformation"
        #import "IMPORT_TYPE","advapi32.dll|IsValidSid" as "IsValidSid"
        
        #import "local", "SEND_RETURN" as "SEND_RETURN"
        #import "local", "free" as "free"
        #import "local", "malloc" as "malloc"

        struct SID_AND_ATTRIBUTES {
          void * sid;
          int attributes;
        };

        void main()
        {
        HANDLE proc_handle;
        HANDLE token_handle;
        int length_needed;
        char * psub_auth_count;
        int * pintegrity_level;
        int ret;
        int last_error;
        struct SID_AND_ATTRIBUTES * ppsid;
        
        proc_handle = GetCurrentProcess();


        // TOKEN_QUERY = 8
        ret = OpenProcessToken(proc_handle, 8, &token_handle);
        if (ret == 0){
           SEND_RETURN(0xffffff0);
           return;
        }



        // TOKEN_INTEGRITY_LEVEL = 25
        ret = GetTokenInformation(token_handle, 25, 0, 0, &length_needed);
        if (ret == 0){
           ppsid = malloc(length_needed);
        }


        if (ppsid == 0){
          SEND_RETURN(0xffffff1);
          return;
        }

        ret = GetTokenInformation(token_handle, 25, ppsid, length_needed, &length_needed);
        if (ret == 0){
           free(ppsid);
           SEND_RETURN(0xffffff2);
           return;
        }

        ret = IsValidSid(ppsid->sid);
        if (ret == 0){
           SEND_RETURN(999);
           return;
        }

        psub_auth_count = GetSidSubAuthorityCount(ppsid->sid);

        pintegrity_level = GetSidSubAuthority(ppsid->sid, *psub_auth_count-1);
        SEND_RETURN(*pintegrity_level);

        free(ppsid);
        return;
        }
        """).replace("SEND_RETURN", self.send_return).replace("IMPORT_TYPE", self.import_type).replace("HANDLE", self.handle_type)

        self.clearfunctioncache()
        request = self.compile(code,vars)

        self.sendrequest(request)
        il = self.read_return()
        self.leave()

        level = None

        if (il >= 0x1000 and il < 0x2000):
            level = "low"
        elif (il >= 0x2000 and il < 0x3000):
            level = "medium"
        elif (il >= 0x3000 and il < 0x4000):
            level = "high"
        elif (il >= 0x4000 and il < 0x5000):
            level = "system"
        elif (il >= 0x5000 and il < 0x6000):
            level = "protected"
        elif (0xffffff0 >= il and il < 0xfffffff):
            self.log("get_process_il failed with return value: %x" % il)
        else:
            self.log("get_process_il obtained unknown integrity level! %x" % il)
            level = il

        return level

    def create_reg_key(self, hkey, key_path, access):
        return_handle = None
        handle = self.RegOpenKeyEx(hkey, key_path, access)
            
        if not handle:
            devlog("winmosdefshellserver", "could not open %s, creating it" % key_path)
            new_handle = self.RegCreateKeyEx(hkey, key_path, access)

            if not new_handle:
                devlog("winmosdefshellserver", "failed to create %s! failing." % (key_path))
                return_handle = None
            else:
                devlog("winmosdefshellserver", "successfully created %s!" % key_path)
                return_handle = handle

        else:
            return_handle = handle
            devlog("winmosdefshellserver", "successfully opened %s" % key_path)

        devlog("winmosdefshellserver", "return_handle is %s!" % str(return_handle))

        return return_handle

    #Registry functions
    def get_reg_key_handle(self, hkey, key_path, access):
        dir_stack = []
        return_handle = None

        key_dirs = key_path.split("\\")
        
        if len(key_dirs) == 0:
            return None
        
        for key_entry in key_dirs[:-1]:
            dir_stack.append(key_entry)

            path = "\\".join(dir_stack)

            handle = self.create_reg_key(hkey, path, access)
            
            if handle == None:
                devlog("winmosdefshellserver", "unable to create reg key: %s" % path)
                break
            else:
                self.RegCloseKey(handle)

        devlog("winmosdefshellserver", "creating final registry key %s" % key_path)
        return_handle = self.create_reg_key(hkey, key_path, access)
        
        return return_handle

    def RegDeleteKeyEx(self, hKey, keyname):
        """
        Delete a subkey of a registry key
        """

        hKey=keyDict.get(hKey,hKey)
        vars={}

        code="""
        #import "%s","advapi32.dll|RegDeleteKeyExA" as "RegDeleteKeyExA"

        #import "local", "%s" as "%s"

        #import "%s", "hKey" as "hKey"
        #import "string", "keyname" as "keyname"



        void main()
        {
        %s ret;
        
        ret=RegDeleteKeyExA(hKey,keyname,0,0);
        %s(ret);
        }
        """ % (self.import_type, self.send_return, self.send_return,
               self.pointer_type,
               self.return_type,
               self.send_return)
        
        vars["keyname"]=keyname
        vars["hKey"]=hKey

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.read_return()
        self.leave()
        return fd


    def RegCreateKeyEx(self,hKey,keyname,access):
        """
        Create a registry key for later use
        """

        hKey=keyDict.get(hKey,hKey)
        access=accessDict.get(access,access)
        vars={}

        # Note: in order for library imports to work, they must be the *exact* same
        # name as they are in the library itself.
        
        code="""
        #import "%s","advapi32.dll|RegCreateKeyExA" as "RegCreateKeyExA"

        #import "local", "%s" as "%s"

        #import "%s", "hKey" as "hKey"
        #import "string", "keyname" as "keyname"
        #import "long", "reserved" as "reserved"
        #import "long", "options" as "options"
        #import "int", "access" as "access"



        void main()
        {
        %s ret;
        %s hKey2;
        %s securityAttributes;
        %s class;
        long options;
        
        securityAttributes = 0;
        class = 0;
        options = 0;
        
        ret=RegCreateKeyExA(hKey,keyname,0,class,options,access,0,&hKey2,0);
        if (ret==0) {
           %s(hKey2); //0 on sucess
           }
        else {
          %s(0);
         }
        }
        """ % (self.import_type, self.send_return, self.send_return, self.pointer_type,
               self.return_type,
               self.pointer_type, self.pointer_type, self.pointer_type,
               self.send_return, self.send_return)
        
        vars["keyname"]=keyname
        vars["hKey"]=hKey
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.read_return()
        self.leave()
        return fd

    def exit(self, exitcode):
        """
        Calls ExitProcess - MSDN says never to do this from a DLL, which is
        essentially what we do.

        Kostya says that we end up sending XX00XX00 as our exit code, instead of what
        you specify in exitcode. Haven't tracked down this bug yet. Possibly due to DLL's
        trying to clean themselves up in weird states.

        You'll most likely want to call TerminateProcess instead which does not
        let each DLL try to clean up.
        """
        vars={}
        vars["exitcode"]=exitcode


        code="""
        //start of code
        #import "%s","kernel32.dll|ExitProcess" as "ExitProcess"
        #import "int","exitcode" as "exitcode"

        void main()
        {
            int i;
            i=ExitProcess(exitcode);
        }
        """ % (self.import_type)
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return

    def CopyFileA(self, existing_file, new_file, fail_if_exists = False):
        if fail_if_exists is False:
            fail_if_exists = 0
        else:
            fail_if_exists = 1

        vars = {}
        vars['lpExistingFileName'] = existing_file+'\0'
        vars['lpNewFileName'] = new_file+'\0'
        vars['bFailIfExists'] = fail_if_exists


        imports = \
        """
        #import "{0}", "kernel32.dll|CopyFileA" as "CopyFileA"
        #import "{0}", "kernel32.dll|GetLastError" as "GetLastError"

        #import "string", "lpExistingFileName" as "lpExistingFileName"
        #import "string", "lpNewFileName" as "lpNewFileName"
        #import "int",  "bFailIfExists" as "bFailIfExists"

        #import "local", "{1}" as "{1}"

        """.format(self.import_type, self.send_return)

        code = ''
        code += imports

        code += \
        """
        int main()
        {
        """

        code += \
        """
        int ret;
        ret = 0;

        ret = CopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
        if (ret == 0){{
            ret = GetLastError();
            {0}(-1);
            {0}(ret);
            return;
        }}

        {0}(1);
        {0}(ret);
        return;
        """.format(self.send_return())

        code += \
        """
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        status = self.sign_t(self.read_return())
        ret = self.read_return()
        self.leave()

        if status == -1:
            devlog('winmosdefshellserver', 'CopyFileA failed - GetLastError %d' % ret)
            return None

        return ret

    #TODO: Implement correctly the lpSecurityAttributes argument
    def CreateDirectoryA(self, path, security_attributes = 0):
        vars = {}
        vars['lpPathName'] = path+'\0'
        #vars['lpSecurityAttributes'] = security_attributes

        imports = \
        """
        #import "{0}", "kernel32.dll|CreateDirectoryA" as "CreateDirectoryA"
        #import "{0}", "kernel32.dll|GetLastError" as "GetLastError"

        #import "string", "lpPathName" as "lpPathName"

        #import "local", "{1}" as "{1}"

        """.format(self.import_type, self.send_return)

        code = ''
        code += imports

        code += \
        """
        int main()
        {
        """
        code += \
        """
        int ret;
        ret = 0;

        ret = CreateDirectory(lpPathName, NULL);
        if (ret == 0){{
            ret = GetLastError();
            {0}(-1);
            {0}(ret);
            return; 
        }}

        {0}(1);
        {0}(ret);
        return;
        """.format(self.send_return)

        code += \
        """
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        status = self.sign_t(self.read_return())
        ret = self.read_return()
        self.leave()

        if status == -1:
            devlog('winmosdefshellserver', 'CreateDirectoryA failed - GetLastError %d' % ret)
            return None

        return ret

    # SYMBOLIC_LINK_ALL_ACCESS = 0xF0001
    def CreateSymlink(self, handle_root = 0, linkname = '', targetname = '', desired_access = 0xF0001):
        wstr_linkname = linkname.encode('utf-16le')+'\0\0'
        wstr_targetname = targetname.encode('utf-16le')+'\0\0'

        UNICODE_STRING_64 = \
        """
        struct UNICODE_STRING {
          unsigned short Length;
          unsigned short MaximumLength;
          char*          Buffer;  // wide char
        };

        """

        UNICODE_STRING_32 = \
        """
        struct UNICODE_STRING {
          unsigned short Length;
          unsigned short MaximumLength;
          int            padding;
          char*          Buffer;  // wide char
        };

        """
 
        UNICODE_STRING = UNICODE_STRING_32 if self.bit_width == 32 else UNICODE_STRING_64

        OBJECT_ATTRIBUTES = \
        """
        struct OBJECT_ATTRIBUTES {{
            unsigned long           Length;
            unsigned {0}            RootDirectory;
            struct UNICODE_STRING*  ObjectName;
            unsigned long           Attributes;
            char*                   SecurityDescriptor;
            char*                   SecurityDescriptorOfService;
        }};

        """.format(self.handle_type)

        imports = \
        """
        #import "{0}", "ntdll.dll|NtCreateSymbolicLinkObject" as "NtCreateSymbolicLinkObject"

        #import "{1}", "handle_root" as "handle_root"
        #import "string", "linkname" as "linkname"
        #import "string", "targetname" as "targetname"
        #import "unsigned int", "desired_access" as "desired_access"

        #import "local", "{2}" as "{2}"
        """.format(self.import_type, self.handle_type, self.send_return)

        vars = {}
        vars['handle_root'] = handle_root
        vars['linkname'] = wstr_linkname
        vars['targetname'] = wstr_targetname
        vars['desired_access'] = desired_access

        code = ''
        code += imports
        code += UNICODE_STRING
        code += OBJECT_ATTRIBUTES

        code += \
        """
        int main()
        {

        """

        code += \
        """
            struct UNICODE_STRING name;

            name.Length = {0};
            name.MaximumLength = {1};
            name.Buffer = linkname;

        """.format(len(wstr_linkname)-2, len(wstr_linkname))

        code += \
        """
            struct UNICODE_STRING target;

            target.Length = {0};
            target.MaximumLength = {1};
            target.Buffer = targetname;

        """.format(len(wstr_targetname)-2, len(wstr_targetname))

        code += \
        """
            // InitializeObjectAttributes
            struct OBJECT_ATTRIBUTES objattr;
       
            objattr.Length =  {0};
            objattr.RootDirectory = handle_root;
            objattr.Attributes = 0x40; //OBJ_CASE_INSENSITIVE
            objattr.ObjectName = &name;
            objattr.SecurityDescriptor = NULL;
            objattr.SecurityDescriptorOfService = NULL;
        
        """.format(24 if self.bit_width == 32 else 48)

        code += \
        """
            int ret;
            ret = 0;

            {0} hLink;
            ret = NtCreateSymbolicLinkObject(&hLink, desired_access, &objattr, &target);
            if (ret == 0){{
                {1}(hLink);
                return;
            }}
            else {{
                {1}(-1);
                return;
            }}

        """.format(self.handle_type, self.send_return);

        code += \
        """
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        handle = self.read_return()

        self.leave()

        if handle == 0:
            return None

        return handle

    def CreateMountPoint(self, path, target = '\\RPC Control\\', printname = ''):
        wstr_target = target.encode('utf-16le')+'\0\0'
        wstr_printname = printname.encode('utf-16le')+'\0\0'

        vars = {}
        vars['path'] = path
        vars['target'] = wstr_target
        vars['printname'] = wstr_printname

        REPARSE_DATA_BUFFER = \
        """
        struct REPARSE_DATA_BUFFER {
            unsigned long   ReparseTag;
            unsigned short  ReparseDataLength;
            unsigned short  Reserved;

            //union MountPointReparseBuffer;
            unsigned short  SubstituteNameOffset;
            unsigned short  SubstituteNameLength;
            unsigned short  PrintNameOffset;
            unsigned short  PrintNameLength;
            char            PathBuffer[1];
        };

        """

        imports = \
        """
        #import "{0}", "kernel32.dll|CreateFileA" as "CreateFileA"
        #import "{0}", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "{0}", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "{0}", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "memcpy" as "memcpy"
        #import "local", "memset" as "memset"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "local", "debug" as "debug"

        #import "string", "path" as "path"
        #import "string", "target" as "target"

        #import "local", "{1}" as "{1}"
        """.format(self.import_type, self.send_return)

        __imports_32 = \
        """
        #import "local", "sendint" as "sendint"

        """.format(self.send_return)

        __imports_64 = \
        """
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"

        """

        #imports += __imports_32 if self.bit_width == 32 else __imports_64

        code = ''
        code += imports
        code += REPARSE_DATA_BUFFER

        code += \
        """
        int main()
        {

        """

        #CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0);
        code += \
        """
            int ret;
            ret = 0;

            {0} hFile;
            hFile = CreateFileA(path, 0xC0000000, 0, NULL, 3, 0x02000000|0x00200000, 0);
            if (hFile == -1){{
                ret = GetLastError();
                {1}(-1);
                {1}(ret);
                return;
            }}

        """.format(self.handle_type, self.send_return)
         
        code += \
        """
            int target_size;
            int printname_size;
            int path_buffer_size;
            int total_buffer_size;
            struct REPARSE_DATA_BUFFER* buffer;

            target_size = {0}-2;
            printname_size = {1}-2;
            path_buffer_size = target_size + printname_size + 8 + 4;
            total_buffer_size = path_buffer_size + 8;

            char* dummy;

            buffer = malloc(total_buffer_size);
            memset(buffer, 0, total_buffer_size);

            dummy = buffer;

            buffer->ReparseTag = 0xA0000003; //IO_REPARSE_TAG_MOUNT_POINT
            buffer->ReparseDataLength = path_buffer_size;
            buffer->Reserved = 0;

            buffer->SubstituteNameOffset = 0;
            buffer->SubstituteNameLength = {0}-2;

            //buffer->PathBuffer
            dummy = dummy + 0x10;
            memcpy(dummy, target, {0});

            buffer->PrintNameOffset = {0};
            buffer->PrintNameLength = {1}-2;

            memcpy(dummy + {0}, printname, {1});

        """.format(len(wstr_target), len(wstr_printname))

        # FSCTL_SET_REPARSE_POINT = 0x900a4
        code += \
        """
            unsigned int cb;
            cb = 0;

            ret = DeviceIoControl(hFile, 0x900a4, buffer, total_buffer_size, NULL, 0, &cb, NULL);
            if (ret == 0){{
                free(buffer);
                CloseHandle(hFile);
                ret = GetLastError();

                {0}(-2);
                {0}(ret);
                return;
            }}

            free(buffer);

            {0}(1);
            {0}(ret);
            return;
        """.format(self.send_return)

        code += \
        """
        }
        """
         
        self.clearfunctioncache()                  
        request = self.compile(code, vars)
        self.sendrequest(request)

        status = self.sign_t(self.read_return())
        ret = self.read_return()
        self.leave()

        if status == 1:
            return ret

        if status == -1:
            devlog('winmosdefshellserver', 'CreateFileA failed - GetLastError %d' % ret)
        elif status == -2:
            devlog('winmosdefshellserver', 'DeviceIoControl failed - GetLastError %d' % ret)

        return None
