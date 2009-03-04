// injcode/dup2module.cc
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <vector>

#include "inject.h"
#include "ErrHandling.h"
#include "injcode.h"

extern options_t options;

extern "C" char* shellcodeDup2();
extern "C" char* shellcodeDup2End();

std::vector<std::string>
strSplit(const std::string str, std::string delim)
{
        std::vector<std::string> ret;
        std::string s(str);
        size_t n;
        while ((n = s.find_first_of(delim)) != s.npos) {
                if (n > 0) {
                        ret.push_back(s.substr(0, n));
                }
                s = s.substr(n + 1);
        }
        if (s.length() > 0) {
                ret.push_back(s);
        }
        return ret;
}
/**
 *
 * Shellcode data:
 *    Size               Value                        Example cmdline
 *    sizeof(int)        fd to dup2 to                -ofd=1
 *    sizeof(int)        open() flags                 -oflags=O_WRONLY,O_CREAT
 *    sizeof(mode_t)     open() file mode             -oflags=0644 (default)
 *    variable           file to open, asciiz         -ofilename=newstdout
 *
 */
Dup2Module::Dup2Module(Inject &injector)
        :InjMod(injector)
{
        char data[injector.pageSize()];
        char code[injector.pageSize()];

        // sanity check input
        if (!options.parameters.count("fd")
            || !options.parameters.count("flags")
            || !options.parameters.count("filename")) {
                throw ErrMalformed("Dup2Module::Dup2Module()",
                                   "dup2 requires options fd, "
                                   "flags & filename");

        }

        // init
        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        // data setup
        int *fd, *flags;
        fd = &((int*)data)[0];
        flags = &((int*)data)[1];
        *fd = strtoul(options.parameters["fd"].c_str(), NULL, NULL);

        std::vector<std::string> fl = strSplit(options.parameters["flags"],",");
        *flags = 0;
        for (std::vector<std::string>::const_iterator itr = fl.begin();
             itr != fl.end();
             ++itr) {
                if (*itr == "O_RDONLY")         { *flags |= O_RDONLY;      }
                else if (*itr == "O_WRONLY")    { *flags |= O_WRONLY;      }
                else if (*itr == "O_RDWR")      { *flags |= O_RDWR;        }
                else if (*itr == "O_CREAT")     { *flags |= O_CREAT;       }
                else if (*itr == "O_APPEND")    { *flags |= O_APPEND;      }
                else if (*itr == "O_DIRECTORY") { *flags |= O_DIRECTORY;   }
                else if (*itr == "O_EXCL")      { *flags |= O_EXCL;        }
                else if (*itr == "O_NONBLOCK")  { *flags |= O_NONBLOCK;    }
                else if (*itr == "O_TRUNC")     { *flags |= O_TRUNC;       }
                else {
                        throw ErrMalformed("Dup2Module::Dup2Module()",
                                           "Invalid flag " + *itr);
                }
        }
        mode_t *mode = (mode_t*)&((int*)data)[2];
        *mode = 0644; // default mode
        if (options.parameters.count("mode")) {
                *mode = strtoul(options.parameters["mode"].c_str(),
                                NULL, NULL);
        }
        memcpy(data + sizeof(int) + sizeof(int) + sizeof(mode_t),
               options.parameters["filename"].data(),
               options.parameters["filename"].length());

        // code setup
        size_t s = (Inject::ptr_t)shellcodeDup2End
                - (Inject::ptr_t)shellcodeDup2;
        memcpy(code, (char*)shellcodeDup2, s);

        // execute
        injector.inject(code, data);
}
