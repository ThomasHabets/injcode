// injcode/closemodule.cc
#include <stdlib.h>

#include "inject.h"
#include "ErrHandling.h"
#include "injcode.h"

extern options_t options;

extern "C" char* shellcodeClose();
extern "C" char* shellcodeCloseEnd();

/**
 *
 * Shellcode data:
 *    Size               Value
 *    sizeof(int)        fd to close
 *
 */
CloseModule::CloseModule(Inject &injector)
        :InjMod(injector)
{
        char data[injector.pageSize()];
        char code[injector.pageSize()];

        // sanity check input
        if (!options.parameters.count("fd")) {
                throw ErrMalformed("CloseModule::CloseModule()",
                                   "Close module requires option -ofd=<num>");
        }

        // init
        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        // data setup
        *((int*)data) = strtoul(options.parameters["fd"].c_str(), NULL, 0);

        // code setup
        size_t s = (Inject::ptr_t)shellcodeCloseEnd
                - (Inject::ptr_t)shellcodeClose;
        memcpy(code, (char*)shellcodeClose, s);

        // execute
        injector.inject(code, data);
}
