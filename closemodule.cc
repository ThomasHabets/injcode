#include "inject.h"
#include "ErrHandling.h"
#include "injcode.h"

extern "C" char* shellcodeClose();
extern "C" char* shellcodeCloseEnd();

CloseModule::CloseModule(Inject &injector)
        :InjMod(injector)
{
        char data[injector.pageSize()];
        char code[injector.pageSize()];

        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        size_t s = (Inject::ptr_t)shellcodeCloseEnd
                - (Inject::ptr_t)shellcodeClose;
        //printf("Shellcode size is %d\n", s);
        memcpy(code, (char*)shellcodeClose, s);
        strcpy(data, "Inject OK\n");

        injector.inject(code, data);
}
