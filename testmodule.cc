// injcode/testmodule.cc
#include "inject.h"
#include "ErrHandling.h"
#include "injcode.h"

extern "C" char* shellcodeTest();
extern "C" char* shellcodeTestEnd();

/**
 *
 */
TestModule::TestModule(Inject &injector)
        :InjMod(injector)
{
        char data[injector.pageSize()];
        char code[injector.pageSize()];

        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        size_t s = (Inject::ptr_t)shellcodeTestEnd
                - (Inject::ptr_t)shellcodeTest;
        //printf("Shellcode size is %d\n", s);
        memcpy(code, (char*)shellcodeTest, s);
        strcpy(data, "Inject OK\n");

        injector.inject(code, data);
}
