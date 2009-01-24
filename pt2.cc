#include <termios.h>
#include <unistd.h>

#include "inject.h"

#include "pt2.h"
options_t options;
void rettySetupShellcode(Inject &injector);
void rettyRun();

extern "C" char* shellcodeTest();
extern "C" char* shellcodeTestEnd();

void
setupShellcodeTest(Inject &injector)
{
        char data[injector.pageSize()];
        char code[injector.pageSize()];

        memset(code, 0x90, injector.pageSize());
        memset(data, 0, injector.pageSize());
        code[injector.pageSize()-1] = 0xcc;

        size_t s = (Inject::ptr_t)shellcodeTestEnd
                - (Inject::ptr_t)shellcodeTest;
        printf("Shellcode size is %d\n", s);
        memcpy(code, (char*)shellcodeTest, s);
        strcpy(data, "Inject OK\n");

        injector.inject(code, data);
}

void
pt2()
{
        Inject injector(options.targetpid);
        rettySetup(injector);
        injector.run();
        injector.dumpregs();
        injector.detach();
        rettyRun();
}

int
main(int argc, char **argv)
{
        struct termios orig_tio;
        // option parsing
        options.targetpid = atoi(argv[1]);
        options.verbose = 1;
        options.shellcodeName = "test";
        
        // 
        if (0 > tcgetattr(0, &orig_tio)) {
                perror("tcgetattr(0, ...)");
                return 1;
        }

        if (options.verbose) {
                printf("Attaching to pid %d\n", options.targetpid);
        }

        try {
                pt2();
        } catch(const std::exception &e) {
                fprintf(stderr, "Error: %s\n", e.what());
        } catch(...) {
                fprintf(stderr, "An error occured\n");
                throw;
        }

        if (0 > tcsetattr(0, TCSANOW, &orig_tio)) {
                perror("tcsetattr(0, ...)");
                return 1;
        }
}
