#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

#include "inject.h"

#include "injcode.h"
options_t options;

void rettySetup(Inject &injector);
void rettyRun();

void testSetup(Inject &injector);
void testRun();

void
pt2()
{
        Inject injector(options.targetpid);
        options.module.reset(new Retty(injector));
        injector.run();
        injector.dumpregs(options.verbose < 2);
        injector.detach();
        options.module->run();
}

int
main(int argc, char **argv)
{
        struct termios orig_tio;
        // option parsing
        options.targetpid = atoi(argv[1]);
        options.verbose = 0;
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
