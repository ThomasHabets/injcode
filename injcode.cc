#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>

#include "inject.h"

#include "injcode.h"
options_t options;

const char* defaultModule = "test";
const float version = 0.10;

static void
injcode()
{
        Inject injector(options.targetpid, options.verbose, options.argv0);
        if (options.moduleName == "retty") {
                options.module.reset(new Retty(injector));
        } else if (options.moduleName == "test") {
                options.module.reset(new TestModule(injector));
        } else if (options.moduleName == "close") {
                options.module.reset(new CloseModule(injector));
        } else if (options.moduleName == "dup2") {
                options.module.reset(new Dup2Module(injector));
        }
        injector.run();
        injector.dumpregs(options.verbose < 2);
        injector.detach();
        options.module->run();
}

/**
 *
 */
static
void usage(int err)
{
        printf("Injcode %.2f, by Thomas Habets <thomas@habets.pp.se>\n"
               "Usage: %s [ -hv ] [ -m <payload> ]\n"
               "\t-h            Show this help text\n"
               "\t-m <payload>  test/retty/close.  Default: %s\n"
               "\t-o<opt>=<val> Module-specific parameters\n"
               "\t-v            Increase verbosity.\n"
               "\n"
               "    Close module\n"
               "\t-ofd=<num>    File descriptor to close\n"
               ,version, options.argv0, defaultModule);
        exit(err);
}

int
main(int argc, char **argv)
{
        // default options
        options.verbose = 0;
        options.argv0 = argv[0];
        options.moduleName = defaultModule;
        
        // save for later. Will use this to reset right before exiting
        struct termios orig_tio;
        if (0 > tcgetattr(0, &orig_tio)) {
                perror("tcgetattr(0, ...)");
                return 1;
        }

        // option parsing
        for(int c = 0; c != -1;) {
                switch((c = getopt(argc, argv, "hm:o:v"))) {
                case -1:
                        break;
                case 'h':
                        usage(0);
                        break;
                case 'm':
                        if (optarg == "test"
                            || optarg == "retty") {
                                fprintf(stderr,
                                        "%s: Unknown module name: '%s'\n",
                                        optarg);
                                usage(1);
                        }
                                
                        options.moduleName = optarg;
                        break;
                case 'o': {
                        char *t = strchr(optarg, '=');
                        if (!t) {
                                usage(1);
                        }
                        options.parameters[std::string(optarg,t)]
                                = std::string(t+1);
                }
                        break;
                case 'v':
                        options.verbose++;
                        break;
                default:
                        usage(1);
                        break;
                }
        }

        if (argc != optind + 1) {
                usage(1);
        }
        options.targetpid = atoi(argv[optind]);

        try {
                injcode();
        } catch(const std::exception &e) {
                fprintf(stderr, "%s: Error: %s\n", argv[0], e.what());
        } catch(...) {
                fprintf(stderr, "%s: An error occured\n", argv[0]);
                throw;
        }

        if (0 > tcsetattr(0, TCSANOW, &orig_tio)) {
                perror("tcsetattr(0, ...)");
                return 1;
        }
}
