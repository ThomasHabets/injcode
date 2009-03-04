#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>

#include "inject.h"

#include "injcode.h"
options_t options;

const char* defaultModule = "test";
const float version = 0.10;

class ErrModule: public std::exception {
protected:
        const std::string func;
        const std::string msg;
        std::string huh;
public:
        ErrModule(const std::string &func,
                const std::string &msg)
                :func(func),msg(msg)
        {
                huh = func + ": " + msg;
        }
        virtual ~ErrModule() throw() {}
        const char *what() const throw() { return huh.c_str(); };
};

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
        } else {
                throw ErrModule("injcode",
                                std::string("Unknown module name: '")
                                + options.moduleName
                                + std::string("'\n"));
        }
        injector.run();
        //injector.dumpregs(options.verbose < 2);
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
               "\t-m <payload>  test/retty/close/dup2.  Default: %s\n"
               "\t-o<opt>=<val> Module-specific parameters\n"
               "\t-v            Increase verbosity.\n"
               "\n"
               "    Close module\n"
               "\t-ofd=<num>    File descriptor to close\n"
               "\n"
               "    Dup2 module\n"
               "\t-ofd=<num>         File descriptor to overwrite\n"
               "\t-ofilename=<file>  File to open()\n"
               "\t-oflags=<num>      open() flags\n"
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
        
        // option parsing
        for(int c = 0; c != -1;) {
                switch((c = getopt(argc, argv, "hm:o:v"))) {
                case -1:
                        break;
                case 'h':
                        usage(0);
                        break;
                case 'm':
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
        } catch(const Inject::ErrMalformed &e) {
                fprintf(stderr, "%s: %s\n", argv[0], e.whatMsg());
                usage(1);
        } catch(const Inject::ErrSysPtrace &e) {
                fprintf(stderr, "%s: Unable to connect to pid: %s\n",
                        argv[0], e.what());
        } catch(const std::exception &e) {
                fprintf(stderr, "%s: Error: %s\n", argv[0], e.what());
        } catch(...) {
                fprintf(stderr, "%s: An error occured\n", argv[0]);
                throw;
        }
}
