#include <string>
#include <memory>
#include <vector>
#include <map>

class InjMod: public ErrHandling {
protected:
        Inject &injector;
        InjMod(const InjMod&);
        InjMod&operator=(const InjMod&);
public:
        InjMod(Inject&injector):injector(injector) {}
        virtual void run() = 0;
        virtual ~InjMod() {};
};

class TestModule: public InjMod {
public:
        TestModule(Inject&);
        void run() {};
};
class CloseModule: public InjMod {
public:
        CloseModule(Inject&);
        void run() {};
};
class Dup2Module: public InjMod {
public:
        Dup2Module(Inject&);
        void run() {};
};
class Retty: public InjMod {
        int send_fds(int sd, int proxyfd);
        void child(int proxyfd);
        std::string readFd(int fd);
        void setRawTerminal(int fd);
        void setupPty();
        static void sigwinch(int);
public:
        Retty(Inject&);
        void run();
};


typedef struct {
        int targetpid;
        int verbose;
        std::string moduleName;
        std::auto_ptr<InjMod> module;
        const char *argv0;
        std::map<std::string, std::string> parameters;
} options_t;
