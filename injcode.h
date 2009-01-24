#include <string>
#include <memory>


class InjMod {
        Inject &injector;
        InjMod(const InjMod&);
        InjMod&operator=(const InjMod&);
public:
        InjMod(Inject&injector): injector(injector) {}
        virtual void run() = 0;
        virtual ~InjMod() {};
};

class Retty: public InjMod {
        int send_fds(int sd, int proxyfd);
        void child(int proxyfd);
        std::string readFd(int fd);
        void setRawTerminal(int fd);
        void setupPty();
public:
        Retty(Inject&);
        void run();
};

typedef struct {
        int targetpid;
        int verbose;
        std::string shellcodeName;
        std::auto_ptr<InjMod> module;
        //InjMod *module;
} options_t;
