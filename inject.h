#include "ErrHandling.h"

#include <vector>

class Inject: public ErrHandling {
public:
        typedef unsigned long ptr_t;
        struct user_regs_struct {
                long ebx, ecx, edx, esi, edi, ebp, eax;
                unsigned short ds, __ds, es, __es;
                unsigned short fs, __fs, gs, __gs;
                long orig_eax, eip;
                unsigned short cs, __cs;
                long eflags, esp;
                unsigned short ss, __ss;
        };
protected:
        int pid;
        bool attached;
        int verbose;
        std::string argv0;

        bool injected;
        ptr_t codebase;
        ptr_t database;
        int pagesize;
        struct user_regs_struct oldregs;

        std::vector<char> olddatapage;
        std::vector<char> oldcodepage;

        void peekpoke(const char *data, ptr_t addr, size_t len, bool poke);
        void peek(const char *data,
                  ptr_t addr,
                  size_t len) { peekpoke(data, addr, len, false); }
        void poke(const char *data,
                  ptr_t addr,
                  size_t len) { peekpoke(data, addr, len, true); }

public:
        class ErrSysPtrace: public ErrSys {
                int req;
        public:
                ErrSysPtrace(const std::string &func, int req,
                             const std::string &msg)
                        :ErrSys(func, "ptrace", msg), req(req) { }
        };

        Inject(pid_t pid, int verbose, const char *argv0);
        ~Inject() { detach(); }

        void attach();
        void detach();
        ptr_t codeBase();
        ptr_t dataBase();
        void run();
        void dumpregs(bool onlyIfEAX=false);
        int pageSize() { attach(); return pagesize; }
        int wordSize() { return sizeof(ptr_t); }

        void inject(void *code, void *data);
        void uninject();
};
