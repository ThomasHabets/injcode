// -*- c++ -*-
#ifndef __INCLUDE_ERRHANDLING_H__
#define __INCLUDE_ERRHANDLING_H__

#include <string>
#include <cerrno>
#include <cstring>

class ErrHandling {
public:
        class ErrBase: public std::exception {
        protected:
                const std::string func;
                const std::string msg;
                std::string huh;
        public:
                ErrBase(const std::string &func,
                        const std::string &msg)
                        :func(func),msg(msg)
                {
                        huh = func + ": " + msg;
                }
                virtual ~ErrBase() throw() {}
                const char *what() const throw() { return huh.c_str(); };
        };
        class ErrMalformed: public ErrBase {
        public:
                ErrMalformed(const std::string &func,
                             const std::string &msg)
                        :ErrBase(func, msg) { }
        };
        class ErrSys: public ErrBase {
        protected:
                const std::string sys;
                int err;
        public:
                ErrSys(const std::string &func,
                       const std::string &sys,
                       const std::string &msg = "")
                        :ErrBase(func, msg),sys(sys)
                {
                        err = errno;
                        huh = func + ": "
                                + sys + "(): "
                                + strerror(errno) + ": "
                                + msg;
                }
                virtual ~ErrSys() throw() {}
        };

};
#endif
