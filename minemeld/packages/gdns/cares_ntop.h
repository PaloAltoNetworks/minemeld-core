#include <arpa/inet.h>
#define ares_inet_ntop(w,x,y,z) inet_ntop(w,x,y,z)
