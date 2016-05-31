#include <arpa/inet.h>
#define ares_inet_pton(x,y,z) inet_pton(x,y,z)
#define ares_inet_net_pton(w,x,y,z) inet_net_pton(w,x,y,z)
