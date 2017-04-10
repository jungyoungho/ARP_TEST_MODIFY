#include "mac.h"
#include <cstdio>
#include <string>
#include <cstring>

Mac& Mac::operator =(const char *str){
    sscanf((const char*)str, "%x:%x:%x:%x:%x:%x",&val[0],&val[1],&val[2],&val[3],&val[4],&val[5]);

    return *this;
}
