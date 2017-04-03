#ifndef MAC_H
#define MAC_H
#include <cstdint>
#include <string>

class Mac
{
public:
    Mac& operator=(const char *str);
    uint8_t val[6];
};

#endif // MAC_H
