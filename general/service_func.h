#ifndef __SERVICE_FUNC_H__
#define __SERVICE_FUNC_H__

#include <string.h>
#include <stdlib.h>

// Argument: MAC address string, returned value: converted string to binary format
unsigned char *binary_mac_format(char *str);

#endif