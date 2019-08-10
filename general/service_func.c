#include "service_func.h"

unsigned char *binary_mac_format(char *str)
{
	static unsigned char binary[6];
	char piece[2];

	for(int i = 0, a = 0; i < 6; i++, a += 3)
	{
		strncpy(piece, str + a, 2);

		binary[i] = strtol(piece, NULL, 16);
	}

	return binary;
}