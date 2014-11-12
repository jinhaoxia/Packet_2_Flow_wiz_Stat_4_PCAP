#ifndef U_CHAR_HANDLE
#define U_CHAR_HANDLE

void u_char_cpy(u_char * dest, const u_char * src, size_t len)
{
	for (unsigned int i = 0; i < len; ++i)
		dest[i] = src[i];
}

bool u_char_equ(const u_char * dest, const u_char * src, size_t len){
	bool isEqual = true;
	for (unsigned int i = 0; i < len; ++i)
		if(dest[i] != src[i]){
			isEqual = false;
			break;
		}
	return isEqual;
}

#endif