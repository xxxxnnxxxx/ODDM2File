#ifndef _PE_H_
#define _PE_H_


#ifdef __cplusplus
extern "C" {
#endif

int is_pefile(char *pebase);
char * generate_pe(char *pebase,size_t *len);

#ifdef __cplusplus
}
#endif


#endif