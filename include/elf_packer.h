#ifndef __elf_packer_h__
#define __elf_packer_h__ 1


#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define MODE_PACK 1
#define MODE_UNPACK 2

#define PAGESIZE 4096


extern void loader_entry(void);
extern uint64_t loader_size;
extern uint64_t unpack_offset;


typedef struct _elf64 {
    Elf64_Ehdr *eheader;
    Elf64_Phdr *pheader;
    uint8_t    **sdata;
    Elf64_Shdr *sheader;
} elf64;


inline uint64_t rotate_right(uint64_t key)
{
    return (key << 63 | key >> 1);
}

// map_elf.c
void *map_elf(void *pa);


// elf_packer_lib.c
uint16_t get_section_by_name(elf64 *elf, char *section_name);


// pack_elf.c
int pack_text(elf64 *elf, size_t fsize);


#endif
