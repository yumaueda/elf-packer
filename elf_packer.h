#ifndef __elf_packer_h__
#define __elf_packer_h__


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


#define PAYLOAD_SIZE 512
#define PAGE_SIZE 4096


typedef struct _elf64 {
    Elf64_Ehdr *eheader;
    Elf64_Phdr *pheader;
    uint8_t    **sdata;
    Elf64_Shdr *sheader;
} elf64;


void *map_elf(void *pa);


int pack_text(elf64 *elf);


#endif