#include "elf_packer.h"


static inline char *get_section_name(elf64 *elf, uint16_t idx)
{
    Elf64_Half shstrndx = elf->eheader->e_shstrndx;
    return ((char *)elf->sdata[shstrndx] + elf->sheader[idx].sh_name);
}


Elf64_Half get_section_by_name(elf64 *elf, char *section_name)
{
    Elf64_Half idx;

    for (idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (strcmp(section_name, get_section_name(elf, idx)) == 0)
            return idx;
    }

    fprintf(stderr, "the %s section not found\n", section_name);
    exit(EXIT_FAILURE);
}
