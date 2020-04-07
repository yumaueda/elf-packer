#include "elf_packer.h"


Elf64_Half get_seg_idx_by_sec_idx(elf64 *elf, Elf64_Half sec_idx)
{
    Elf64_Off sh_offset = elf->sheader[sec_idx].sh_offset;
    Elf64_Xword sh_size = elf->sheader[sec_idx].sh_size;
    Elf64_Half seg_idx;

    for (seg_idx = 0; seg_idx < elf->eheader->e_phnum; seg_idx++) {
        if (elf->pheader[seg_idx].p_type != PT_LOAD)
            continue;
        if (elf->pheader[seg_idx].p_offset <= sh_offset && elf->pheader[seg_idx].p_filesz >= sh_size)
            return seg_idx;
    }

    fprintf(stderr, "a segment conitans the section %u not found\n", sec_idx);
    exit(EXIT_FAILURE);
}


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
