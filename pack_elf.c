#include "elf_packer.h"


static inline bool contain_entrypoint_segment(elf64 *elf, uint16_t idx)
{
    if (elf->eheader->e_entry < elf->pheader[idx].p_vaddr)
        return false;
    if (elf->eheader->e_entry >= elf->pheader[idx].p_vaddr+elf->pheader[idx].p_memsz)
        return false;

    return true;
}


static void modify_segments(elf64 *elf)
{
    bool corrupt = false;
    bool entry_exists = false;
    for (uint16_t idx = 0; idx < elf->eheader->e_phnum; idx++) {
        if (corrupt == true)
            elf->pheader[idx].p_offset += PAGE_SIZE;
        
        if ((entry_exists = contain_entrypoint_segment(elf, idx)) == true) {
            corrupt = true;

            elf->pheader[idx].p_filesz += PAYLOAD_SIZE;
            elf->pheader[idx].p_memsz += PAYLOAD_SIZE;
            elf->pheader[idx].p_flags |= PF_W;
        }
    }

    if (entry_exists == false) {
        perror("a segment contains entrypoint not found\n");
        exit(EXIT_FAILURE);
    }
}


static inline uint64_t rotate_right(uint64_t key)
{
    return ((key << 63) | (key >> 1));
}


static uint8_t encrypt_section(elf64 *elf, uint16_t idx)
{
    uint64_t key, one_time_key;
    ssize_t nbytes_copied; 
    if ((nbytes_copied = getrandom(&key, sizeof(uint64_t), 0)) == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }
    if (nbytes_copied != (ssize_t)sizeof(uint64_t)) {
        fprintf(stderr, "the getrandom syscall was interupted by a signal");
        exit(EXIT_FAILURE);
    }

    uint64_t sh_size = elf->sheader[idx].sh_size;
    uint8_t *sdata = elf->sdata[idx];

    one_time_key = key;
    for (uint64_t i = 0; i < sh_size; i++) {
        sdata[i] ^= (uint8_t)one_time_key;
        one_time_key = rotate_right(one_time_key);
    }

    return key;
}


static char *get_section_name(elf64 *elf, uint16_t idx)
{
    uint16_t elf_shstrndx = elf->eheader->e_shstrndx;
    return ((char *)elf->sdata[elf_shstrndx] + elf->sheader[idx].sh_name);
}


static uint16_t get_text_idx(elf64 *elf)
{
    uint16_t idx;
    for (idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (strcmp(".text", get_section_name(elf, idx)) == 0)
            return idx;
    }

    perror("cannot find the section '.text'\n");
    exit(EXIT_FAILURE);
}


int pack_text(elf64 *elf)
{
    uint16_t idx = get_text_idx(elf);
    uint8_t key = encrypt_section(elf, idx);
    modify_segments(elf);

    return EXIT_SUCCESS;
}