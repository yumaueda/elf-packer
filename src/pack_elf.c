#include "elf_packer.h"


extern void loader_entry(void);
extern uint64_t loader_size;
extern uint64_t unpack_offset;


static void append_payload(elf64 *elf, void *ptr_packed, uint16_t idx, uint64_t old_e_entry, uint64_t key, uint16_t textsec_idx)
{
    void *loader_addr = ptr_packed + elf->sheader[idx].sh_offset + elf->sheader[idx].sh_size - loader_size;
    uint64_t r12_sub_text = elf->sheader[idx].sh_addr + elf->sheader[idx].sh_size - loader_size - elf->sheader[textsec_idx].sh_addr;
    uint64_t text_sh_size = elf->sheader[textsec_idx].sh_size;
    ssize_t target_addr = old_e_entry - elf->eheader->e_entry - loader_size;

    memcpy(loader_addr, (void *)loader_entry, loader_size);

    /* overrwrite immediate value of mov instructions */
    memcpy(loader_addr + unpack_offset +  0 + 2, &r12_sub_text, 8);
    memcpy(loader_addr + unpack_offset + 10 + 2, &text_sh_size, 8);
    memcpy(loader_addr + unpack_offset + 20 + 2, &key, 8);
    /* overwrite */
    memcpy(loader_addr + loader_size - 4, &target_addr, 4);
}


static void write_on_mem(elf64 *elf, void *ptr_packed, uint64_t key, uint16_t lastsh_idx, uint64_t old_e_entry, uint16_t textsec_idx)
{
    size_t phtsize = elf->eheader->e_phentsize * elf->eheader->e_phnum;
    size_t shtsize  = elf->eheader->e_shnum * elf->eheader->e_shentsize;
    memcpy(ptr_packed, elf->eheader, elf->eheader->e_ehsize);
    memcpy(ptr_packed + elf->eheader->e_phoff, elf->pheader, phtsize);
    for (uint16_t idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (elf->sdata[idx] == NULL)
            continue;
        if (idx != lastsh_idx) {
            memcpy(ptr_packed + elf->sheader[idx].sh_offset, elf->sdata[idx], elf->sheader[idx].sh_size);
        }
        else {
            memcpy(ptr_packed + elf->sheader[idx].sh_offset, elf->sdata[idx], elf->sheader[idx].sh_size - loader_size);
            append_payload(elf, ptr_packed, idx, old_e_entry, key, textsec_idx);
        }
    }
    memcpy(ptr_packed + elf->eheader->e_shoff, elf->sheader, shtsize);
}


static uint16_t get_seg_idx_by_sec_idx(elf64 *elf, uint16_t sec_idx)
{
    uint64_t sh_offset = elf->sheader[sec_idx].sh_offset;
    uint64_t sh_size = elf->sheader[sec_idx].sh_size;
    for (uint16_t seg_idx = 0; seg_idx < elf->eheader->e_phnum; seg_idx++) {
        if (elf->pheader[seg_idx].p_type != PT_LOAD)
            continue;

        if (elf->pheader[seg_idx].p_offset <= sh_offset && elf->pheader[seg_idx].p_filesz >= sh_size)
            return seg_idx;
    }

    fprintf(stderr, "the segment conitans the section %u not found\n", sec_idx);
    exit(EXIT_FAILURE);
}


static inline uint64_t rotate_right(uint64_t key)
{
    return ((key << 63) | (key >> 1));
}


static uint64_t encrypt_section(elf64 *elf, uint16_t idx)
{
    uint64_t key, one_time_key;
    ssize_t nbytes_copied;
    if ((nbytes_copied = getrandom(&key, sizeof(uint64_t), 0)) == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }
    if (nbytes_copied != (ssize_t)sizeof(uint64_t)) {
        fprintf(stderr, "the getrandom syscall was interupted by a signal\n");
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


static inline char *get_section_name(elf64 *elf, uint16_t idx)
{
    uint16_t shstrndx = elf->eheader->e_shstrndx;
    return ((char *)elf->sdata[shstrndx] + elf->sheader[idx].sh_name);
}


static uint16_t get_section_by_name(elf64 *elf, char *section_name)
{
    for (uint16_t idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (strcmp(section_name, get_section_name(elf, idx)) == 0)
            return idx;
    }

    fprintf(stderr, "the %s section not found\n", section_name);
    exit(EXIT_FAILURE);
}


static uint16_t get_lastsh_idx(elf64 *elf, uint16_t targetseg_idx)
{
    uint64_t sh_offset;
    uint64_t sh_size;
    for (uint16_t idx; idx < elf->eheader->e_shnum; idx++) {

        sh_offset = elf->sheader[idx].sh_offset;
        sh_size = elf->sheader[idx].sh_size;
        if (sh_offset + sh_size == elf->pheader[targetseg_idx].p_offset + elf->pheader[targetseg_idx].p_filesz)
            return idx;
    }

    fprintf(stderr, "the last section in the target segment not found\n");
    exit(EXIT_FAILURE);
}


static uint16_t find_gap(elf64 *elf)
{
    uint64_t  p_vaddr;
    uint64_t  p_memsz;
    for (uint16_t idx = 0; idx < elf->eheader->e_phnum; idx++) {
        if (elf->pheader[idx].p_type != PT_LOAD)
            continue;

        p_vaddr = elf->pheader[idx].p_vaddr;
        p_memsz = elf->pheader[idx].p_memsz;
        if (elf->pheader[idx+1].p_vaddr - p_vaddr + p_memsz >= loader_size)
            return idx;
    }

    fprintf(stderr, "a sufficient gap not found\n");
    exit(EXIT_FAILURE);
}


int pack_text(elf64 *elf, size_t fsize)
{
    uint16_t targetseg_idx = find_gap(elf);
    uint16_t lastsh_idx = get_lastsh_idx(elf, targetseg_idx);


    uint64_t old_e_entry = elf->eheader->e_entry;
    elf->eheader->e_entry = elf->sheader[lastsh_idx].sh_offset + elf->sheader[lastsh_idx].sh_size;
    elf->pheader[targetseg_idx].p_filesz += loader_size;
    elf->pheader[targetseg_idx].p_memsz += loader_size;
    elf->sheader[lastsh_idx].sh_size += loader_size;

    uint16_t textsec_idx = get_section_by_name(elf, ".text");
    uint64_t key = encrypt_section(elf, textsec_idx);

    uint64_t textseg_idx = get_seg_idx_by_sec_idx(elf, textsec_idx);
    elf->pheader[textseg_idx].p_flags |= PF_W;

    int fd;
    char const *filename = "packed";
    void *ptr_packed;
    if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IXUSR)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if ((ptr_packed = calloc((size_t)1, fsize)) == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    write_on_mem(elf, ptr_packed, key, lastsh_idx, old_e_entry, textsec_idx);
    write(fd, ptr_packed, fsize);

    return EXIT_SUCCESS;
}