#include "elf_packer.h"


static void decrypt_section(elf64* elf, Elf64_Half idx, uint64_t key)
{
    uint64_t one_time_key;
    uint64_t sh_size = elf->sheader[idx].sh_size;
    uint8_t *sdata = elf->sdata[idx];

    one_time_key = key;
    for (uint64_t i = 0; i < sh_size; i++) {
        sdata[i] ^= (uint8_t)one_time_key;
        one_time_key = rotate_right(one_time_key);
    }
}


static uint64_t extract_key(void *ptr_loader)
{
    uint64_t key;
    memcpy(&key, ptr_loader + unpack_offset + 20 + 2, 8);
    return key;
}


static Elf64_Addr extract_orig_entry(elf64 *elf, void *ptr_loader)
{
    int target_addr;
    memcpy(&target_addr, ptr_loader + loader_size - 4, 4);
    return target_addr + elf->eheader->e_entry + loader_size;
}


static void write_on_mem(elf64 *elf, void *ptr_unpacked)
{
    size_t phtsize = elf->eheader->e_phentsize * elf->eheader->e_phnum;
    size_t shtsize  = elf->eheader->e_shnum * elf->eheader->e_shentsize;
    memcpy(ptr_unpacked, elf->eheader, elf->eheader->e_ehsize);
    memcpy(ptr_unpacked + elf->eheader->e_phoff, elf->pheader, phtsize);
    for (Elf64_Half idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (elf->sdata[idx] == NULL)
            continue;
        memcpy(ptr_unpacked + elf->sheader[idx].sh_offset, elf->sdata[idx], elf->sheader[idx].sh_size);
    }
    memcpy(ptr_unpacked + elf->eheader->e_shoff, elf->sheader, shtsize);
}


static Elf64_Half get_entry_section(elf64 *elf)
{
    Elf64_Addr e_entry = elf->eheader->e_entry;

    for (Elf64_Half idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (elf->sheader[idx].sh_addr <= e_entry && elf->sheader[idx+1].sh_addr > e_entry)
            return idx;
    }

    fprintf(stderr, "a section contains entry point not found\n");
    exit(EXIT_FAILURE);
}


int unpack_text(elf64 *elf, size_t fsize)
{
    int fd;
    char const *filename = "unpacked";
    void *ptr_unpacked;
    Elf64_Half entrysec_idx = get_entry_section(elf);
    Elf64_Half entryseg_idx = get_seg_idx_by_sec_idx(elf, entrysec_idx);
    Elf64_Half textsec_idx = get_section_by_name(elf, ".text");
    Elf64_Half textseg_idx = get_seg_idx_by_sec_idx(elf, textsec_idx);
    void *ptr_loader;
    Elf64_Addr orig_e_entry;
    uint64_t key;

    elf->pheader[entryseg_idx].p_filesz -= loader_size;
    elf->pheader[entryseg_idx].p_memsz -= loader_size;
    elf->sheader[entrysec_idx].sh_size -= loader_size;
    elf->pheader[textseg_idx].p_flags &= ~PF_W;

    if ((ptr_loader = calloc((size_t)1, loader_size)) == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    memcpy(ptr_loader, elf->sdata[entrysec_idx] + elf->sheader[entrysec_idx].sh_size, loader_size);

    orig_e_entry = extract_orig_entry(elf, ptr_loader);
    elf->eheader->e_entry = orig_e_entry;

    key = extract_key(ptr_loader);
    decrypt_section(elf, textsec_idx, key);

    free(ptr_loader);

    if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IXUSR)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if ((ptr_unpacked = calloc((size_t)1, fsize)) == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    write_on_mem(elf, ptr_unpacked);

    write(fd, ptr_unpacked, fsize);

    return 0;
}
