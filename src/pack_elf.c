#include "elf_packer.h"


extern uint64_t rotate_right(uint64_t key);


static void append_payload(
        elf64 *elf,
        void *ptr_packed,
        Elf64_Half idx,
        Elf64_Addr old_e_entry,
        uint64_t key,
        Elf64_Half textsec_idx)
{
    void *loader_addr = ptr_packed + elf->sheader[idx].sh_offset + elf->sheader[idx].sh_size - loader_size;
    uint64_t r12_sub_text = elf->sheader[idx].sh_addr + elf->sheader[idx].sh_size - loader_size - elf->sheader[textsec_idx].sh_addr;
    Elf64_Xword text_sh_size = elf->sheader[textsec_idx].sh_size;
    int target_addr = old_e_entry - elf->eheader->e_entry - loader_size;
    memcpy(loader_addr, (void *)loader_entry, loader_size);
    /* overrwrite the immediate value of instructions */
    memcpy(loader_addr + unpack_offset +  0 + 2, &r12_sub_text, 8);
    memcpy(loader_addr + unpack_offset + 10 + 2, &text_sh_size, 8);
    memcpy(loader_addr + unpack_offset + 20 + 2, &key, 8);
    memcpy(loader_addr + loader_size - 4, &target_addr, 4);
}


static void write_on_mem(elf64 *elf, void *ptr_packed, Elf64_Half lastsh_idx)
{
    size_t phtsize = elf->eheader->e_phentsize * elf->eheader->e_phnum;
    size_t shtsize  = elf->eheader->e_shnum * elf->eheader->e_shentsize;
    memcpy(ptr_packed, elf->eheader, elf->eheader->e_ehsize);
    memcpy(ptr_packed + elf->eheader->e_phoff, elf->pheader, phtsize);
    for (Elf64_Half idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (elf->sdata[idx] == NULL)
            continue;
        if (idx != lastsh_idx)
            memcpy(ptr_packed + elf->sheader[idx].sh_offset, elf->sdata[idx], elf->sheader[idx].sh_size);
        else
            memcpy(ptr_packed + elf->sheader[idx].sh_offset, elf->sdata[idx], elf->sheader[idx].sh_size - loader_size);
    }
    memcpy(ptr_packed + elf->eheader->e_shoff, elf->sheader, shtsize);
}


static uint64_t encrypt_section(elf64 *elf, Elf64_Half idx)
{
    uint64_t key, one_time_key;
    ssize_t nbytes_copied;
    Elf64_Xword sh_size = elf->sheader[idx].sh_size;
    Elf64_Xword i;
    uint8_t *sdata = elf->sdata[idx];

    if ((nbytes_copied = getrandom(&key, sizeof(uint64_t), 0)) == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }
    if (nbytes_copied != (ssize_t)sizeof(uint64_t)) {
        fprintf(stderr, "the getrandom syscall was interupted by a signal\n");
        exit(EXIT_FAILURE);
    }

    one_time_key = key;
    for (i = 0; i < sh_size; i++) {
        sdata[i] ^= (uint8_t)one_time_key;
        one_time_key = rotate_right(one_time_key);
    }

    return key;
}


static Elf64_Half get_lastsh_idx(elf64 *elf, Elf64_Half targetseg_idx)
{
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Half idx;

    for (idx = 0; idx < elf->eheader->e_shnum; idx++) {
        sh_offset = elf->sheader[idx].sh_offset;
        sh_size = elf->sheader[idx].sh_size;
        if (sh_offset + sh_size == elf->pheader[targetseg_idx].p_offset + elf->pheader[targetseg_idx].p_filesz)
            return idx;
    }

    fprintf(stderr, "a last section in the target segment not found\n");
    exit(EXIT_FAILURE);
}


static Elf64_Half find_gap(elf64 *elf)
{
    Elf64_Addr p_vaddr;
    Elf64_Xword p_memsz;
    Elf64_Half idx;

    for (idx = 0; idx < elf->eheader->e_phnum; idx++) {
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
    Elf64_Half targetseg_idx = find_gap(elf);
    Elf64_Half lastsh_idx = get_lastsh_idx(elf, targetseg_idx);
    Elf64_Addr old_e_entry = elf->eheader->e_entry;
    Elf64_Half textsec_idx = get_section_by_name(elf, ".text");
    Elf64_Half textseg_idx = get_seg_idx_by_sec_idx(elf, textsec_idx);
    uint64_t key = encrypt_section(elf, textsec_idx);
    int fd;
    char const *filename = "packed";
    void *ptr_packed;

    elf->eheader->e_entry = elf->sheader[lastsh_idx].sh_offset + elf->sheader[lastsh_idx].sh_size;
    elf->pheader[targetseg_idx].p_filesz += loader_size;
    elf->pheader[targetseg_idx].p_memsz += loader_size;
    elf->sheader[lastsh_idx].sh_size += loader_size;
    elf->pheader[textseg_idx].p_flags |= PF_W;

    if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IXUSR)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if ((ptr_packed = calloc((size_t)1, fsize)) == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    write_on_mem(elf, ptr_packed, lastsh_idx);
    append_payload(elf, ptr_packed, lastsh_idx, old_e_entry, key, textsec_idx);

    write(fd, ptr_packed, fsize);

    return 0;
}
