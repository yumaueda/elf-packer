#include "elf_packer.h"


extern void loader_entry(void);
extern uint64_t loader_size;
extern uint64_t mprotect_offset;
extern uint64_t unpack_offset;


static uint16_t ep_sh_idx;
static uint16_t last_ptload_sh_idx;

static uint64_t ep_sh_addr;
static uint64_t ep_sh_offset;
static uint64_t ep_sh_size;

static uint64_t ep_segment_vaddr;
static uint64_t ep_segment_offset;
static uint64_t ep_segment_filesz;

static uint64_t old_e_entry;


static void append_payload(elf64 *elf,void *ptr_packed, uint16_t idx, uint64_t key)
{
    uint64_t sh_offset = elf->sheader[idx].sh_offset;
    uint64_t sh_size = elf->sheader[idx].sh_size;
    void *loader_addr = ptr_packed + sh_offset + sh_size - loader_size;

    ssize_t target_addr = old_e_entry - elf->eheader->e_entry - loader_size;

    memcpy(loader_addr, (void *)loader_entry, loader_size);

    /* overrwrite immediate value of mov instructions */
    memcpy(loader_addr + mprotect_offset +  0 + 2, &old_e_entry, 8);
    memcpy(loader_addr + mprotect_offset + 10 + 2, &ep_sh_size, 8);
    memcpy(loader_addr + unpack_offset +  0 + 2, &old_e_entry, 8);
    memcpy(loader_addr + unpack_offset + 10 + 2, &ep_sh_size, 8);
    memcpy(loader_addr + unpack_offset + 20 + 2, &key, 8);
    /* overwrite */
    memcpy(loader_addr + loader_size - 4, &target_addr, 4);
}


static void write_on_mem(elf64 *elf, void *ptr_packed, uint64_t key)
{
    size_t ehsize = elf->eheader->e_ehsize;
    size_t phtsize = elf->eheader->e_phentsize * elf->eheader->e_phnum;
    uint16_t shnum = elf->eheader->e_shnum;
    size_t shtsize  = shnum * elf->eheader->e_shentsize;

    memcpy(ptr_packed, elf->eheader, ehsize);

    memcpy(ptr_packed + elf->eheader->e_phoff, elf->pheader, phtsize);

    size_t sdata_size;
    for (uint16_t idx = 0; idx < shnum; idx++) {
        sdata_size = elf->sheader[idx].sh_size;
        memcpy(ptr_packed + elf->sheader[idx].sh_offset, elf->sdata[idx], sdata_size);

        if (idx == last_ptload_sh_idx)
            append_payload(elf, ptr_packed, idx, key);
    }

    memcpy(ptr_packed + elf->eheader->e_shoff, elf->sheader, shtsize);
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

    char *new_sh_name = "crypt";
    memcpy(elf->sdata[elf->eheader->e_shstrndx] + elf->sheader[idx].sh_name, (uint8_t *)new_sh_name, 5);

    return key;
}


static void modify_header(elf64 *elf)
{
    old_e_entry = elf->eheader->e_entry;
    elf->eheader->e_entry = ep_segment_vaddr + ep_segment_filesz;
    elf->eheader->e_shoff += PAGESIZE;
}


static inline bool is_last_section_in_ptload(elf64* elf, uint16_t idx)
{
    uint64_t sh_offset = elf->sheader[idx].sh_offset;
    uint64_t sh_size = elf->sheader[idx].sh_size;
    return sh_offset + sh_size == ep_segment_offset + ep_segment_filesz;
}


static char *get_section_name(elf64 *elf, uint16_t idx)
{
    uint16_t shstrndx = elf->eheader->e_shstrndx;
    return ((char *)elf->sdata[shstrndx] + elf->sheader[idx].sh_name);
}


static inline bool contain_entrypoint_section(elf64 *elf, uint16_t idx)
{
    if (strcmp(".debug_info", get_section_name(elf, idx)) == 0)
        return false;

    uint64_t e_entry = elf->eheader->e_entry;
    uint64_t sh_addr = elf->sheader[idx].sh_addr;
    uint64_t sh_size = elf->sheader[idx].sh_size;
    return e_entry >= sh_addr && e_entry < sh_addr+sh_size;
}


static void modify_sections(elf64 *elf)
{
    bool corrupt = false;
    bool contain_ep_sh = false;

    for (uint16_t idx = 0; idx < elf->eheader->e_shnum; idx++) {
        if (corrupt == true)
            elf->sheader[idx].sh_offset += PAGESIZE;

        if (contain_entrypoint_section(elf, idx) == true) {
            contain_ep_sh = true;

            ep_sh_idx = idx;

            ep_sh_addr = elf->sheader[idx].sh_offset;
            ep_sh_offset = elf->sheader[idx].sh_offset;
            ep_sh_size = elf->sheader[idx].sh_size;

            elf->sheader[idx].sh_flags |= SHF_WRITE;
        }

        if (is_last_section_in_ptload(elf, idx) == true)
        {
            corrupt = true;

            last_ptload_sh_idx = idx;

            elf->sheader[idx].sh_size += loader_size;
        }
    }

    if (contain_ep_sh == false) {
        fprintf(stderr, "a section contains entrypoint not found\n");
        exit(EXIT_FAILURE);
    }

    if (corrupt == false) {
        fprintf(stderr, "a last ptload section not found\n");
        exit(EXIT_FAILURE);
    }
}


static inline bool contain_entrypoint_segment(elf64 *elf, uint16_t idx)
{
    if (elf->eheader->e_entry < elf->pheader[idx].p_vaddr)
        return false;
    if (elf->eheader->e_entry >= elf->pheader[idx].p_vaddr+elf->pheader[idx].p_filesz)
        return false;

    return true;
}


static void modify_segments(elf64 *elf)
{
    bool corrupt = false;
    for (uint16_t idx = 0; idx < elf->eheader->e_phnum; idx++) {
        if (corrupt == true)
            elf->pheader[idx].p_offset += PAGESIZE;

        if (contain_entrypoint_segment(elf, idx) == true) {
            corrupt = true;

            ep_segment_vaddr = elf->pheader[idx].p_vaddr;
            ep_segment_offset = elf->pheader[idx].p_offset;
            ep_segment_filesz = elf->pheader[idx].p_filesz;

            elf->pheader[idx].p_filesz += loader_size;
            elf->pheader[idx].p_memsz += loader_size;
            elf->pheader[idx].p_flags |= PF_W | PF_X;
        }
    }

    if (corrupt == false) {
        fprintf(stderr, "a segment contains entrypoint not found\n");
        exit(EXIT_FAILURE);
    }
}

int pack_text(elf64 *elf, size_t fsize)
{
    uint64_t key;

    modify_segments(elf);
    modify_sections(elf);
    modify_header(elf);
    key = encrypt_section(elf, ep_sh_idx);

    fsize += PAGESIZE;

    int fd;
    char const *filename = "packed";
    void *ptr_packed;

    if ((fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if ((ptr_packed = calloc((size_t)1, fsize)) == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    write_on_mem(elf, ptr_packed, key);

    write(fd, ptr_packed, fsize);

    return EXIT_SUCCESS;
}
