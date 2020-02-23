#include "elf_packer.h"


static int map_sdata(elf64 *elf, void *pa)
{
    size_t elf_shnum = elf->eheader->e_shnum;
    if ((elf->sdata = (uint8_t **)calloc(elf_shnum, sizeof(uint8_t *))) == NULL) {
        perror("calloc\n");
        exit(EXIT_FAILURE);
    }

    size_t elf_section_size;

    for (uint16_t i = 0; i < elf_shnum; i++) {
        if (elf->sheader[i].sh_type == SHT_NOBITS) {
           elf->sdata[i] = (uint8_t *)0;
           continue;
        }

        elf_section_size = (size_t)elf->sheader[i].sh_size;
        if ((elf->sdata[i] =  (uint8_t *)calloc((size_t)1, elf_section_size)) == NULL) {
            perror("calloc\n");
            exit(EXIT_FAILURE);
        }

        memcpy(elf->sdata[i], (uint8_t *)pa+elf->sheader[i].sh_offset, elf_section_size);
    }

    return EXIT_SUCCESS;
}


static int map_sheader_t(elf64 *elf, void *pa)
{
    size_t elf_shnum = elf->eheader->e_shnum;

    if ((elf->sheader  = (Elf64_Shdr *)calloc(elf_shnum, sizeof(Elf64_Shdr))) == NULL) {
        perror("calloc\n");
        exit(EXIT_FAILURE);
    }

    memcpy(elf->sheader, (uint8_t *)pa+elf->eheader->e_shoff, sizeof(Elf64_Shdr)*elf_shnum);

    return EXIT_SUCCESS;
}


static int map_pheader_t(elf64 *elf, void *pa)
{
    size_t elf_phnum = elf->eheader->e_phnum;
    if ((elf->pheader = (Elf64_Phdr *)calloc(elf_phnum, sizeof(Elf64_Phdr))) == NULL) {
        perror("calloc\n");
        exit(EXIT_FAILURE);
    }

    memcpy(elf->pheader, (uint8_t *)pa+elf->eheader->e_phoff, sizeof(Elf64_Phdr)*elf_phnum);

    return EXIT_SUCCESS;
}


static int map_eheader(elf64 *elf, void *pa)
{
    if ((elf->eheader = (Elf64_Ehdr *)calloc((size_t)1, sizeof(Elf64_Ehdr))) == NULL) {
        perror("calloc\n");
        exit(EXIT_FAILURE);
    }

    memcpy(elf->eheader, pa, sizeof(Elf64_Ehdr));
    
    return EXIT_SUCCESS;
}


void *map_elf(void *pa)
{
    elf64 *elf;
    if ((elf = (elf64 *)calloc((size_t)1, sizeof(elf64))) == NULL) {
        perror("calloc\n");
        exit(EXIT_FAILURE);
    }

    map_eheader(elf, pa);
    map_pheader_t(elf, pa);
    map_sheader_t(elf, pa);
    map_sdata(elf, pa);

    return elf;
}