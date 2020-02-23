#include "elf_packer.h"


static inline bool is_elf(elf64 *elf)
{
    if (strncmp((char *)elf->eheader->e_ident, ELFMAG, SELFMAG) == 0)
        return true;

    return false;
}


static void *map_file(char *filename, size_t *ptr_fsize)
{
    int fd;
    struct stat stbuf;
    off_t fsize;
    void *pa; 

    if ((fd = open(filename, O_RDONLY)) == -1) {
        perror("open\n");
        exit(EXIT_FAILURE);
    }

    if (fstat(fd, &stbuf) == -1) {
        perror("fstat\n");
        exit(EXIT_FAILURE);
    }
    fsize = stbuf.st_size;

    if ((pa = mmap((void *)0, (size_t)fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == (void *)-1) {
        perror("mmap\n");
        exit(EXIT_FAILURE);
    }

    close(fd);
    *ptr_fsize = (size_t)fsize;

    return pa;
}


int main(int argc, char **argv)
{
    void *pa;
    size_t fsize;
    elf64 *elf;

    if (argc < 2) {
        printf("usage: %s file\n", argv[0]);
        return EXIT_SUCCESS;
    }
    else if (argc > 2) {
        fprintf(stderr, "too many arguments\n");
        return EXIT_FAILURE;
    }

    pa = map_file(argv[1], &fsize);
    elf = (elf64 *)map_elf(pa);

    if (!is_elf(elf)) {
        fprintf(stderr, "unsupported format\n");
        exit(EXIT_FAILURE);
    }    

    munmap(pa, fsize);

    pack_text(elf);

    return EXIT_SUCCESS;
}