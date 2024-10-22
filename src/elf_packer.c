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
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (fstat(fd, &stbuf) == -1) {
        perror("fstat");
        exit(EXIT_FAILURE);
    }
    fsize = stbuf.st_size;

    if ((pa = mmap((void *)0, (size_t)fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == (void *)-1) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    close(fd);
    *ptr_fsize = (size_t)fsize;

    return pa;
}


void usage(void)
{
    printf("Usage:\n"
           "    elf_packer [options] file\n"
           "Options:\n"
           "    -p    pack a file\n"
           "    -u    unpack a file\n");
}


int main(int argc, char **argv)
{
    int opt;
    int mode;
    void *pa;
    size_t fsize;
    elf64 *elf;

    if (argc < 2) {
        usage();
        return EXIT_SUCCESS;
    } else if (argc > 3 || argc == 2) {
        fprintf(stderr, "wrong number of arguments\n");
        usage();
        return EXIT_FAILURE;
    }

    while ((opt = getopt(argc, argv, "p:u:")) != -1) {
        switch (opt) {
            case 'p':
                mode = MODE_PACK;
                break;
            case 'u':
                mode = MODE_UNPACK;
                break;
            default:
                usage();
                return EXIT_FAILURE;
        }
    }

    pa = map_file(argv[2], &fsize);
    elf = (elf64 *)map_elf(pa);
    munmap(pa, fsize);

    if (!is_elf(elf)) {
        fprintf(stderr, "unsupported format\n");
        return EXIT_FAILURE;
    }

    if (mode == MODE_PACK)
        pack_text(elf, fsize);
    else if (mode == MODE_UNPACK)
        unpack_text(elf, fsize);

    return EXIT_SUCCESS;
}
