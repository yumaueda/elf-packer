NAME = elf_packer
CC   = gcc
AS   = nasm

CFLAGS  = -Wall -Wextra -Werror -std=c99 -I include
ASFLAGS = -f elf64

SRC = src/elf_packer.c \
	src/map_elf.c \
	src/pack_elf.c

SRC_ASM = src/loader.S

OBJ_ASM = $(SRC_ASM:.S=.o)

$(NAME): $(SRC) $(OBJ_ASM)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_ASM): $(SRC_ASM)
	$(AS) $(ASFLAGS) -o $@ $^

clean:
	rm -f $(NAME) src/loader.o

.PHONY: elf-packer clean
