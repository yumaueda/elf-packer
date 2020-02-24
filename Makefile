NAME = elf_packer
CC   = gcc
AS   = nasm

CFLAGS  = -Wall -Wextra -std=c99
ASFLAGS = -f elf64

SRC =   elf_packer.c \
		map_elf.c \
		pack_elf.c

SRC_ASM = loader.S

OBJ_ASM = $(SRC_ASM:.S=.o)

$(NAME): $(SRC) $(OBJ_ASM)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_ASM): $(SRC_ASM)
	$(AS) $(ASFLAGS) -o $@ $^

clean:
	rm -f $(NAME) loader.o

.PHONY: elf-packer clean