# elf-packer

A packer encrypts ELF64 binaries like dacryfile.

- Searche through the binary to find a sufficient gap to inject a payload
- Encrypt the .text section
- Inject a payload. The entry point is the base of a payload

