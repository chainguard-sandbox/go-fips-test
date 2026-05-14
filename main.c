//go:build ignore

/*
 * SPDX-FileCopyrightText: 2026 Chainguard, Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// go-fips-test inspects a Go ELF binary and reports whether it uses a
// validated cryptographic module.
//
// It reads the embedded debug/buildinfo by mmap-ing the file and
// parsing ELF directly (no libelf), prints the buildinfo (similar to
// `go version -m`, with dependency lines suppressed), highlights
// FIPS-relevant settings (GOFIPS140, DefaultGODEBUG,
// microsoft_systemcrypto) with ANSI bold, then prints a conclusion:
//
//   - microsoft_systemcrypto=1 -> binary uses OpenSSL via the
//     Microsoft Go fork; suggests verifying with openssl-fips-test.
//   - GOFIPS140=v1.0.0-c2097c7c -> binary uses the CMVP #5247
//     validated module (OSC 8 hyperlink to the NIST certificate).
//   - otherwise -> falls back to scanning the ELF symbol table for
//     "crypto/" symbols to decide between non-validated cryptography,
//     no cryptography (FIPS compliant), or unknown (no symbol table).
//
// Only 64-bit little-endian ELF is supported (covers essentially all
// production Go binaries on amd64/arm64/etc.).

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define BOLD_ON  "\x1b[1m"
#define BOLD_OFF "\x1b[22m"
#define CMVP_URL "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247"

static const unsigned char BUILDINFO_MAGIC[] = {
    0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', 'i', 'n', 'f', ':'
};
enum {
    BUILDINFO_MAGIC_LEN  = 14,
    BUILDINFO_HEADER_LEN = 32,
    INFO_FRAME_LEN       = 16,
};

static const char *const BOLD_KEYWORDS[] = {
    "microsoft_systemcrypto",
    "DefaultGODEBUG",
    "GOFIPS140",
    NULL,
};

static bool contains(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (hlen < nlen) return false;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return true;
    }
    return false;
}

static size_t read_varint(const unsigned char *p, size_t avail, uint64_t *out) {
    uint64_t v = 0;
    int shift = 0;
    for (size_t i = 0; i < avail && i < 10; i++) {
        unsigned char b = p[i];
        v |= (uint64_t)(b & 0x7f) << shift;
        if ((b & 0x80) == 0) {
            *out = v;
            return i + 1;
        }
        shift += 7;
    }
    return 0;
}

// elf_map mmaps the file read-only. On success returns the mapped
// pointer and stores the size in *size_out; on failure returns NULL.
static const unsigned char *elf_map(const char *file, size_t *size_out, const char *err_prefix) {
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s%s: %s\n", err_prefix, file, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        fprintf(stderr, "%s%s: stat failed\n", err_prefix, file);
        close(fd);
        return NULL;
    }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        fprintf(stderr, "%s%s: mmap: %s\n", err_prefix, file, strerror(errno));
        return NULL;
    }
    *size_out = (size_t)st.st_size;
    return m;
}

// Validate that the mapping looks like a 64-bit LE ELF and return a
// pointer to the parsed header (which aliases the mapping).
static const Elf64_Ehdr *elf_header(const unsigned char *map, size_t size, const char *file) {
    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: file too small for ELF header\n", file);
        return NULL;
    }
    if (memcmp(map, "\x7f" "ELF", 4) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", file);
        return NULL;
    }
    if (map[EI_CLASS] != ELFCLASS64 || map[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s: only 64-bit little-endian ELF is supported\n", file);
        return NULL;
    }
    return (const Elf64_Ehdr *)map;
}

// Return a pointer to the section header at index i, or NULL on bounds violation.
static const Elf64_Shdr *shdr_at(const unsigned char *map, size_t size,
                                  const Elf64_Ehdr *eh, uint16_t i) {
    if (i >= eh->e_shnum) return NULL;
    uint64_t off = eh->e_shoff + (uint64_t)i * eh->e_shentsize;
    if (off + sizeof(Elf64_Shdr) > size) return NULL;
    return (const Elf64_Shdr *)(map + off);
}

// Return a pointer to the start of the section's data, validating bounds.
static const unsigned char *shdr_data(const unsigned char *map, size_t size,
                                       const Elf64_Shdr *sh) {
    if (sh->sh_type == SHT_NOBITS) return NULL;
    if (sh->sh_offset > size || sh->sh_offset + sh->sh_size > size) return NULL;
    return map + sh->sh_offset;
}

// Look up a NUL-terminated string in the string table section identified
// by index `strtab_idx`, at offset `off`. Returns NULL on bounds violation.
static const char *strtab_str(const unsigned char *map, size_t size,
                               const Elf64_Ehdr *eh, uint32_t strtab_idx, uint32_t off) {
    const Elf64_Shdr *sh = shdr_at(map, size, eh, (uint16_t)strtab_idx);
    if (!sh) return NULL;
    const unsigned char *data = shdr_data(map, size, sh);
    if (!data) return NULL;
    if (off >= sh->sh_size) return NULL;
    // ensure NUL-terminated within section
    const unsigned char *p = data + off;
    const unsigned char *end = data + sh->sh_size;
    for (const unsigned char *q = p; q < end; q++) {
        if (*q == 0) return (const char *)p;
    }
    return NULL;
}

// Find a section by name, returning its header (or NULL).
static const Elf64_Shdr *find_section(const unsigned char *map, size_t size,
                                       const Elf64_Ehdr *eh, const char *name) {
    if (eh->e_shstrndx == SHN_UNDEF) return NULL;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = shdr_at(map, size, eh, i);
        if (!sh) continue;
        const char *n = strtab_str(map, size, eh, eh->e_shstrndx, sh->sh_name);
        if (n && strcmp(n, name) == 0) return sh;
    }
    return NULL;
}

// Scan the ELF .symtab for symbols whose name contains "crypto/".
static void scan_symbols(const unsigned char *map, size_t size,
                          const Elf64_Ehdr *eh,
                          bool *has_syms, bool *has_crypto) {
    *has_syms = false;
    *has_crypto = false;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = shdr_at(map, size, eh, i);
        if (!sh || sh->sh_type != SHT_SYMTAB) continue;
        if (sh->sh_entsize != sizeof(Elf64_Sym)) continue;
        const unsigned char *data = shdr_data(map, size, sh);
        if (!data) continue;
        size_t count = sh->sh_size / sh->sh_entsize;
        if (count == 0) continue;
        *has_syms = true;
        for (size_t k = 0; k < count; k++) {
            const Elf64_Sym *sym = (const Elf64_Sym *)(data + k * sizeof(Elf64_Sym));
            const char *name = strtab_str(map, size, eh, sh->sh_link, sym->st_name);
            if (name && strstr(name, "crypto/")) {
                *has_crypto = true;
                return;
            }
        }
        return;
    }
}

static bool should_bold(const char *line, size_t len, bool ms_exclusive) {
    if (ms_exclusive) {
        return contains(line, len, "microsoft_systemcrypto=1");
    }
    for (int i = 0; BOLD_KEYWORDS[i]; i++) {
        if (contains(line, len, BOLD_KEYWORDS[i])) return true;
    }
    return false;
}

static void print_line(const char *line, size_t len, bool bold) {
    if (bold) {
        printf("\t" BOLD_ON "%.*s" BOLD_OFF "\n", (int)len, line);
    } else {
        printf("\t%.*s\n", (int)len, line);
    }
}

// Returns 1 on success, 0 on error (with diagnostic to stderr).
static int scan_file(const char *file) {
    size_t map_size;
    const unsigned char *map = elf_map(file, &map_size, "");
    if (!map) return 0;

    int rc = 0;

    const Elf64_Ehdr *eh = elf_header(map, map_size, file);
    if (!eh) goto out;

    const Elf64_Shdr *bi_sh = find_section(map, map_size, eh, ".go.buildinfo");
    if (!bi_sh) {
        fprintf(stderr, "%s: missing .go.buildinfo section\n", file);
        goto out;
    }
    const unsigned char *bi = shdr_data(map, map_size, bi_sh);
    if (!bi || bi_sh->sh_size < BUILDINFO_HEADER_LEN) {
        fprintf(stderr, "%s: .go.buildinfo too small\n", file);
        goto out;
    }
    if (memcmp(bi, BUILDINFO_MAGIC, BUILDINFO_MAGIC_LEN) != 0) {
        fprintf(stderr, "%s: bad buildinfo magic\n", file);
        goto out;
    }
    if ((bi[15] & 0x2) == 0) {
        fprintf(stderr, "%s: pre-Go 1.18 buildinfo format not supported\n", file);
        goto out;
    }

    const unsigned char *p   = bi + BUILDINFO_HEADER_LEN;
    const unsigned char *end = bi + bi_sh->sh_size;

    uint64_t vlen;
    size_t n = read_varint(p, end - p, &vlen);
    if (n == 0 || p + n + vlen > end) {
        fprintf(stderr, "%s: bad version in buildinfo\n", file);
        goto out;
    }
    const char *go_version = (const char *)(p + n);
    size_t      go_ver_len = vlen;
    p += n + vlen;

    uint64_t mlen;
    n = read_varint(p, end - p, &mlen);
    if (n == 0 || p + n + mlen > end) {
        fprintf(stderr, "%s: bad modinfo in buildinfo\n", file);
        goto out;
    }
    const char *mod_info     = (const char *)(p + n);
    size_t      mod_info_len = mlen;

    // Strip the 16-byte sentinel framing, matching Go's debug/buildinfo
    // heuristic: requires len >= 33 and a newline at mod[len-17].
    if (mod_info_len >= 33 && mod_info[mod_info_len - 17] == '\n') {
        mod_info += INFO_FRAME_LEN;
        mod_info_len -= 2 * INFO_FRAME_LEN;
    } else {
        mod_info_len = 0;
    }

    bool has_ms_crypto = contains(mod_info, mod_info_len, "microsoft_systemcrypto=1");

    char  *gofips140 = NULL;
    {
        const char *cursor = mod_info;
        const char *mod_end = mod_info + mod_info_len;
        const char  prefix[] = "build\tGOFIPS140=";
        size_t plen = sizeof(prefix) - 1;
        while (cursor < mod_end) {
            const char *nl = memchr(cursor, '\n', mod_end - cursor);
            const char *line_end = nl ? nl : mod_end;
            size_t line_len = line_end - cursor;
            if (line_len > plen && memcmp(cursor, prefix, plen) == 0) {
                size_t vlen2 = line_len - plen;
                gofips140 = malloc(vlen2 + 1);
                memcpy(gofips140, cursor + plen, vlen2);
                gofips140[vlen2] = '\0';
            }
            cursor = nl ? nl + 1 : mod_end;
        }
    }

    printf("%s: %.*s\n", file, (int)go_ver_len, go_version);

    {
        const char *cursor = mod_info;
        const char *mod_end = mod_info + mod_info_len;
        while (cursor < mod_end) {
            const char *nl = memchr(cursor, '\n', mod_end - cursor);
            const char *line_end = nl ? nl : mod_end;
            size_t line_len = line_end - cursor;
            bool skip = false;
            if (line_len >= 4 && memcmp(cursor, "dep\t", 4) == 0) skip = true;
            if (line_len >= 3 && memcmp(cursor, "=>\t", 3) == 0) skip = true;
            if (!skip && line_len > 0) {
                print_line(cursor, line_len, should_bold(cursor, line_len, has_ms_crypto));
            }
            cursor = nl ? nl + 1 : mod_end;
        }
    }

    printf("\n");
    if (has_ms_crypto) {
        printf("Binary is using OpenSSL, check status with openssl-fips-test\n");
    } else if (gofips140 && strcmp(gofips140, "v1.0.0-c2097c7c") == 0) {
        printf("Binary is using \x1b]8;;%s\x1b\\CMVP #5247\x1b]8;;\x1b\\\n", CMVP_URL);
    } else {
        bool has_syms, has_crypto;
        scan_symbols(map, map_size, eh, &has_syms, &has_crypto);
        if (has_syms && has_crypto) {
            printf("Binary is using non-validated cryptography. (verified symbols table)\n");
        } else if (has_syms) {
            printf("Binary is not using any cryptography, which is FIPS compliant. (verified symbols table)\n");
        } else {
            printf("Binary does not use a validated cryptographic module. Unknown if cryptography is in use. (no symbols table)\n");
        }
    }

    free(gofips140);
    rc = 1;

out:
    munmap((void *)map, map_size);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE ...]\n", argv[0]);
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        if (!scan_file(argv[i])) rc = 1;
    }
    return rc;
}
