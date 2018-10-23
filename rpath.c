#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned char ubyte_t;

typedef struct file_t {
    char *name;
    size_t size;
    ubyte_t *content;
    int fd;
} file_t;

typedef struct pheader_t {
    size_t offset;
    size_t size;
} pheader_t;

static int
is_elf_file(file_t *file) {
    assert(file);
    return file->size >= 4 &&
           0x7f == file->content[0] && 'E' == file->content[1] && 'L' == file->content[2] && 'F' == file->content[3];
}

static size_t
wordsize(const file_t *file) {
    assert(file);
    assert(file->size >= 5);
    if (1 == file->content[4])
        return 4;
    if (2 == file->content[4])
        return 8;
    fprintf(stderr, "%s: invalid ELF file class: %d\n", file->name, (int)file->content[4]);
    exit(1);
}

static file_t *
open_file(const char *file_name, int oflags) {
    assert(file_name);
    file_t *file = calloc(1, sizeof(file_t));
    if (!file) {
        perror("calloc file_t");
        exit(1);
    }

    file->name = strdup(file_name);
    file->fd = open(file_name, oflags);
    if (-1 == file->fd) {
        perror(file_name);
        exit(1);
    }
    struct stat sb;
    if (-1 == fstat(file->fd, &sb)) {
        perror(file_name);
        exit(1);
    }
    file->size = sb.st_size;

    int protflags = PROT_READ;
    int mmflags = MAP_PRIVATE;
    if ((oflags & O_RDWR) != 0) {
        protflags |= PROT_WRITE;
        mmflags = MAP_SHARED;
    }
    
    file->content = mmap(NULL, sb.st_size, protflags, mmflags, file->fd, 0);
    if (MAP_FAILED == file->content) {
        perror(file_name);
        exit(1);
    }
    if (!is_elf_file(file)) {
        fprintf(stderr, "%s: not an ELF file\n", file_name);
        exit(1);
    }

    assert(file);
    assert(file->fd != -1);
    assert(file->size > 0);
    assert(file->content);
    return file;
}

static void
close_file(file_t *file) {
    assert(file);
    if (-1 == munmap(file->content, file->size)) {
        perror(file->name);
        exit(1);
    }
    if (-1 == close(file->fd)) {
        perror(file->name);
        exit(1);
    }
    file->name = NULL;
    file->content = NULL;
    file->size = 0;
    file->fd = -1;
}

static unsigned long
read_u(const file_t *file, size_t offset, size_t size) {
    assert(file);
    assert(offset + size <= file->size);
    unsigned long retval = 0;
    if (1 == file->content[5]) {                        // little endian
        for (size_t i=0; i<size; ++i)
            retval |= (unsigned long)file->content[offset+i] << (8*i);
    } else if (2 == file->content[5]) {                 // big endian
        for (size_t i=0; i<size; ++i)
            retval = (retval << 8) | (unsigned long)file->content[offset+i];
    } else {
        fprintf(stderr, "%s: invalid byte order\n", file->name);
        exit(1);
    }
    return retval;
}

static pheader_t
find_dynamic(const file_t *file) {
    size_t phoff=0, phentsize=0, phnum=0;
    if (4 == wordsize(file)) {
        phoff = read_u(file, 0x1c, 4);
        phentsize = read_u(file, 0x2a, 2);
        phnum = read_u(file, 0x2c, 2);
    } else {
        assert(8 == wordsize(file));
        phoff = read_u(file, 0x20, 8);
        phentsize = read_u(file, 0x36, 2);
        phnum = read_u(file, 0x38, 2);
    }

    for (size_t i=0; i<phnum; ++i) {
        if (2 == read_u(file, phoff + i*phentsize, 4)) {
            pheader_t retval;
            if (4 == wordsize(file)) {
                retval.offset = read_u(file, phoff + i*phentsize + 4, 4);
                retval.size = read_u(file, phoff + i*phentsize + 0x10, 4);
            } else {
                assert(8 == wordsize(file));
                retval.offset = read_u(file, phoff + i*phentsize + 8, 8);
                retval.size = read_u(file, phoff + i*phentsize + 0x20, 8);
            }
            return retval;
        }
    }
    fprintf(stderr, "%s: ELF file has no PT_DYNAMIC header\n", file->name);
    exit(1);
}

// Return file offset for section at specified virtual address, or zero
static size_t
find_section_at(const file_t *file, size_t va) {
    size_t shoff=0, shentsize=0, shnum=0;
    if (4 == wordsize(file)) {
        shoff = read_u(file, 0x20, 4);
        shentsize = read_u(file, 0x2e, 2);
        shnum = read_u(file, 0x30, 2);
    } else {
        assert(8 == wordsize(file));
        shoff = read_u(file, 0x28, 8);
        shentsize = read_u(file, 0x3a, 2);
        shnum = read_u(file, 0x3c, 2);
    }

    const size_t addr_off = 4 == wordsize(file) ? 0x0c : 0x10;
    const size_t offset_off = 4 == wordsize(file) ? 0x10 : 0x18;
    for (size_t i=0; i<shnum; ++i) {
        if (va == read_u(file, shoff + i*shentsize + addr_off, wordsize(file)))
            return read_u(file, shoff + i*shentsize + offset_off, wordsize(file));
    }

    return 0;
}

static char *
find_rpath(const file_t *file) {
    pheader_t dynamic = find_dynamic(file);
    size_t strtab_offset = 0, rpath_offset = (size_t)(-1);
    const size_t entsize = 2 * wordsize(file);
    const size_t nents = dynamic.size / entsize;
    for (size_t i=0; i<nents; ++i) {
        unsigned long tag = read_u(file, dynamic.offset + i*entsize, wordsize(file));
        if (5 == tag) {
            size_t strtab_va = read_u(file, dynamic.offset + i*entsize + wordsize(file), wordsize(file));
            strtab_offset = find_section_at(file, strtab_va);
        } else if (29 == tag) {
            rpath_offset = read_u(file, dynamic.offset + i*entsize + wordsize(file), wordsize(file));
        }
    }

    if ((size_t)(-1) == rpath_offset || 0 == strtab_offset)
        return NULL;
    return (char*)file->content + strtab_offset + rpath_offset;
}

static void
list_rpath(const char *file_name) {
    file_t *file = open_file(file_name, O_RDONLY);
    char *rpath = find_rpath(file);
    if (rpath)
        puts(rpath);
}

static void
set_rpath(const char *new_rpath, const char *file_name) {
    file_t *file = open_file(file_name, O_RDWR);
    char *old_rpath = find_rpath(file);
    if (old_rpath) {
        if (strlen(new_rpath) > strlen(old_rpath)) {
            fprintf(stderr, "%s: cannot increase length of rpath\n", file->name);
            exit(1);
        }
        strncpy(old_rpath, new_rpath, strlen(old_rpath)+1);
    } else {
        fprintf(stderr, "%s: ELF file doesn't have a previous rpath\n", file->name);
        exit(1);
    }
    close_file(file);
}

int
main(int argc, char *argv[]) {
    if (2 == argc) {
        list_rpath(argv[1]);
    } else if (3 == argc) {
        set_rpath(argv[1], argv[2]);
    } else {
        fprintf(stderr, "usage: %s [NEW_RPATH] FILE\n", argv[0]);
        exit(1);
    }

    return 0;
}
