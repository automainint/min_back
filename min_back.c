#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  TARGET_386 = 1,
  TARGET_X86_64,

  ALIGNMENT_X86_64 = 16 * 1024,

  ELF32_HEADER_SIZE            = 52,
  ELF32_PROGRAM_HEADER_SIZE    = 32,
  ELF32_SECTION_HEADER_SIZE    = 40,
  ELF64_HEADER_SIZE            = 64,
  ELF64_PROGRAM_HEADER_SIZE    = 56,
  ELF64_SECTION_HEADER_SIZE    = 64,
  ELF_IDENT_SIZE               = 16,
  ELF_MAGIC                    = 0x7f,
  ELF_CLASS_ARCHITECTURE_32    = 1,
  ELF_CLASS_ARCHITECTURE_64    = 2,
  ELF_DATA_2_LITTLE_ENDIAN     = 1,
  ELF_VERSION_CURRENT          = 1,
  ELF_OS_ABI_UNIX_SYSTEM_V     = 0,
  ELF_OS_ABI_VERSION_NONE      = 0,
  ELF_TYPE_EXECUTABLE          = 2,
  ELF_MACHINE_386              = 3,
  ELF_MACHINE_X86_64           = 62,
  ELF_PROGRAM_HEADER_XNUM      = 0xffff,
  ELF_SECTION_HEADER_LORESERVE = 0xff00,
  ELF_SECTION_HEADER_UNDEF     = 0,
  ELF_SECTION_HEADER_XINDEX    = 0xffff,
  ELF_PROGRAM_HEADER_TYPE_LOAD = 1,
  ELF_PROGRAM_HEADER_FLAG_R    = 4,
  ELF_PROGRAM_HEADER_FLAG_W    = 2,
  ELF_PROGRAM_HEADER_FLAG_X    = 1
};

typedef struct {
  uint8_t  *data;
  ptrdiff_t size;
  ptrdiff_t offset;
  ptrdiff_t address;
} segment_t;

typedef struct {
  ptrdiff_t target;
  ptrdiff_t alignment;
  ptrdiff_t entry_point;

  segment_t code;
  segment_t text;
  segment_t constant;
  segment_t mutable;
} program_t;

typedef struct {
  uint8_t  architecture;
  uint16_t machine;
  uint64_t entry_point;
  uint32_t flags;

  ptrdiff_t program_header_table_offset;
  ptrdiff_t section_header_table_offset;

  ptrdiff_t program_header_table_entry_size;
  ptrdiff_t section_header_table_entry_size;

  ptrdiff_t program_header_table_size;
  ptrdiff_t section_header_table_size;
  ptrdiff_t section_name_string_table_index;
} elf_t;

typedef struct {
  uint8_t   architecture;
  uint32_t  type;
  uint32_t  flags;
  ptrdiff_t offset;
  ptrdiff_t virtual_address;
  ptrdiff_t physical_address;
  uint64_t  file_size;
  uint64_t  memory_size;
  uint64_t  alignment;
} elf_program_header_t;

typedef struct {
  int         status;
  char const *error;
  char const *output;
  FILE       *f;
  ptrdiff_t   offset;
} out_t;

ptrdiff_t adjust_alignment(ptrdiff_t const offset,
                           ptrdiff_t const alignment) {
  ptrdiff_t const delta = offset % alignment;
  return delta == 0 ? offset : offset + alignment - delta;
}

out_t parse_command_line(int argc, char **argv) {
  out_t out = { .status = 0,
                .error  = NULL,
                .output = "a.out",
                .f      = NULL,
                .offset = 0 };

  return out;
}

out_t open(out_t out) {
  if (out.status != 0)
    return out;

  out.f = fopen(out.output, "w");

  if (out.f == NULL) {
    out.status = -1;
    out.error  = "Unable to open output file.";
  }

  return out;
}

out_t write_bytes(out_t out, ptrdiff_t const size,
                  void const *const p) {
  if (out.status != 0 || size <= 0)
    return out;

  size_t n = fwrite(p, 1, size, out.f);

  if (n != size) {
    out.status = -1;
    out.error  = "Unable to write output file.";
  }

  out.offset += size;

  return out;
}

out_t write_repeat(out_t out, ptrdiff_t size, uint8_t const value) {
  if (out.status != 0)
    return out;

  uint8_t buf[40];
  memset(buf, value, sizeof buf);

  for (; size > 0; size -= sizeof buf) {
    ptrdiff_t n = size < sizeof buf ? size : (ptrdiff_t) sizeof buf;
    out         = write_bytes(out, n, buf);
  }

  return out;
}

out_t write_zero(out_t out, ptrdiff_t size) {
  return write_repeat(out, size, 0);
}

out_t write_str(out_t out, char const *const s) {
  return write_bytes(out, (ptrdiff_t) strlen(s), s);
}

out_t write_byte(out_t out, uint64_t value) {
  if ((value & 0xffull) != value) {
    out.status = -1;
    out.error  = "Invalid u8 write.";
    return out;
  }

  return write_bytes(out, 1, &value);
}

out_t write_int16(out_t out, int64_t value) {
  if ((value & 0xffffll) != value) {
    out.status = -1;
    out.error  = "Invalid i16 write.";
    return out;
  }

  return write_bytes(out, 2, &value);
}

out_t write_int32(out_t out, int64_t value) {
  if ((value & 0xffffffffll) != value) {
    out.status = -1;
    out.error  = "Invalid i32 write.";
    return out;
  }

  return write_bytes(out, 4, &value);
}

out_t write_int64(out_t out, int64_t value) {
  return write_bytes(out, 8, &value);
}

out_t write_uint16(out_t out, uint16_t value) {
  if ((value & 0xffffull) != value) {
    out.status = -1;
    out.error  = "Invalid u16 write.";
    return out;
  }

  return write_bytes(out, 2, &value);
}

out_t write_uint32(out_t out, uint32_t value) {
  if ((value & 0xffffffffull) != value) {
    out.status = -1;
    out.error  = "Invalid u32 write.";
    return out;
  }

  return write_bytes(out, 4, &value);
}

out_t write_uint64(out_t out, uint64_t value) {
  return write_bytes(out, 8, &value);
}

program_t create_program() {
  program_t program;
  memset(&program, 0, sizeof program);

  program.target = TARGET_X86_64;

  return program;
}

out_t write_elf_header(out_t out, elf_t elf) {
  if (out.status != 0)
    return out;

  if (elf.architecture != ELF_CLASS_ARCHITECTURE_32 &&
      elf.architecture != ELF_CLASS_ARCHITECTURE_64) {
    out.status = -1;
    out.error  = "Unsupported architecture.";
    return out;
  }

  uint16_t header_size = elf.architecture == ELF_CLASS_ARCHITECTURE_32
                             ? ELF32_HEADER_SIZE
                             : ELF64_HEADER_SIZE;

  uint16_t program_header_table_size_x16 = ELF_PROGRAM_HEADER_XNUM;
  uint16_t section_header_table_size_x16 = 0;
  uint16_t section_name_string_table_index_x16 =
      ELF_SECTION_HEADER_XINDEX;

  if (elf.program_header_table_size < ELF_PROGRAM_HEADER_XNUM)
    program_header_table_size_x16 = (uint16_t)
                                        elf.program_header_table_size;

  if (elf.section_header_table_size < ELF_SECTION_HEADER_LORESERVE)
    section_header_table_size_x16 = (uint16_t)
                                        elf.section_header_table_size;

  if (elf.section_name_string_table_index <
      ELF_SECTION_HEADER_LORESERVE)
    section_name_string_table_index_x16 =
        (uint16_t) elf.section_name_string_table_index;

  out = write_byte(out, ELF_MAGIC);
  out = write_str(out, "ELF");
  out = write_byte(out, elf.architecture);
  out = write_byte(out, ELF_DATA_2_LITTLE_ENDIAN);
  out = write_byte(out, ELF_VERSION_CURRENT);
  out = write_byte(out, ELF_OS_ABI_UNIX_SYSTEM_V);
  out = write_byte(out, ELF_OS_ABI_VERSION_NONE);
  out = write_zero(out, ELF_IDENT_SIZE - out.offset - 1);
  out = write_byte(out, ELF_IDENT_SIZE);

  out = write_uint16(out, ELF_TYPE_EXECUTABLE);
  out = write_uint16(out, elf.machine);
  out = write_uint32(out, ELF_VERSION_CURRENT);

  if (elf.architecture == ELF_CLASS_ARCHITECTURE_32) {
    out = write_uint32(out, elf.entry_point);
    out = write_uint32(out, elf.program_header_table_offset);
    out = write_uint32(out, elf.section_header_table_offset);
  } else {
    out = write_uint64(out, elf.entry_point);
    out = write_uint64(out, elf.program_header_table_offset);
    out = write_uint64(out, elf.section_header_table_offset);
  }

  out = write_uint32(out, elf.flags);
  out = write_uint16(out, header_size);

  out = write_uint16(out, elf.program_header_table_entry_size);
  out = write_uint16(out, program_header_table_size_x16);
  out = write_uint16(out, elf.section_header_table_entry_size);
  out = write_uint16(out, section_header_table_size_x16);
  out = write_uint16(out, section_name_string_table_index_x16);

  if (out.offset > header_size) {
    out.status = -1;
    out.error  = "Invalid ELF header offset.";
  } else
    out = write_zero(out, header_size - out.offset);

  return out;
}

out_t write_elf_program_header(out_t                out,
                               elf_program_header_t header) {
  out = write_uint32(out, header.type);

  if (header.architecture == ELF_CLASS_ARCHITECTURE_32) {
    out = write_uint32(out, header.offset);
    out = write_uint32(out, header.virtual_address);
    out = write_uint32(out, header.physical_address);
    out = write_uint32(out, header.file_size);
    out = write_uint32(out, header.memory_size);
    out = write_uint32(out, header.flags);
    out = write_uint32(out, header.alignment);
  } else {
    out = write_uint32(out, header.flags);
    out = write_uint64(out, header.offset);
    out = write_uint64(out, header.virtual_address);
    out = write_uint64(out, header.physical_address);
    out = write_uint64(out, header.file_size);
    out = write_uint64(out, header.memory_size);
    out = write_uint64(out, header.alignment);
  }

  return out;
}

out_t write_elf_load_header(out_t out, segment_t segment,
                            uint8_t architecture, ptrdiff_t alignment,
                            uint32_t flags) {
  if (out.status != 0 || segment.size == 0)
    return out;

  elf_program_header_t header = {
    .architecture     = architecture,
    .type             = ELF_PROGRAM_HEADER_TYPE_LOAD,
    .flags            = flags,
    .offset           = segment.offset,
    .virtual_address  = segment.address,
    .physical_address = segment.address,
    .file_size        = segment.size,
    .memory_size      = segment.size,
    .alignment        = alignment
  };

  return write_elf_program_header(out, header);
}

out_t write_elf_program_headers(out_t out, program_t program,
                                elf_t elf) {
  if (out.status != 0 || elf.program_header_table_size == 0)
    return out;

  out = write_zero(out, elf.program_header_table_offset - out.offset);

  out = write_elf_load_header(out, program.code, elf.architecture,
                              program.alignment,
                              ELF_PROGRAM_HEADER_FLAG_X);

  out = write_elf_load_header(
      out, program.text, elf.architecture, program.alignment,
      ELF_PROGRAM_HEADER_FLAG_X | ELF_PROGRAM_HEADER_FLAG_R);

  out = write_elf_load_header(out, program.constant, elf.architecture,
                              program.alignment,
                              ELF_PROGRAM_HEADER_FLAG_R);

  out = write_elf_load_header(
      out, program.mutable, elf.architecture, program.alignment,
      ELF_PROGRAM_HEADER_FLAG_R | ELF_PROGRAM_HEADER_FLAG_W);

  return out;
}

out_t write_elf_section_headers(out_t out, program_t program,
                                elf_t elf) {
  if (out.status != 0 || elf.section_header_table_size == 0)
    return out;

  return out;
}

out_t write_elf(out_t out, program_t program) {
  if (out.status != 0)
    return out;

  elf_t elf;
  memset(&elf, 0, sizeof elf);

  program.alignment = ALIGNMENT_X86_64;

  if (program.target == TARGET_386) {
    elf.architecture = ELF_CLASS_ARCHITECTURE_32;
    elf.machine      = ELF_MACHINE_386;

    elf.program_header_table_entry_size = ELF32_PROGRAM_HEADER_SIZE;
    elf.section_header_table_entry_size = ELF32_SECTION_HEADER_SIZE;
  } else if (program.target == TARGET_X86_64) {
    elf.architecture = ELF_CLASS_ARCHITECTURE_64;
    elf.machine      = ELF_MACHINE_X86_64;

    elf.program_header_table_entry_size = ELF64_PROGRAM_HEADER_SIZE;
    elf.section_header_table_entry_size = ELF64_SECTION_HEADER_SIZE;
  } else {
    out.status = -1;
    out.error  = "Unsupported target.";
    return out;
  }

  elf.entry_point = program.entry_point;

  if (program.code.size > 0)
    elf.program_header_table_size++;
  if (program.text.size > 0)
    elf.program_header_table_size++;
  if (program.constant.size > 0)
    elf.program_header_table_size++;
  if (program.mutable.size > 0)
    elf.program_header_table_size++;

  ptrdiff_t const header_size = elf.architecture ==
                                        ELF_CLASS_ARCHITECTURE_32
                                    ? ELF32_HEADER_SIZE
                                    : ELF64_HEADER_SIZE;

  ptrdiff_t const headers_end = header_size +
                                elf.program_header_table_entry_size *
                                    elf.section_header_table_size +
                                elf.section_header_table_entry_size *
                                    elf.section_header_table_size;

  if (elf.program_header_table_size != 0)
    elf.program_header_table_offset = headers_end;

  if (elf.section_header_table_size != 0)
    elf.program_header_table_offset =
        elf.program_header_table_offset == 0
            ? headers_end
            : elf.program_header_table_offset +
                  elf.program_header_table_entry_size *
                      elf.program_header_table_size;

  program.code.offset = adjust_alignment(headers_end,
                                         program.alignment);

  program.text.offset = adjust_alignment(
      program.code.offset + program.code.size, program.alignment);
  program.text.address = adjust_alignment(program.code.size,
                                          program.alignment);

  program.constant.offset = adjust_alignment(
      program.text.offset + program.text.size, program.alignment);
  program.constant.address = adjust_alignment(program.text.size,
                                              program.alignment);

  program.mutable.offset  = adjust_alignment(program.constant.offset +
                                                 program.constant.size,
                                             program.alignment);
  program.mutable.address = adjust_alignment(program.constant.size,
                                             program.alignment);

  out = write_elf_header(out, elf);
  out = write_elf_program_headers(out, program, elf);
  out = write_elf_section_headers(out, program, elf);

  return out;
}

out_t done(out_t out) {
  if (out.f != NULL)
    fclose(out.f);

  if (out.status != 0)
    printf("Error: %s\n", out.error);

  return out;
}

int main(int argc, char **argv) {
  out_t out;

  out = parse_command_line(argc, argv);
  out = open(out);
  out = write_elf(out, create_program());
  out = done(out);

  return out.status;
}
