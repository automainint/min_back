#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
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
  ELF_SECTION_HEADER_XINDEX    = 0xffff
};

typedef struct {
  uint8_t  *data;
  ptrdiff_t size;
} segment_t;

typedef struct {
  uint8_t  architecture;
  uint16_t machine;
  uint32_t machine_flags;

  ptrdiff_t entry_point;
  ptrdiff_t program_header_table_offset;
  ptrdiff_t section_header_table_offset;

  uint16_t program_header_table_entry_size;
  uint16_t section_header_table_entry_size;

  ptrdiff_t program_header_table_size;
  ptrdiff_t section_header_table_size;
  ptrdiff_t section_name_string_table_index;

  segment_t text;
  segment_t data;
} program_t;

typedef struct {
  int         status;
  char const *error;
  char const *output;
  FILE       *f;
  ptrdiff_t   offset;
} out_t;

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

out_t write_byte(out_t out, uint8_t value) {
  return write_bytes(out, 1, &value);
}

out_t write_int16(out_t out, int16_t value) {
  return write_bytes(out, 2, &value);
}

out_t write_int32(out_t out, int32_t value) {
  return write_bytes(out, 4, &value);
}

out_t write_int64(out_t out, int64_t value) {
  return write_bytes(out, 8, &value);
}

out_t write_uint16(out_t out, uint16_t value) {
  return write_bytes(out, 2, &value);
}

out_t write_uint32(out_t out, uint32_t value) {
  return write_bytes(out, 4, &value);
}

out_t write_uint64(out_t out, uint64_t value) {
  return write_bytes(out, 8, &value);
}

program_t create_program() {
  program_t program = { .architecture  = ELF_CLASS_ARCHITECTURE_64,
                        .machine       = ELF_MACHINE_X86_64,
                        .machine_flags = 0,

                        .entry_point                 = 0,
                        .program_header_table_offset = 0,
                        .section_header_table_offset = 0,

                        .program_header_table_entry_size = 0,
                        .section_header_table_entry_size = 0,

                        .program_header_table_size       = 0,
                        .section_header_table_size       = 0,
                        .section_name_string_table_index = 0 };

  return program;
}

out_t write_elf_header(out_t out, program_t program) {
  if (out.status != 0)
    return out;

  if (program.architecture != ELF_CLASS_ARCHITECTURE_32 &&
      program.architecture != ELF_CLASS_ARCHITECTURE_64) {
    out.status = -1;
    out.error  = "Unsupported architecture.";
    return out;
  }

  uint16_t elf_header_size = program.architecture ==
                                     ELF_CLASS_ARCHITECTURE_32
                                 ? ELF32_HEADER_SIZE
                                 : ELF64_HEADER_SIZE;

  uint16_t program_header_table_size_x16 = ELF_PROGRAM_HEADER_XNUM;
  uint16_t section_header_table_size_x16 = 0;
  uint16_t section_name_string_table_index_x16 =
      ELF_SECTION_HEADER_XINDEX;

  if (program.program_header_table_size < ELF_PROGRAM_HEADER_XNUM)
    program_header_table_size_x16 =
        (uint16_t) program.program_header_table_size;

  if (program.section_header_table_size <
      ELF_SECTION_HEADER_LORESERVE)
    section_header_table_size_x16 =
        (uint16_t) program.section_header_table_size;

  if (program.section_name_string_table_index <
      ELF_SECTION_HEADER_LORESERVE)
    section_name_string_table_index_x16 =
        (uint16_t) program.section_name_string_table_index;

  out = write_byte(out, ELF_MAGIC);
  out = write_str(out, "ELF");
  out = write_byte(out, program.architecture);
  out = write_byte(out, ELF_DATA_2_LITTLE_ENDIAN);
  out = write_byte(out, ELF_VERSION_CURRENT);
  out = write_byte(out, ELF_OS_ABI_UNIX_SYSTEM_V);
  out = write_byte(out, ELF_OS_ABI_VERSION_NONE);
  out = write_zero(out, ELF_IDENT_SIZE - out.offset - 1);
  out = write_byte(out, ELF_IDENT_SIZE);

  out = write_uint16(out, ELF_TYPE_EXECUTABLE);
  out = write_uint16(out, program.machine);
  out = write_uint32(out, ELF_VERSION_CURRENT);

  if (program.architecture == ELF_CLASS_ARCHITECTURE_32) {
    out = write_uint32(out, (uint32_t) program.entry_point);
    out = write_uint32(
        out, (uint32_t) program.program_header_table_offset);
    out = write_uint32(
        out, (uint32_t) program.section_header_table_offset);
  } else {
    out = write_uint64(out, (uint64_t) program.entry_point);
    out = write_uint64(
        out, (uint64_t) program.program_header_table_offset);
    out = write_uint64(
        out, (uint64_t) program.section_header_table_offset);
  }

  out = write_uint32(out, program.machine_flags);
  out = write_uint16(out, elf_header_size);

  out = write_uint16(out, program.program_header_table_entry_size);
  out = write_uint16(out, program_header_table_size_x16);
  out = write_uint16(out, program.section_header_table_entry_size);
  out = write_uint16(out, section_header_table_size_x16);
  out = write_uint16(out, section_name_string_table_index_x16);

  if (out.offset > elf_header_size) {
    out.status = -1;
    out.error  = "Invalid ELF header offset.";
  } else
    out = write_zero(out, elf_header_size - out.offset);

  return out;
}

out_t write_program_headers(out_t out, program_t program) {
  if (out.status != 0)
    return out;

  return out;
}

out_t write_section_headers(out_t out, program_t program) {
  if (out.status != 0)
    return out;

  return out;
}

out_t write_elf(out_t out, program_t program) {
  if (out.status != 0)
    return out;

  if (program.architecture == ELF_CLASS_ARCHITECTURE_32) {
    // program.program_header_table_offset = ELF32_HEADER_SIZE;
    program.program_header_table_entry_size =
        ELF32_PROGRAM_HEADER_SIZE;
    program.section_header_table_entry_size =
        ELF32_SECTION_HEADER_SIZE;
  } else {
    // program.program_header_table_offset = ELF64_HEADER_SIZE;
    program.program_header_table_entry_size =
        ELF64_PROGRAM_HEADER_SIZE;
    program.section_header_table_entry_size =
        ELF64_SECTION_HEADER_SIZE;
  }

  out = write_elf_header(out, program);
  out = write_program_headers(out, program);
  out = write_section_headers(out, program);

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
