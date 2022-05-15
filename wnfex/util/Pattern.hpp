#pragma once
#include <stdint.h>

class Pattern
{
public:
    static uintptr_t find( uintptr_t image, const char* pat );
    static uintptr_t find_rel32( uintptr_t image, const char* pat, int32_t offset );
    static uintptr_t find_string_ref( uintptr_t image, const char* str );
    static uintptr_t find_raw( uintptr_t image, uint8_t* pattern_data, size_t pattern_size );
    static uintptr_t find_ex( uintptr_t start, uintptr_t end, const char* pat );
    static uintptr_t find_rel32_ex( uintptr_t start, uintptr_t end, const char* pat, int32_t offset );
    static uintptr_t find_string_ref_ex( uintptr_t start, uintptr_t end, const char* str );
    static uintptr_t find_raw_ex( uintptr_t start, uintptr_t end, uint8_t* pattern_data, size_t pattern_size );
    static uintptr_t rel32_to_abs64( uintptr_t src, int32_t offset_offset );

private:
    static bool is_rel32_opcode_x64( uint8_t* code, uint8_t* out_rel32_offset );
    static uint64_t ascii_to_bin( const char* str, size_t len );
};