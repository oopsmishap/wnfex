#include "Pattern.hpp"
#include "../win/win_helper.hpp"

uintptr_t Pattern::find( uintptr_t image, const char* pat )
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_ex( start, end, pat );
}

uintptr_t Pattern::find_rel32( uintptr_t image, const char* pat, int32_t offset )
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_rel32_ex( start, end, pat, offset );
}

uintptr_t Pattern::find_string_ref( uintptr_t image, const char* str )
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_string_ref_ex( start, end, str );
}

uintptr_t Pattern::find_raw( uintptr_t image, uint8_t* pattern_data, size_t pattern_size )
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_raw_ex( start, end, pattern_data, pattern_size );
}

uintptr_t Pattern::find_ex( uintptr_t start, uintptr_t end, const char* pat )
{
    bool    start_less = start < end;
    int32_t   pattern_len = static_cast< uint32_t >( strlen( pat ) ) - 1;
    int32_t   pattern_pos = start_less ? 0 : pattern_len;
    uint32_t  bytes_found = 0;
    uintptr_t current = start;
    uintptr_t first_match = current;

    while( start_less ? current < end : current >= end )
    {
        if( pat[ pattern_pos ] == ' ' )
        {
            start_less ? pattern_pos++ : pattern_pos--;
            continue;
        }

        auto current_byte = *reinterpret_cast<uint8_t*>( current );
        auto pattern_byte = static_cast< uint8_t >( ascii_to_bin
        (
            &pat[ start_less ? pattern_pos : pattern_pos - 1 ],
            2
        ) );

        if( current_byte == pattern_byte || pat[ pattern_pos ] == '?' )
        {
            bytes_found++;

            if( bytes_found == 1 ) { first_match = current; }

            if( start_less )
            {
                pattern_pos += ( pat[ pattern_pos ] == '?' ) ? 1 : 2;
            }
            else
            {
                pattern_pos -= ( pat[ pattern_pos ] == '?' ) ? 1 : 2;
            }

            if( pattern_pos < 0 || !pat[ pattern_pos ] )
            {
                if( start_less ) 
                { 
                    return current - bytes_found + 1; 
                }
                else 
                { 
                    return current; 
                }
            }
        }
        else
        {
            if( bytes_found > 0 ) { current = first_match; }

            bytes_found = 0;
            pattern_pos = start_less ? 0 : pattern_len;
        }

        start_less ? current++ : current--;
    }

    return 0;
}

uintptr_t Pattern::find_rel32_ex( uintptr_t start, uintptr_t end, const char* pat, int32_t offset )
{
    uintptr_t data = find_ex( start, end, pat );

    if( data == 0 )
        return 0;

    return rel32_to_abs64( data, offset );
}

uintptr_t Pattern::find_string_ref_ex( uintptr_t start, uintptr_t end, const char* str )
{
    uintptr_t string_ptr;

    // find_ex the global string pointer
    size_t string_len = strlen( str );

    string_ptr = find_raw_ex( start, end, reinterpret_cast< uint8_t* >( 
        const_cast< char* >( str ) ), string_len );

    if( string_ptr == 0 ) { return 0; }

    // find_ex refs in the code
    uint32_t  pattern_pos = 0;
    uint32_t  bytes_found = 0;
    uintptr_t current = start;

    while( current < end )
    {
        uint8_t rel_32_offset;

        if( is_rel32_opcode_x64( reinterpret_cast< uint8_t* >( current ), &rel_32_offset ) )
            if( rel32_to_abs64( current, rel_32_offset ) == string_ptr )
                return current;

        current++;
    }

    return 0;
}

uintptr_t Pattern::find_raw_ex( uintptr_t start, uintptr_t end, uint8_t* pattern_data, size_t pattern_size )
{
    uint32_t  pattern_pos = 0;
    uint32_t  bytes_found = 0;
    uintptr_t current = start;

    while( current < end )
    {
        uint8_t current_byte = *reinterpret_cast< uint8_t* >( current );
        uint8_t pattern_byte = pattern_data[ pattern_pos ];

        if( current_byte == pattern_byte )
        {
            bytes_found++;
            pattern_pos++;

            if( pattern_pos >= pattern_size )
            {
                return current - bytes_found + 1;
            }
        }
        else
        {
            bytes_found = 0;
            pattern_pos = 0;
        }

        current++;
    }

    return 0;
}

uintptr_t Pattern::rel32_to_abs64( uintptr_t src, int32_t offset_offset )
{
    if( src == 0 ) { return 0; }

    return src + offset_offset + sizeof( int32_t )
        + *reinterpret_cast< int32_t* >( src + offset_offset );
}

bool Pattern::is_rel32_opcode_x64( uint8_t* code, uint8_t* out_rel32_offset )
{
    struct opcode_info
    {
        uint8_t opcode;
        uint8_t offset;
    };

    static struct opcode_info opcodes[] =
    {
        { 0x4C, +3 },
        { 0x48, +3 },
        { 0xE8, +1 },
        { 0xE9, +1 }
    };

    for( auto& opcode : opcodes )
    {
        if( code[ 0 ] == opcode.opcode )
        {
            if( out_rel32_offset )
                *out_rel32_offset = opcode.offset;

            return true;
        }
    }

    return false;
}

uint64_t Pattern::ascii_to_bin( const char* str, size_t len )
{
    uint64_t out = 0;

    // convert at max a QWORD
    if( len > 16 || !str ) { return 0; }

    for( size_t i = 0; i < len; i++ )
    {
        out <<= 4;

        if( str[ i ] >= '0' && str[ i ] <= '9' ) { out |= ( str[ i ] - '0' ); }
        else if( str[ i ] >= 'A' && str[ i ] <= 'F' ) { out |= ( 10 + ( str[ i ] - 'A' ) ); }
        else if( str[ i ] >= 'a' && str[ i ] <= 'f' ) { out |= ( 10 + ( str[ i ] - 'a' ) ); }
        else if( str[ i ] == '?' ) { out |= 0; }
        else { return 0; }
    }

    return out;
}