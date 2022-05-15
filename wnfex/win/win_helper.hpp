#pragma once
#include "win_structs.hpp"

namespace win
{
    _FORCEINLINE_
    const PEB_T* peb() noexcept
    {
#if defined(_WIN64)
        return reinterpret_cast< const PEB_T* >( __readgsqword( 0x60 ) );
#elif defined(_WIN32)
        return reinterpret_cast< const PEB_T* >( __readfsdword( 0x30 ) );
#else
#error Unsupported platform.
#endif
    }

    _FORCEINLINE_
    const TEB_T* teb() noexcept
    {
#if defined(_WIN64)
        return reinterpret_cast< const TEB_T* >( __readgsqword( 0x30 ) );
#elif defined(_WIN32)
        return reinterpret_cast< const TEB_T* >( __readfsdword( 0x18 ) );
#else
#error Unsupported platform.
#endif
    }
    _FORCEINLINE_
    const void* image_base()
    {
        return reinterpret_cast< const void* >( peb()->ImageBaseAddress );
    }

    _FORCEINLINE_
    const PEB_LDR_DATA_T* ldr()
    {
        return reinterpret_cast< const PEB_LDR_DATA_T* >( peb()->Ldr );
    }

    _FORCEINLINE_
    const IMAGE_NT_HEADERS* nt_headers( const uint8_t* base ) noexcept
    {
        return reinterpret_cast< const IMAGE_NT_HEADERS* >(
            base + reinterpret_cast< const IMAGE_DOS_HEADER* >( base )->e_lfanew );
    }

    _FORCEINLINE_
    const size_t img_size( const uint8_t* base ) noexcept
    {
        return static_cast< size_t >( win::nt_headers( base )->OptionalHeader.SizeOfImage );
    }

    _FORCEINLINE_
    const uint32_t entry_point( const uint8_t* base ) noexcept
    {
        return static_cast< uint32_t >( win::nt_headers( base )->OptionalHeader.AddressOfEntryPoint );
    }

    _FORCEINLINE_
    const IMAGE_EXPORT_DIRECTORY* image_export_dir( const uint8_t* base ) noexcept
    {
        return reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >(
            base + nt_headers( base )->OptionalHeader.DataDirectory->VirtualAddress );
    }

    _FORCEINLINE_
    const LDR_DATA_TABLE_ENTRY_T* ldr_data_entry() noexcept
    {
        return reinterpret_cast< const LDR_DATA_TABLE_ENTRY_T* >(
            ldr()->InLoadOrderModuleList.Flink );
    }

    _FORCEINLINE_
    bool set_priv( const char* priv, BOOL enable )
    {
        HANDLE           token;
        BOOL             res;
        LUID             luid;
        TOKEN_PRIVILEGES tp;

        res = OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token );

        if( res )
        {
            res = LookupPrivilegeValue( NULL, priv, &luid );
            if( res )
            {
                tp.PrivilegeCount = 1;
                tp.Privileges[ 0 ].Luid = luid;
                tp.Privileges[ 0 ].Attributes = ( enable ) ? SE_PRIVILEGE_ENABLED : 0;

                AdjustTokenPrivileges( token, FALSE, &tp, 0, NULL, NULL );
                res = GetLastError() == ERROR_SUCCESS;
            }
            CloseHandle( token );
        }
        return res;
    }

    _FORCEINLINE_
    uint32_t get_version()
    {
        // hacky but standard GetVersion is broken

        using RtlGetVersionFn =
            NTSTATUS( NTAPI* )( _Out_ OSVERSIONINFOEXW* );

        static auto RtlGetVersion =
            reinterpret_cast< RtlGetVersionFn >( GetProcAddress(
                GetModuleHandle( "ntdll.dll" ), "RtlGetVersion" ) );

        auto osvi = OSVERSIONINFOEXW{ sizeof( OSVERSIONINFOEXW ) };

        osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFOEXW );

        if( RtlGetVersion( &osvi ) != 0 )
        {
            return 0;
        }

        return static_cast< uint32_t >( osvi.dwBuildNumber );
    }
}