#include "Process.hpp"

#include <TlHelp32.h>
#include <Psapi.h>

#include "log.hpp"

Process::Process( const std::string& proc_name )
    : m_handle( 0 ), m_proc_name( proc_name ), m_pid( 0 ), m_attached( false )
{}

Process::Process( const std::string& proc_name, uint32_t pid )
    : m_handle( 0 ), m_proc_name( proc_name ), m_pid( pid ), m_attached(false)
{}

Process::~Process()
{}

bool Process::attach( uint32_t flags /*= PROCESS_ALL_ACCESS */ )
{
    detach();

    if( !m_pid )
    {
        if( m_proc_name.empty() )
        {
            log_err( "Process name not provided" );
            return false;
        }

        m_pid = get_pid( m_proc_name );

        if( !m_pid )
        {
            log_err( "Could not find process" );
            return false;
        }
    }

    m_handle = OpenProcess( flags, false, m_pid );

    if( !m_handle )
    {
        return false;
    }

    if( m_proc_name.empty() )
        m_proc_name = "UNKNOWN";

    m_attached = get_module_list();
    return m_attached;
}

void Process::detach()
{
    if( m_handle )
        CloseHandle( m_handle );

    m_handle = 0;
    m_attached = false;

    if( !m_mod_list.empty() )
    {
        for( auto& m : m_mod_list )
        {
            delete m;
            m = nullptr;
        }
    }
}

bool Process::read_memory( uintptr_t addr, void* buffer, size_t size )
{
    size_t out = 0;
    return !!ReadProcessMemory( m_handle, ( LPVOID )addr, buffer, size, ( SIZE_T* )&out );
}

bool Process::write_memory( uintptr_t addr, void* buffer, size_t size )
{
    size_t out = 0;
    return !!WriteProcessMemory( m_handle, ( LPVOID )addr, buffer, size, ( SIZE_T* )&out );
}

Module* Process::get_module( const std::string& mod_name )
{
    if( m_mod_list.empty() )
        return nullptr;

    for( auto& mod : m_mod_list )
    {
        if( mod_name.compare( mod->name() ) == 0 )
            return mod;
    }

    return nullptr;
}

Module* Process::get_module( uintptr_t address )
{
    if( m_mod_list.empty() )
        return nullptr;

    for( auto& mod : m_mod_list )
    {
        auto base = mod->img();
        auto size = mod->size();

        auto offset = address - base;

        if( offset < size )
        {
            return mod;
        }
    }

    return nullptr;
}

bool Process::impersonate()
{
    HANDLE token{};
    HANDLE dup_token{};

    if( !OpenProcessToken( m_handle, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &token ) )
    {
        log_err( "failed to impersonate", m_proc_name, ":", GetLastError() );
        return false;
    }

    if( !DuplicateToken( token, SecurityImpersonation, &dup_token ) )
    {
        log_err( "failed to duplicate token:", GetLastError() );
        return false;
    }

    if( !SetThreadToken( 0, dup_token ) )
    {
        log_err( "failed to set thread token:", GetLastError() );
        return false;
    }

    CloseHandle( dup_token );
    CloseHandle( token );

    return true;
}

/* static */ std::vector<process_t> Process::get_all_procs()
{
    std::vector<process_t> procs{};

    auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    
    if( snapshot == INVALID_HANDLE_VALUE )
    {
        log_err( "CreateToolhelp32Snapshot failure" );
        return procs;
    }

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof( PROCESSENTRY32 );

    if( !Process32First( snapshot, &entry ) )
    {
        CloseHandle( snapshot );
        log_err( "Process32First failure" );
        return procs;
    }

    do
    {
        process_t proc{};

        proc.name = entry.szExeFile;
        proc.pid = entry.th32ProcessID;

        procs.push_back( proc );

        bool add_parent = true;

        for( const auto& p : procs )
        {
            if( p.pid == entry.th32ParentProcessID )
            {
                add_parent = false;
                break;
            }
        }

        if( add_parent )
        {
            process_t proc{};

            proc.name = entry.szExeFile;
            proc.pid = entry.th32ParentProcessID;

            procs.push_back( proc );
        }

    } while( Process32Next( snapshot, &entry ) );

    return procs;
}

bool Process::get_module_list()
{
    auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, m_pid );

    if( snapshot == INVALID_HANDLE_VALUE )
    { 
        return false;
    }
        

    MODULEENTRY32 entry{};

    entry.dwSize = sizeof( MODULEENTRY32 );

    if( !Module32First( snapshot, &entry ) )
    {
        CloseHandle( snapshot );
        log_err( "Module32First failure" );
        return false;
    }

    Module* mod = nullptr;

    do 
    {
        mod = new Module
        ( 
            ( uintptr_t )entry.hModule,
            ( size_t )entry.modBaseSize,
            entry.szModule 
        );

        m_mod_list.push_back( mod );

    } while ( Module32Next( snapshot, &entry ) );

    CloseHandle( snapshot );

    return !m_mod_list.empty();
}

uint32_t Process::get_pid( const std::string& proc_name )
{
    auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

    if( snapshot == INVALID_HANDLE_VALUE )
    {
        log_err( "CreateToolhelp32Snapshot failure" );
        return 0;
    }

    PROCESSENTRY32 entry{};

    entry.dwSize = sizeof( PROCESSENTRY32 );

    if( !Process32First( snapshot, &entry ) )
    {
        CloseHandle( snapshot );
        log_err( "Module32First failure" );
        return NULL;
    }

    do
    {
        if( proc_name.compare( entry.szExeFile ) == 0 )
            break;

    } while( Process32Next( snapshot, &entry ) );


    CloseHandle( snapshot );

    return ( uint32_t )entry.th32ProcessID;
}
