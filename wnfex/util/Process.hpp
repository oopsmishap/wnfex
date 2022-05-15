#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <stdint.h>

#include "Module.hpp"

typedef struct {
    std::string name;
    uint32_t pid;
} process_t;

class Process
{
public:
    Process( const std::string& proc_name );
    Process( const std::string& proc_name, uint32_t pid );
    ~Process();

    bool attach( uint32_t flags = PROCESS_ALL_ACCESS );
    void detach();

    bool read_memory( uintptr_t addr, void* buffer, size_t size );
    bool write_memory( uintptr_t addr, void* buffer, size_t size );

    Module* get_module( const std::string& mod_name );
    Module* get_module( uintptr_t address );

    bool impersonate();

    template<typename T>
    T read( uintptr_t addr, const T& default_t = T() )
    {
        T ret;

        if( !read_memory( addr, &ret, sizeof( T ) ) )
            return default_t;

        return ret;
    }

    template<typename T>
    bool write( uintptr_t addr, const T& value )
    {
        return Write( addr, &value, sizeof( T ) );
    }

    bool                is_attached() const { return m_attached; }
    uint32_t            pid() const         { return m_pid; }
    HANDLE              handle() const      { return m_handle; }
    const std::string&  name() const        { return m_proc_name; }

    static std::vector<process_t> get_all_procs();

private:
    bool get_module_list();
    uint32_t get_pid( const std::string& proc_name );

private:
    bool m_attached;
    HANDLE m_handle;
    uint32_t m_pid;
    std::string m_proc_name;
    std::vector<Module*> m_mod_list;
};