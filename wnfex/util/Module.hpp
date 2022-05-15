#pragma once

#include <stdint.h>
#include <string>

class Module
{
public:
    Module( 
        uintptr_t img_base, 
        size_t img_size, 
        const std::string& img_name
    )
        : 
        m_img_base( img_base ),
        m_img_size( img_size ),
        m_img_name( img_name )
    {}


    inline const uintptr_t img() const 
    {
        return m_img_base; 
    }

    inline const size_t size() const
    { 
        return m_img_size; 
    }

    inline const std::string& name() const
    { 
        return m_img_name; 
    }

private:
    uintptr_t m_img_base;
    size_t m_img_size;
    std::string m_img_name;
};