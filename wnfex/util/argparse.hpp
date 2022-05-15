#pragma once
#include <string>
#include <vector>

class ArgParse{
public:
    ArgParse( int& argc, char** argv )
    {
        m_cmd_count = 0;

        for( int i = 1; i < argc; ++i )
        {
            m_tokens.push_back( std::string( argv[ i ] ) );
            m_cmd_count++;
        }
    }

    const std::string& get( const std::string& option ) const
    {
        std::vector<std::string>::const_iterator itr;
        itr = std::find( m_tokens.begin(), m_tokens.end(), option );

        if( itr != m_tokens.end() && ++itr != m_tokens.end() )
            return *itr;

        static const std::string empty_string( "" );
        return empty_string;
    }

    bool exists( const std::string& option ) const
    {
        return std::find( m_tokens.begin(), m_tokens.end(), option ) != m_tokens.end();
    }

    int cmd_count() { return m_cmd_count; }

private:
    std::vector<std::string> m_tokens;
    int m_cmd_count;
};