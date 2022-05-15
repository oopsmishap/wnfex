#include <Windows.h>
#include <stdio.h>

#include "util/argparse.hpp"
#include "util/Pattern.hpp"
#include "util/log.hpp"
#include "wnf/WnfSubscriberScan.hpp"
#include <ios>

void print_banner()
{
    printf(
        R"EOF( 
:::       ::: ::::    ::: :::::::::: :::::::::: :::    ::: 
:+:       :+: :+:+:   :+: :+:        :+:        :+:    :+: 
+:+       +:+ :+:+:+  +:+ +:+        +:+         +:+  +:+  
+#+  +:+  +#+ +#+ +:+ +#+ :#::+::#   +#++:++#     +#++:+   
+#+ +#+#+ +#+ +#+  +#+#+# +#+        +#+         +#+  +#+  
 #+#+# #+#+#  #+#   #+#+# #+#        #+#        #+#    #+# 
  ###   ###   ###    #### ###        ########## ###    ### 
                   Extended WNF Utility

)EOF" );
}

void print_help()
{
    printf(
        "\n"
        "-h           : print help menu\n"
        "-p   <name>  : select a single process to dump\n"
        "-pid <pid>   : select a single process to dump\n"
        "-a           : dump all WNF subscriptions from all processes\n"
        "-n   <name>  : select a single WNF WellKnown name, string\n"
        "-s   <state> : select a single WNF state name, hex number\n"
        "-v           : show verbose output, best to use on single name, don't do on all procs!\n"
        "\n"
        "-- Examples --\n\n"
        " .\\wnfex.exe -p chrome.exe\n"
        " .\\wnfex.exe -p explorer.exe -s 0x0D83063EA3B800F5\n"
        " .\\wnfex.exe -pid 21200 -n WNF_AUDC_VAM_ACTIVE -v\n"
        " .\\wnfex.exe -a\n"
        "\n"
        "-- Keys (Non-Verbose) --\n\n"
        " V  - WNF Version\n"
        " P  - Is permanent data (T/F)\n"
        " CS - Change Stamp (Doesn't always reflect usage!)\n"
        " L  - WNF_STATE_NAME_LIFETIME\n"
        "    0 = WnfWellKnownStateName  (Green)\n"
        "    1 = WnfPermanentStateName  (Cyan)\n"
        "    2 = WnfPersistentStateName (Magenta)\n"
        "    3 = WnfTemporaryStateName  (White)\n\n"
        " S  - WNF_DATA_SCOPE\n"
        "    0 = WnfDataScopeSystem\n"
        "    1 = WnfDataScopeSession\n"
        "    2 = WnfDataScopeUser\n"
        "    3 = WnfDataScopeProcess\n"
        "    4 = WnfDataScopeMachine\n\n"
    );
}

constexpr const char* OPTION_HELP = "-h";
constexpr const char* OPTION_PROC_NAME = "-p";
constexpr const char* OPTION_PID = "-pid";
constexpr const char* OPTION_ALL_PROC = "-a";
constexpr const char* OPTION_WNF_NAME = "-n";
constexpr const char* OPTION_WNF_STATE = "-s";
constexpr const char* OPTION_VERBOSE = "-v";

int main( int argc, char** argv )
{
    // apparently speeds up iostream
    std::ios_base::sync_with_stdio( false );

    print_banner();

    ArgParse args( argc, argv );

    if( args.cmd_count() < 1 || args.exists( OPTION_HELP ) )
    {
        print_help();
        exit( 0 );
    }

    uint64_t filter_state_name = 0;

    if( args.exists( OPTION_WNF_NAME ) )
    {
        auto wnf_name = args.get( OPTION_WNF_NAME );
        filter_state_name = WnfName::name_to_state( wnf_name );
    }
    else if( args.exists( OPTION_WNF_STATE ) )
    {
        auto wnf_state_str = args.get( OPTION_WNF_STATE );
        filter_state_name = std::stoull( wnf_state_str, nullptr, 16 );
    }

    auto verbose = args.exists( OPTION_VERBOSE );

    if( args.exists( OPTION_PID ) )
    {
        auto pid_str = args.get( OPTION_PID );
        auto pid = std::stoi( pid_str );

        WnfSubscriberScan scan;
        if( scan.init() )
        {
            scan.dump( pid, filter_state_name, verbose );
        }

        exit( 0 );
    }
    else if( args.exists( OPTION_PROC_NAME ) )
    {
        auto proc_name = args.get( OPTION_PROC_NAME );

        WnfSubscriberScan scan;
        if( scan.init() )
        {
            scan.dump( proc_name, filter_state_name, verbose );
        }

        exit( 0 );
    }
    else if( args.exists( OPTION_ALL_PROC ) )
    {
        log_info( "This can take some time..." );

        if( verbose )
        {
            log_info( "This WILL take time, come back later :)" );
        }

        auto proc_vec = Process::get_all_procs();

        if( proc_vec.empty() )
        {
            log_err( "failed to get proc list" );
            exit( -1 );
        }

        WnfSubscriberScan scan;

        if( scan.init() )
        {
            scan.dump( proc_vec, filter_state_name, verbose );
        }

        exit( 0 );
    }
}