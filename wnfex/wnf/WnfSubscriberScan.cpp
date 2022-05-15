#include "WnfSubscriberScan.hpp"

#include "../util/Pattern.hpp"
#include "../util/log.hpp"
#include "../util/RBTreeRemote.hpp"

#include "../win/win_helper.hpp"

#include <format>
#include <DbgHelp.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dbghelp.lib")

#pragma warning (disable : 4996)

namespace test
{
    uint32_t a;
}

bool WnfSubscriberScan::init()
{
    if( !win::set_priv( SE_DEBUG_NAME, TRUE ) )
    {
        log_err( "Could not adjust privilege to debug, might not print everything... Try being admin" );
        Sleep( 1500 );
    }

    // hacky but standard GetVersion is broken

    using RtlGetVersionFn =
        NTSTATUS( NTAPI* )( _Out_ OSVERSIONINFOEXW* );

    static auto RtlGetVersion =
        ( RtlGetVersionFn )GetProcAddress(
            GetModuleHandle( "ntdll.dll" ), "RtlGetVersion" );

    auto osvi = OSVERSIONINFOEXW{ sizeof( OSVERSIONINFOEXW ) };

    osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFOEXW );

    if( RtlGetVersion( &osvi ) != 0 )
    {
        log_err( "Could not get windows version, defaulting to pre Windows 11" );
        Sleep( 1500 );
    }

    if( osvi.dwBuildNumber >= 22000 )
    {
        log_info( "Using Windows 11 WNF Structs" );
        m_windows11 = true;
    }
    else
    {
        log_info( "Using Pre Windows 11 WNF Structs" );
    }

    return find_subscriber_table();
}

void WnfSubscriberScan::dump( const std::string& proc_name, uint64_t filter_state_name, bool verbose )
{
    if( !m_wnf_table_offset )
    {
        log_err( "failed to get wnf table offset" );
        return;
    }

    auto proc = Process( proc_name );

    if( !proc.attach() )
    {
        log_err( "failed to attach to", proc_name.c_str() );
        return;
    }

    // setup the process for DbgHelp
    SymInitialize( proc.handle(), nullptr, TRUE );

    dump_table( proc, filter_state_name, verbose );

    // DbgHelp clean up
    SymCleanup( proc.handle() );

    proc.detach();

    print( verbose );
}

void WnfSubscriberScan::dump( const std::vector<process_t>& processes, uint64_t filter_state_name, bool verbose )
{
    if( !m_wnf_table_offset )
    {
        log_err( "failed to get wnf table offset" );
        return;
    }

    for( const auto& process : processes )
    {
        auto proc = Process( process.name, process.pid );

        if( !proc.attach() )
        {
            log_err( "failed to attach to", process.name.c_str(), ":", process.pid );
            continue;
        }

        SymInitialize( proc.handle(), nullptr, TRUE );

        dump_table( proc, filter_state_name, verbose );

        SymCleanup( proc.handle() );

        proc.detach();
    }

    print( verbose );
}

void WnfSubscriberScan::dump( uint32_t pid, uint64_t filter_state_name /*= 0*/, bool verbose /*= false */ )
{
    if( !m_wnf_table_offset )
    {
        log_err( "failed to get wnf table offset" );
        return;
    }

    auto proc = Process( "", pid );

    if( !proc.attach() )
    {
        log_err( "failed to attach to PID", pid );
        return;
    }

    // setup the process for DbgHelp
    SymInitialize( proc.handle(), nullptr, TRUE );

    dump_table( proc, filter_state_name, verbose );

    // DbgHelp clean up
    SymCleanup( proc.handle() );

    proc.detach();

    print( verbose );
}

bool WnfSubscriberScan::find_subscriber_table()
{
    auto ntdll = reinterpret_cast< uintptr_t >( GetModuleHandleA( "ntdll.dll" ) );

    if( !ntdll )
    {
        log_err( "somehow ntdll.dll did not load...." );
        return false;
    }

    auto wnf_table = Pattern::find_rel32( ntdll, "48 8B 05 ? ? ? ? 8B 48 40", 3 );

    if( !wnf_table )
    {
        log_err( "failed to find WNF Subscriber Table within our NTDLL.dll, probably broken sig" );
        return false;
    }

    m_wnf_table_offset = wnf_table - ntdll;

    return true;
}

uintptr_t WnfSubscriberScan::get_table_addr( Process& proc )
{
    if( !m_wnf_table_offset )
        return 0;

    if( !proc.is_attached() )
        return 0;

    auto ntdll = proc.get_module( "ntdll.dll" )->img();

    if( !ntdll )
        return 0;

    auto remote_table_addr = ntdll + m_wnf_table_offset;

    return proc.read<uintptr_t>( remote_table_addr );
}

bool WnfSubscriberScan::get_table(
    Process& proc, uintptr_t table_addr, WNF_SUBSCRIPTION_TABLE& table )
{
    if( !table_addr )
        return false;

    if( !proc.is_attached() )
        return false;

    table = proc.read<WNF_SUBSCRIPTION_TABLE>( table_addr );

    // each node/structure in WNF has a header giving you the size and code type of it
    // we just check if we indeed have the right one
    if( table.Header.NodeTypeCode != WNF_NODE_SUBSCRIPTION_TABLE )
    {
        log_err( "Node Type Code does not match WNF_NODE_SUBSCRIPTION_TABLE, probably updated structure" );
        return false;
    }

    return true;
}

bool WnfSubscriberScan::get_table_w11(
    Process& proc, uintptr_t table_addr, WNF_SUBSCRIPTION_TABLE_W11& table )
{
    if( !table_addr )
        return false;

    if( !proc.is_attached() )
        return false;

    table = proc.read<WNF_SUBSCRIPTION_TABLE_W11>( table_addr );

    // each node/structure in WNF has a header giving you the size and code type of it
    // we just check if we indeed have the right one
    if( table.Header.NodeTypeCode != WNF_NODE_SUBSCRIPTION_TABLE )
    {
        log_err( "Node Type Code does not match WNF_NODE_SUBSCRIPTION_TABLE, probably updated structure" );
        return false;
    }

    return true;
}

bool WnfSubscriberScan::build_wnf_info(
    Process& proc, wnf_info_t* wnf_info, uint64_t filter_state_name /*= 0 */ )
{
    bool filter = !!filter_state_name;

    auto table_addr = get_table_addr( proc );

    if( !table_addr )
        return false;

    if( !get_table( proc, table_addr, wnf_info->subscription_table ) )
        return false;

    wnf_info->address = table_addr;
    wnf_info->proc_name = proc.name();
    wnf_info->pid = proc.pid();

    auto name_list = wnf_info->subscription_table.NamesTableEntry;
    auto name_list_curr = ( uintptr_t )name_list.Flink;

    for( ;; )
    {
        // normal weird windows thing where it links mid struct
        uintptr_t name_addr = name_list_curr -
            offsetof( WNF_NAME_SUBSCRIPTION, NamesTableEntry );

        auto wnf_name = proc.read< WNF_NAME_SUBSCRIPTION >( name_addr );

        // each node/structure in WNF has a header giving you the size and code type of it
        // we just check if we indeed have the right one
        if( wnf_name.Header.NodeTypeCode != WNF_NODE_NAME_SUBSCRIPTION )
        {
            log_err( "Node Type Code does not match WNF_NODE_NAME_SUBSCRIPTION, probably updated structure" );
            continue;
        }

        // statename is a struct, we need to dereference it as an int64
        auto state_name = *( uint64_t* )&wnf_name.StateName;

        // apply state name filter, if it doesn't match skip...
        if( !filter || state_name == filter_state_name )
        {
            // set the show flag to true if no filter or we have a match
            wnf_info->show = true;

            // setup WNF name struct
            wnf_name_t name;
            name.address = name_addr;
            name.name = wnf_name;

            // get head of the subscription list
            auto user_sub_list = wnf_name.SubscriptionsListHead;
            auto user_sub_list_curr = ( uintptr_t )user_sub_list.Flink;

            for( ;; )
            {
                // normal weird windows thing where it links mid struct
                uintptr_t user_sub_addr = user_sub_list_curr -
                    offsetof( WNF_USER_SUBSCRIPTION, SubscriptionsListEntry );

                auto wnf_user_sub = proc.read<WNF_USER_SUBSCRIPTION>( user_sub_addr );

                // each node/structure in WNF has a header giving you the size and code type of it
                // we just check if we indeed have the right one
                if( wnf_user_sub.Header.NodeTypeCode != WNF_NODE_USER_SUBSCRIPTION )
                {
                    log_err( "Node Type Code does not match WNF_NODE_USER_SUBSCRIPTION, probably updated structure" );
                    continue;
                }

                // lambda to get the file name from function address
                auto get_file_name = []( Process& proc, uintptr_t addr ) -> std::string
                {
                    auto mod = proc.get_module( addr );

                    if( !mod ) return "";

                    return mod->name();
                };

                auto get_va = []( Process& proc, uintptr_t addr ) -> uintptr_t
                {
                    auto mod = proc.get_module( addr );

                    if( !mod ) return 0;

                    return ( addr - mod->img() ) + 0x180000000;
                };

                // lambda to get symbol name from function address if it exists
                auto get_symbol = []( Process& proc, uintptr_t addr ) -> std::string
                {
                    uint8_t buf[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME ]{};
                    auto* sym_info = ( SYMBOL_INFO* )buf;
                    sym_info->SizeOfStruct = sizeof( SYMBOL_INFO );
                    sym_info->MaxNameLen = MAX_SYM_NAME;
                    if( !SymFromAddr( proc.handle(), addr, nullptr, sym_info ) || !sym_info->Name )
                    {
                        return "";
                    }
                    return sym_info->Name;
                };

                // setup WNF subscription struct
                // save other values we want to print later when we no longer have the "Process"
                wnf_subscription_t subscription{};
                subscription.address = user_sub_addr;
                subscription.subscription = wnf_user_sub;
                subscription.callback_va = get_va( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_va = get_va( proc, ( uintptr_t )wnf_user_sub.CallbackContext );
                subscription.callback_file_name = get_file_name( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_file_name = get_file_name( proc, ( uintptr_t )wnf_user_sub.CallbackContext );
                subscription.callback_symbol_name = get_symbol( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_symbol_name = get_symbol( proc, ( uintptr_t )wnf_user_sub.CallbackContext );

                // push to WNF name struct
                name.subscriptions.push_back( subscription );

                // break out of loop when we reached the back link
                if( user_sub_list_curr == ( uintptr_t )user_sub_list.Blink )
                    break;

                // get next item in linked list
                user_sub_list_curr = proc.read<uintptr_t>( user_sub_list_curr );
            }

            // push WNF name to WNF info
            wnf_info->wnf_names.push_back( name );
        }

        // break out of loop when we reached the back link
        if( name_list_curr == ( uintptr_t )name_list.Blink )
            break;

        // get next item in linked list
        name_list_curr = proc.read<uintptr_t>( name_list_curr );
    }

    return true;
}

// Windows 11 doubled down on WNF, to the point where a linked list was
// becoming too slow, they have updated the name subscription list to
// a Red Black binary tree, not fun to traverse remotely
bool WnfSubscriberScan::build_wnf_info_w11(
    Process& proc, wnf_info_w11_t* wnf_info, uint64_t filter_state_name )
{
    bool filter = !!filter_state_name;

    auto table_addr = get_table_addr( proc );

    if( !table_addr )
        return false;

    if( !get_table_w11( proc, table_addr, wnf_info->subscription_table ) )
        return false;

    wnf_info->address = table_addr;
    wnf_info->proc_name = proc.name();
    wnf_info->pid = proc.pid();

    // get the root node from the tree and pass it into RBTreeRemote
    auto name_tree_root = wnf_info->subscription_table.NamesTableEntry.Root;
    auto tree = RBTreeRemote( proc, ( uintptr_t )name_tree_root );

    // to iterate over the entire tree we need to find the first (left most) node
    auto node = tree.first();

    // we will keep looping until we are at the last node
    while( !node.is_null() )
    {
        // normal weird windows thing where it links mid struct
        uintptr_t name_addr = node.get_address() -
            offsetof( WNF_NAME_SUBSCRIPTION_W11, NamesTableEntry );

        auto wnf_name = proc.read< WNF_NAME_SUBSCRIPTION_W11 >( name_addr );

        // each node/structure in WNF has a header giving you the size and code type of it
        // we just check if we indeed have the right one
        if( wnf_name.Header.NodeTypeCode != WNF_NODE_NAME_SUBSCRIPTION )
        {
            log_err( "Node Type Code does not match WNF_NODE_NAME_SUBSCRIPTION, probably updated structure" );
            continue;
        }

        // statename is a struct, we need to dereference it as an int64
        auto state_name = *( uint64_t* )&wnf_name.StateName;

        // apply state name filter, if it doesn't match skip...
        if( !filter || state_name == filter_state_name )
        {
            // set the show flag to true if no filter or we have a match
            wnf_info->show = true;

            // setup WNF name struct
            wnf_name_w11_t name;
            name.address = name_addr;
            name.name = wnf_name;

            // get head of the subscription list
            auto user_sub_list = wnf_name.SubscriptionsListHead;
            auto user_sub_list_curr = ( uintptr_t )user_sub_list.Flink;

            for( ;; )
            {
                // normal weird windows thing where it links mid struct
                uintptr_t user_sub_addr = user_sub_list_curr -
                    offsetof( WNF_USER_SUBSCRIPTION, SubscriptionsListEntry );

                auto wnf_user_sub = proc.read<WNF_USER_SUBSCRIPTION>( user_sub_addr );

                // each node/structure in WNF has a header giving you the size and code type of it
                // we just check if we indeed have the right one
                if( wnf_user_sub.Header.NodeTypeCode != WNF_NODE_USER_SUBSCRIPTION )
                {
                    log_err( "Node Type Code does not match WNF_NODE_USER_SUBSCRIPTION, probably updated structure" );
                    continue;
                }

                // lambda to get the file name from function address
                auto get_file_name = []( Process& proc, uintptr_t addr ) -> std::string
                {
                    auto mod = proc.get_module( addr );

                    if( !mod ) return "";

                    return mod->name();
                };

                auto get_va = []( Process& proc, uintptr_t addr ) -> uintptr_t
                {
                    auto mod = proc.get_module( addr );

                    if( !mod ) return 0;

                    return ( addr - mod->img() ) + 0x180000000;
                };

                // lambda to get symbol name from function address if it exists
                auto get_symbol = []( Process& proc, uintptr_t addr ) -> std::string
                {
                    uint8_t buf[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME ]{};
                    auto* sym_info = ( SYMBOL_INFO* )buf;
                    sym_info->SizeOfStruct = sizeof( SYMBOL_INFO );
                    sym_info->MaxNameLen = MAX_SYM_NAME;
                    if( !SymFromAddr( proc.handle(), addr, nullptr, sym_info ) || !sym_info->Name )
                    {
                        return "";
                    }
                    return sym_info->Name;
                };

                // setup WNF subscription struct
                // save other values we want to print later when we no longer have the "Process"
                wnf_subscription_t subscription{};
                subscription.address = user_sub_addr;
                subscription.subscription = wnf_user_sub;
                subscription.callback_va = get_va( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_va = get_va( proc, ( uintptr_t )wnf_user_sub.CallbackContext );
                subscription.callback_file_name = get_file_name( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_file_name = get_file_name( proc, ( uintptr_t )wnf_user_sub.CallbackContext );
                subscription.callback_symbol_name = get_symbol( proc, ( uintptr_t )wnf_user_sub.Callback );
                subscription.callback_ctx_symbol_name = get_symbol( proc, ( uintptr_t )wnf_user_sub.CallbackContext );

                // push to WNF name struct
                name.subscriptions.push_back( subscription );

                // break out of loop when we reached the back link
                if( user_sub_list_curr == ( uintptr_t )user_sub_list.Blink )
                    break;

                // get next item in linked list
                user_sub_list_curr = proc.read<uintptr_t>( user_sub_list_curr );
            }

            // push WNF name to WNF info
            wnf_info->wnf_names.push_back( name );
        }

        // go to the next node in the tree
        node = node.next();
    }

    return true;
}

void WnfSubscriberScan::dump_table( Process& proc, uint64_t filter_state_name, bool verbose )
{
    if( m_windows11 )
    {
        wnf_info_w11_t wnf_info{};

        if( !build_wnf_info_w11( proc, &wnf_info, filter_state_name ) )
        {
            return;
        }

        if( !wnf_info.show )
            return;

        m_wnf_infos_w11.push_back( wnf_info );
    }
    else
    {
        wnf_info_t wnf_info{};

        if( !build_wnf_info( proc, &wnf_info, filter_state_name ) )
        {
            return;
        }

        if( !wnf_info.show )
            return;

        m_wnf_infos.push_back( wnf_info );
    }
}

// there be dragons below!!!

void WnfSubscriberScan::print( bool verbose )
{
    Table table;

    if( verbose )
    {
        if( m_windows11 )
        {
            for( auto& info : m_wnf_infos_w11 )
            {
                build_print_table_verbose_w11( table, info );
            }
        }
        else
        {
            for( auto& info : m_wnf_infos )
            {
                build_print_table_verbose( table, info );
            }
        }
    }
    else
    {
        table.add_row( { "Process","PID","WNF Name","WNF State", "L", "S", "V", "P", "CS" } )
            .format()
            .font_style( { FontStyle::bold, FontStyle::underline } );

        if( m_windows11 )
        {
            for( auto& info : m_wnf_infos_w11 )
            {
                build_print_table_w11( table, info );

                table.format().hide_border_top();
                table.row( 0 ).format()
                    .show_border_top()
                    .font_color( Color::yellow );
                table.row( 1 ).format().show_border_top();
            }
        }
        else
        {
            for( auto& info : m_wnf_infos )
            {
                build_print_table( table, info );

                table.format().hide_border_top();
                table.row( 0 ).format()
                    .show_border_top()
                    .font_color( Color::yellow );
                table.row( 1 ).format().show_border_top();
            }
        }
    }

    // wow this is slow for large tables
    std::cout << table << std::endl;
}

// no really, everything below is just table printing, nothing of value

void WnfSubscriberScan::build_print_table_w11( Table& table, wnf_info_w11_t& wnf_info )
{
    int idx = 1;

    for( auto& name : wnf_info.wnf_names )
    {
        auto state_name = *( uint64_t* )&name.name.StateName;

        auto state_name_2 = state_name ^ WNF_STATE_KEY;

        auto version = state_name_2 & 0xf;
        auto lifetime = ( state_name_2 >> 4 ) & 0x3;
        auto data_scope = ( state_name_2 >> 6 ) & 0xf;
        auto is_perm = ( state_name_2 >> 10 ) & 0x1;
        auto unique = state_name_2 >> 11;

        table.add_row(
            {
                wnf_info.proc_name,
                std::format( "{:>6}", wnf_info.pid ),
                WnfName::state_to_name( state_name ),
                std::format( "0x{:016X}",state_name ),
                std::format( "{}", lifetime ),
                std::format( "{}", data_scope ),
                std::format( "{}", version ),
                std::format( "{}", is_perm ? "T" : "F" ),
                std::format( "{:X}", name.name.CurrentChangeStamp )
            } );

        if( lifetime == WnfWellKnownStateName )
        {
            table.row( idx ).format().font_color( Color::green ).hide_border_top();
        }
        else if( lifetime == WnfPermanentStateName )
        {
            table.row( idx ).format().font_color( Color::cyan ).hide_border_top();
        }
        else if( lifetime == WnfPersistentStateName )
        {
            table.row( idx ).format().font_color( Color::magenta ).hide_border_top();
        }
        else
        {
            table.row( idx ).format().font_color( Color::white ).hide_border_top();
        }

        idx++;
    }
}

void WnfSubscriberScan::build_print_table( Table& table, wnf_info_t& wnf_info )
{
    int idx = 1;

    for( auto& name : wnf_info.wnf_names )
    {
        auto state_name = *( uint64_t* )&name.name.StateName;

        auto state_name_2 = state_name ^ WNF_STATE_KEY;

        auto version = state_name_2 & 0xf;
        auto lifetime = ( state_name_2 >> 4 ) & 0x3;
        auto data_scope = ( state_name_2 >> 6 ) & 0xf;
        auto is_perm = ( state_name_2 >> 10 ) & 0x1;
        auto unique = state_name_2 >> 11;

        table.add_row(
            {
                wnf_info.proc_name,
                std::format( "{:>6}", wnf_info.pid ),
                WnfName::state_to_name( state_name ),
                std::format( "0x{:016X}",state_name ),
                std::format( "{}", lifetime ),
                std::format( "{}", data_scope ),
                std::format( "{}", version ),
                std::format( "{}", is_perm ? "T" : "F" ),
                std::format( "{:X}", name.name.CurrentChangeStamp )
            } );

        if( lifetime == WnfWellKnownStateName )
        {
            table.row( idx ).format().font_color( Color::green ).hide_border_top();
        }
        else if( lifetime == WnfPermanentStateName )
        {
            table.row( idx ).format().font_color( Color::cyan ).hide_border_top();
        }
        else if( lifetime == WnfPersistentStateName )
        {
            table.row( idx ).format().font_color( Color::magenta ).hide_border_top();
        }
        else
        {
            table.row( idx ).format().font_color( Color::white ).hide_border_top();
        }

        idx++;
    }
}

// I did warn you, it's a mess T_T

void WnfSubscriberScan::build_print_table_verbose_w11( Table& table, wnf_info_w11_t& wnf_info )
{
    table.format()
        .border_color( Color::green )
        .corner_color( Color::green );


    table.add_row( { std::format( "{:>6} : {}", wnf_info.pid, wnf_info.proc_name ) } );

    table.row( 0 ).format()
        .font_color( Color::green );

    Table sub_table;

    // header
    sub_table.add_row( { std::format( "WNF_SUBSCRIPTION_TABLE : 0x{:016X}", wnf_info.address ) } );

    Table sub_table_contents;

    // content
    sub_table_contents.add_row( { "Header.NodeTypeCode", std::format( "{:X}", wnf_info.subscription_table.Header.NodeTypeCode ) } );
    sub_table_contents.add_row( { "Header.NodeByteSize", std::format( "{:X}", wnf_info.subscription_table.Header.NodeByteSize ) } );
    sub_table_contents.add_row( { "NamesTableEntry.Root", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.NamesTableEntry.Root ) } );
    sub_table_contents.add_row( { "NamesTableEntry.Min", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.NamesTableEntry.Min ) } );
    sub_table_contents.add_row( { "SerializationGroupListHead.Flink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupListHead.Flink ) } );
    sub_table_contents.add_row( { "SerializationGroupListHead.Blink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupListHead.Blink ) } );
    sub_table_contents.add_row( { "SerializationGroupLock", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupLock.Ptr ) } );
    sub_table_contents.add_row( { "Unknown1[ 0 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown1[ 0 ] ) } );
    sub_table_contents.add_row( { "Unknown1[ 1 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown1[ 1 ] ) } );
    sub_table_contents.add_row( { "SubscribedEventSet", std::format( "{:X}", wnf_info.subscription_table.SubscribedEventSet ) } );
    sub_table_contents.add_row( { "Unknown2[ 0 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown2[ 0 ] ) } );
    sub_table_contents.add_row( { "Unknown2[ 1 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown2[ 1 ] ) } );
    sub_table_contents.add_row( { "Timer", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.Timer ) } );
    sub_table_contents.add_row( { "TimerDueTime", std::format( "{:X}", wnf_info.subscription_table.TimerDueTime ) } );

    // this tabulate is annoying to format to how you want to...

    sub_table_contents.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : sub_table_contents.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : sub_table_contents.column( 1 ) )
        cell.format().hide_border_right();

    sub_table.add_row( { sub_table_contents } );

    for( auto& wnf_name : wnf_info.wnf_names )
    {
        build_print_table_names_verbose_w11( sub_table, wnf_name );
    }

    table.add_row( { sub_table } );
}

void WnfSubscriberScan::build_print_table_names_verbose_w11( Table& table, wnf_name_w11_t& wnf_name )
{
    // I can only apologise

    // statename is a struct, we need to derefence it as an int64
    auto state_name = *( uint64_t* )&wnf_name.name.StateName;
    auto state_name_2 = state_name ^ WNF_STATE_KEY;

    auto version = state_name_2 & 0xf;
    auto lifetime = ( state_name_2 >> 4 ) & 0x3;
    auto data_scope = ( state_name_2 >> 6 ) & 0xf;
    auto is_perm = ( state_name_2 >> 10 ) & 0x1;
    auto unique = state_name_2 >> 11;

    // lambda to pretty print the Data Scope
    auto data_scope_name = []( uint64_t data_scope ) -> std::string
    {
        switch( data_scope )
        {
        case WnfDataScopeSystem:
            return "System";
        case WnfDataScopeSession:
            return "Session";
        case WnfDataScopeUser:
            return "User";
        case WnfDataScopeProcess:
            return "Process";
        case WnfDataScopeMachine:
            return "Machine";
        default:
            return "Unknown";
        }
    };

    // lambda to pretty print Lifetime
    auto lifetime_name = []( uint64_t lifetime ) -> std::string
    {
        switch( lifetime )
        {
        case WnfWellKnownStateName:
            return "WellKnown";
        case WnfPermanentStateName:
            return "Permanent";
        case WnfPersistentStateName:
            return "Persistent";
        case WnfTemporaryStateName:
            return "Temporary";
        default:
            return "Unknown";
        }
    };

    Table name_table;

    // header
    name_table.add_row( { std::format( "WNF_NAME_SUBSCRIPTION : 0x{:016X}", wnf_name.address ) } );

    Table name_table_contents;

    name_table_contents.add_row( { "Name", std::format( "{}", WnfName::state_to_name( state_name ) ) } );
    name_table_contents.add_row( { "StateName", std::format( "0x{:016X}", state_name ) } );
    name_table_contents.add_row( { "UnXOR'd StateName", std::format( "0x{:016X}", state_name_2 ) } );
    name_table_contents.add_row( { "Version", std::format( "{:X}", version ) } );
    name_table_contents.add_row( { "NameLifetime", std::format( "{:X} : {}", lifetime, lifetime_name( lifetime ) ) } );
    name_table_contents.add_row( { "DataScope", std::format( "{:X} : {}", data_scope, data_scope_name( data_scope ) ) } );
    name_table_contents.add_row( { "PermanentData", std::format( "{}", is_perm ? "True" : "False" ) } );
    name_table_contents.add_row( { "Unique", std::format( "{:X}", unique ) } );
    name_table_contents.add_row( { "Header.NodeTypeCode", std::format( "{:X}", wnf_name.name.Header.NodeTypeCode ) } );
    name_table_contents.add_row( { "Header.NodeByteSize", std::format( "{:X}", wnf_name.name.Header.NodeByteSize ) } );
    name_table_contents.add_row( { "NamesTableEntry.Left", std::format( "{:X}", ( uintptr_t )wnf_name.name.NamesTableEntry.Left ) } );
    name_table_contents.add_row( { "NamesTableEntry.Right", std::format( "{:X}", ( uintptr_t )wnf_name.name.NamesTableEntry.Right ) } );
    name_table_contents.add_row( { "NamesTableEntry.ParentValue", std::format( "{:X}", wnf_name.name.NamesTableEntry.ParentValue ) } );
    name_table_contents.add_row( { "SubscriptionId", std::format( "{:X}", wnf_name.name.SubscriptionId ) } );
    name_table_contents.add_row( { "CurrentChangeStamp", std::format( "{:X}", wnf_name.name.CurrentChangeStamp ) } );
    name_table_contents.add_row( { "NormalDeliverySubscriptions", std::format( "{:X}", wnf_name.name.NormalDeliverySubscriptions ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 0 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 0 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 1 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 1 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 2 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 2 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 3 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 3 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 4 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 4 ] ) } );
    name_table_contents.add_row( { "DeliveryState", std::format( "{:X}", wnf_name.name.DeliveryState ) } );
    name_table_contents.add_row( { "ReliableRetryTime", std::format( "{:X}", wnf_name.name.ReliableRetryTime ) } );

    // this tabulate is annoying to format to how you want to...

    name_table_contents.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : name_table_contents.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : name_table_contents.column( 1 ) )
        cell.format().hide_border_right();

    name_table.add_row( { name_table_contents } );

    for( auto& wnf_sub : wnf_name.subscriptions )
    {
        build_print_table_subscriptions_verbose( name_table, wnf_sub );
    }

    table.add_row( { name_table } );
}

void WnfSubscriberScan::build_print_table_verbose( Table& table, wnf_info_t& wnf_info )
{
    table.format()
        .border_color( Color::green )
        .corner_color( Color::green );


    table.add_row( { std::format( "{:>6} : {}", wnf_info.pid, wnf_info.proc_name ) } );

    table.row( 0 ).format()
        .font_color( Color::green );

    Table sub_table;

    // header
    sub_table.add_row( { std::format( "WNF_SUBSCRIPTION_TABLE : 0x{:016X}", wnf_info.address ) } );

    Table sub_table_contents;

    // content
    sub_table_contents.add_row( { "Header.NodeTypeCode", std::format( "{:X}", wnf_info.subscription_table.Header.NodeTypeCode ) } );
    sub_table_contents.add_row( { "Header.NodeByteSize", std::format( "{:X}", wnf_info.subscription_table.Header.NodeByteSize ) } );
    sub_table_contents.add_row( { "NamesTableEntry.Flink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.NamesTableEntry.Flink ) } );
    sub_table_contents.add_row( { "NamesTableEntry.Blink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.NamesTableEntry.Blink ) } );
    sub_table_contents.add_row( { "SerializationGroupListHead.Flink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupListHead.Flink ) } );
    sub_table_contents.add_row( { "SerializationGroupListHead.Blink", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupListHead.Blink ) } );
    sub_table_contents.add_row( { "SerializationGroupLock", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.SerializationGroupLock.Ptr ) } );
    sub_table_contents.add_row( { "Unknown1[ 0 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown1[ 0 ] ) } );
    sub_table_contents.add_row( { "Unknown1[ 1 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown1[ 1 ] ) } );
    sub_table_contents.add_row( { "SubscribedEventSet", std::format( "{:X}", wnf_info.subscription_table.SubscribedEventSet ) } );
    sub_table_contents.add_row( { "Unknown2[ 0 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown2[ 0 ] ) } );
    sub_table_contents.add_row( { "Unknown2[ 1 ]", std::format( "{:X}", wnf_info.subscription_table.Unknown2[ 1 ] ) } );
    sub_table_contents.add_row( { "Timer", std::format( "{:X}", ( uintptr_t )wnf_info.subscription_table.Timer ) } );
    sub_table_contents.add_row( { "TimerDueTime", std::format( "{:X}", wnf_info.subscription_table.TimerDueTime ) } );

    // this tabulate is annoying to format to how you want to... really annoying

    sub_table_contents.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : sub_table_contents.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : sub_table_contents.column( 1 ) )
        cell.format().hide_border_right();

    sub_table.add_row( { sub_table_contents } );

    for( auto& wnf_name : wnf_info.wnf_names )
    {
        build_print_table_names_verbose( sub_table, wnf_name );
    }

    table.add_row( { sub_table } );
}

void WnfSubscriberScan::build_print_table_names_verbose( Table& table, wnf_name_t& wnf_name )
{
    // I can only apologise

    // statename is a struct, we need to dereference it as an int64
    auto state_name = *( uint64_t* )&wnf_name.name.StateName;
    auto state_name_2 = state_name ^ WNF_STATE_KEY;

    auto version = state_name_2 & 0xf;
    auto lifetime = ( state_name_2 >> 4 ) & 0x3;
    auto data_scope = ( state_name_2 >> 6 ) & 0xf;
    auto is_perm = ( state_name_2 >> 10 ) & 0x1;
    auto unique = state_name_2 >> 11;

    // lambda to pretty print the Data Scope
    auto data_scope_name = []( uint64_t data_scope ) -> std::string
    {
        switch( data_scope )
        {
        case WnfDataScopeSystem:
            return "System";
        case WnfDataScopeSession:
            return "Session";
        case WnfDataScopeUser:
            return "User";
        case WnfDataScopeProcess:
            return "Process";
        case WnfDataScopeMachine:
            return "Machine";
        default:
            return "Unknown";
        }
    };

    // lambda to pretty print Lifetime
    auto lifetime_name = []( uint64_t lifetime ) -> std::string
    {
        switch( lifetime )
        {
        case WnfWellKnownStateName:
            return "WellKnown";
        case WnfPermanentStateName:
            return "Permanent";
        case WnfPersistentStateName:
            return "Persistent";
        case WnfTemporaryStateName:
            return "Temporary";
        default:
            return "Unknown";
        }
    };

    Table name_table;

    // header
    name_table.add_row( { std::format( "WNF_NAME_SUBSCRIPTION : 0x{:016X}", wnf_name.address ) } );

    Table name_table_contents;

    name_table_contents.add_row( { "Name", std::format( "{}", WnfName::state_to_name( state_name ) ) } );
    name_table_contents.add_row( { "StateName", std::format( "0x{:016X}", state_name ) } );
    name_table_contents.add_row( { "UnXOR'd StateName", std::format( "0x{:016X}", state_name_2 ) } );
    name_table_contents.add_row( { "Version", std::format( "{:X}", version ) } );
    name_table_contents.add_row( { "NameLifetime", std::format( "{:X} : {}", lifetime, lifetime_name( lifetime ) ) } );
    name_table_contents.add_row( { "DataScope", std::format( "{:X} : {}", data_scope, data_scope_name( data_scope ) ) } );
    name_table_contents.add_row( { "PermanentData", std::format( "{}", is_perm ? "True" : "False" ) } );
    name_table_contents.add_row( { "Unique", std::format( "{:X}", unique ) } );
    name_table_contents.add_row( { "Header.NodeTypeCode", std::format( "{:X}", wnf_name.name.Header.NodeTypeCode ) } );
    name_table_contents.add_row( { "Header.NodeByteSize", std::format( "{:X}", wnf_name.name.Header.NodeByteSize ) } );
    name_table_contents.add_row( { "NamesTableEntry.Flink", std::format( "{:X}", ( uintptr_t )wnf_name.name.NamesTableEntry.Flink ) } );
    name_table_contents.add_row( { "NamesTableEntry.Blink", std::format( "{:X}", ( uintptr_t )wnf_name.name.NamesTableEntry.Blink ) } );
    name_table_contents.add_row( { "SubscriptionId", std::format( "{:X}", wnf_name.name.SubscriptionId ) } );
    name_table_contents.add_row( { "CurrentChangeStamp", std::format( "{:X}", wnf_name.name.CurrentChangeStamp ) } );
    name_table_contents.add_row( { "NormalDeliverySubscriptions", std::format( "{:X}", wnf_name.name.NormalDeliverySubscriptions ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 0 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 0 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 1 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 1 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 2 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 2 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 3 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 3 ] ) } );
    name_table_contents.add_row( { "NotificationTypeCount[ 4 ]", std::format( "{:X}", wnf_name.name.NotificationTypeCount[ 4 ] ) } );
    name_table_contents.add_row( { "DeliveryState", std::format( "{:X}", wnf_name.name.DeliveryState ) } );
    name_table_contents.add_row( { "ReliableRetryTime", std::format( "{:X}", wnf_name.name.ReliableRetryTime ) } );

    // this tabulate is annoying to format to how you want to... T_T

    name_table_contents.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : name_table_contents.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : name_table_contents.column( 1 ) )
        cell.format().hide_border_right();

    name_table.add_row( { name_table_contents } );

    for( auto& wnf_sub : wnf_name.subscriptions )
    {
        build_print_table_subscriptions_verbose( name_table, wnf_sub );
    }

    table.add_row( { name_table } );
}

void WnfSubscriberScan::build_print_table_subscriptions_verbose( Table& table, wnf_subscription_t& wnf_sub )
{
    Table sub_table;

    // header
    sub_table.add_row( { std::format( "WNF_USER_SUBSCRIPTION : 0x{:016X}", wnf_sub.address ) } );

    Table sub_table_contents;

    // Callback sub table

    sub_table_contents.add_row( { "Callback" } );

    Table sub_table_contents_callback;

    sub_table_contents_callback.add_row( { "Address", std::format( "0x{:016X}", ( uintptr_t )wnf_sub.subscription.Callback ) } );
    sub_table_contents_callback.add_row( { "Virtual Address", std::format( "0x{:016X}", wnf_sub.callback_va ) } );
    sub_table_contents_callback.add_row( { "File", std::format( "{}", wnf_sub.callback_file_name ) } );
    sub_table_contents_callback.add_row( { "Symbol (Unreliable)", std::format( "{}", wnf_sub.callback_symbol_name ) } );

    // this tabulate is annoying to format to how you want to... TT_TT

    sub_table_contents_callback.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : sub_table_contents_callback.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : sub_table_contents_callback.column( 1 ) )
        cell.format().hide_border_right();

    sub_table_contents.add_row( { sub_table_contents_callback } );

    // Callback Context sub table

    sub_table_contents.add_row( { "Callback Context" } );

    Table sub_table_contents_callback_ctx;

    sub_table_contents_callback_ctx.add_row( { "Address", std::format( "0x{:016X}", ( uintptr_t )wnf_sub.subscription.CallbackContext ) } );
    sub_table_contents_callback_ctx.add_row( { "Virtual Address", std::format( "0x{:016X}", wnf_sub.callback_ctx_va ) } );
    sub_table_contents_callback_ctx.add_row( { "File", std::format( "{}", wnf_sub.callback_ctx_file_name ) } );
    sub_table_contents_callback_ctx.add_row( { "Symbol (Unreliable)", std::format( "{}", wnf_sub.callback_ctx_symbol_name ) } );

    // this tabulate is annoying to format to how you want to... TTT_TTT

    sub_table_contents_callback_ctx.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : sub_table_contents_callback_ctx.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : sub_table_contents_callback_ctx.column( 1 ) )
        cell.format().hide_border_right();

    sub_table_contents.add_row( { sub_table_contents_callback_ctx } );

    // Other Info sub table

    sub_table_contents.add_row( { "Other Info" } );

    Table sub_table_contents_other;

    sub_table_contents_other.add_row( { "SubProcessTag", std::format( "{:X}", wnf_sub.subscription.SubProcessTag ) } );
    sub_table_contents_other.add_row( { "CurrentChangeStamp", std::format( "{:X}", wnf_sub.subscription.CurrentChangeStamp ) } );
    sub_table_contents_other.add_row( { "DeliveryOptions", std::format( "{:X}", wnf_sub.subscription.DeliveryOptions ) } );
    sub_table_contents_other.add_row( { "UserSubscriptionCount", std::format( "{:X}", wnf_sub.subscription.UserSubscriptionCount ) } );

    // this tabulate is annoying to format to how you want to... I cry...

    sub_table_contents_other.format()
        .hide_border_top()
        .hide_border_bottom();

    for( auto& cell : sub_table_contents_other.column( 0 ) )
        cell.format().hide_border_left();

    for( auto& cell : sub_table_contents_other.column( 1 ) )
        cell.format().hide_border_right();

    sub_table_contents.add_row( { sub_table_contents_other } );

    sub_table.add_row( { sub_table_contents } );

    table.add_row( { sub_table } );
}

// if you really looked at the table printing code then all I can do is laugh xD