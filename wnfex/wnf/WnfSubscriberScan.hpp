#pragma once
#include <stdint.h>
#include <Windows.h>
#include <vector>
#include <string>

#include "../util/Process.hpp"
#include "../wnf/wnf_structs.hpp"
#include "../wnf/wnf_names.hpp"
// idk, slow but easy to use
#include "../util/tabulate.hpp"

using namespace tabulate;

class WnfSubscriberScan
{
    struct wnf_subscription_t
    {
        uint64_t address;
        uint64_t callback_va;
        uint64_t callback_ctx_va;
        std::string callback_file_name;
        std::string callback_ctx_file_name;
        std::string callback_symbol_name;
        std::string callback_ctx_symbol_name;
        WNF_USER_SUBSCRIPTION subscription;
    };

    struct wnf_name_t
    {
        uint64_t address;
        WNF_NAME_SUBSCRIPTION name;
        std::vector<wnf_subscription_t> subscriptions;
    };

    struct wnf_info_t
    {
        bool show;
        std::string proc_name;
        uint32_t pid;
        uint64_t address;
        WNF_SUBSCRIPTION_TABLE subscription_table;
        std::vector<wnf_name_t> wnf_names;
    };

    struct wnf_name_w11_t
    {
        uint64_t address;
        WNF_NAME_SUBSCRIPTION_W11 name;
        std::vector<wnf_subscription_t> subscriptions;
    };

    struct wnf_info_w11_t
    {
        bool show;
        std::string proc_name;
        uint32_t pid;
        uint64_t address;
        WNF_SUBSCRIPTION_TABLE_W11 subscription_table;
        std::vector<wnf_name_w11_t> wnf_names;
    };

public:
    WnfSubscriberScan() : m_wnf_table_offset(0), m_windows11(false) {};
    ~WnfSubscriberScan() {};

    bool init();
    void dump( const std::string& proc_name, uint64_t filter_state_name = 0, bool verbose = false );
    void dump( uint32_t pid, uint64_t filter_state_name = 0, bool verbose = false );
    void dump( const std::vector<process_t>& processes, uint64_t filter_state_name = 0, bool verbose = false );

private:
    bool find_subscriber_table();
    uintptr_t get_table_addr( Process& proc );

    bool get_table( Process& proc, uintptr_t table_addr, WNF_SUBSCRIPTION_TABLE& table );
    bool get_table_w11( Process& proc, uintptr_t table_addr, WNF_SUBSCRIPTION_TABLE_W11& table );

    bool build_wnf_info( Process& proc, wnf_info_t* wnf_info, uint64_t filter_state_name );
    bool build_wnf_info_w11( Process& proc, wnf_info_w11_t* wnf_info, uint64_t filter_state_name );

    void dump_table( Process& proc, uint64_t filter_state_name, bool verbose );

    void print( bool verbose );

    void build_print_table_w11( Table& table, wnf_info_w11_t& wnf_info );
    void build_print_table( Table& table, wnf_info_t& wnf_info );

    void build_print_table_verbose_w11( Table& table, wnf_info_w11_t& wnf_info );
    void build_print_table_names_verbose_w11( Table& table, wnf_name_w11_t& wnf_name );

    void build_print_table_verbose( Table& table, wnf_info_t& wnf_info );
    void build_print_table_names_verbose( Table& table, wnf_name_t& wnf_name );

    void build_print_table_subscriptions_verbose( Table& table, wnf_subscription_t& wnf_sub );
    
private:
    uintptr_t m_wnf_table_offset;
    bool m_windows11;
    std::vector<wnf_info_t> m_wnf_infos;
    std::vector<wnf_info_w11_t> m_wnf_infos_w11;
};