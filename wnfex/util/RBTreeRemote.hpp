#pragma once
#include "Process.hpp"

// allows block reads, and it's tidy
struct rbnode_t
{
    uintptr_t left;
    uintptr_t right;
    uintptr_t parent_value;

    uintptr_t parent()
    {
        constexpr uintptr_t parent_ptr_mask = 3;
        return parent_value & ~parent_ptr_mask;
    }
};

class RBNodeRemote
{
public:
    // read the node on entry
    RBNodeRemote( Process& proc, uintptr_t address )
        : m_proc( proc ), m_null( false ), m_addr( address )
    {
        m_node = proc.read<rbnode_t>( address );

        if( m_node.left == 0
            && m_node.right == 0
            && m_node.parent() == 0 )
        {
            m_null = true;
        }
    };

    RBNodeRemote left_most()
    {
        auto node = *this;

        // keep going left until left it null
        // slippery slide
        while( node.m_node.left )
        {
            node = node.left();
        }

        return node;
    }

    // need to start from the first node
    RBNodeRemote next()
    {
        auto node = *this;

        // if there's a right follow it down to it's left most node
        if( node.m_node.right )
        {
            return right().left_most();
        }

        // iterate up the tree until the next right node
        while( node.m_node.parent()
               && node.m_addr == node.parent().m_node.right )
        {
            node = node.parent();
        }

        return node.parent();
    }

    bool is_null() const
    {
        return m_null;
    }

    uintptr_t get_address() const
    {
        return m_addr;
    }

private:
    RBNodeRemote left()
    {
        return RBNodeRemote( m_proc, m_node.left );
    }

    RBNodeRemote right()
    {
        return RBNodeRemote( m_proc, m_node.right );
    }

    RBNodeRemote parent()
    {
        return RBNodeRemote( m_proc, m_node.parent() );
    }

private:
    Process m_proc;
    rbnode_t m_node;
    uintptr_t m_addr;
    bool m_null;
};

class RBTreeRemote
{
public:
    RBTreeRemote( Process& proc, uintptr_t root )
        : m_proc( proc ), m_root( root )
    {};

    // grab the left most node as it's the first in the tree
    RBNodeRemote first()
    {
        if( m_root == 0 )
            return RBNodeRemote( m_proc, 0 );

        auto root = RBNodeRemote( m_proc, m_root );

        return root.left_most();
    }

private:
    Process m_proc;
    uintptr_t m_root;
};