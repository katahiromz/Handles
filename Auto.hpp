// Auto.hpp
// Copyright (C) 2020 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
// This file is public domain software.

#pragma once

#include <cstdlib>

struct AutoCloseHandle
{
    HANDLE m_h;

    AutoCloseHandle(HANDLE h) : m_h(h)
    {
    }

    ~AutoCloseHandle()
    {
        CloseHandle(m_h);
    }

    operator HANDLE()
    {
        return m_h;
    }

    HANDLE* operator&()
    {
        return &m_h;
    }
};

template <typename T>
struct AutoFree
{
    T *m_p;
    size_t m_cb;

    AutoFree(size_t cb) : m_p(reinterpret_cast<T *>(std::malloc(cb))), m_cb(cb)
    {
    }

    ~AutoFree()
    {
        std::free(m_p);
    }

    operator T*()
    {
        return m_p;
    }

    T *operator->()
    {
        return m_p;
    }

    size_t size() const
    {
        return m_cb;
    }

    T *resize(size_t cb)
    {
        m_p = reinterpret_cast<T *>(std::realloc(m_p, cb));
        m_cb = cb;
        return m_p;
    }
};
