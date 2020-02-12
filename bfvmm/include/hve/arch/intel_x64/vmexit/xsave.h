//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VMEXIT_XSAVE_INTEL_X64_H
#define VMEXIT_XSAVE_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

///
/// Provides an interface for registering handlers for xsave exits.
///
class EXPORT_HVE xsave_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by control_register::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Value (in/out)
        ///
        /// For in, the value written by the guest.
        /// default: edx:eax
        ///
        /// For out, the value written to xcr0
        /// default: edx:eax
        ///
        uint64_t val;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state with the value
        /// from the default.
        ///
        /// default: false
        ///
        bool ignore_write;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
        ///
        bool ignore_advance;
    };


    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(vcpu *, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this xsave handler
    ///
    xsave_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xsave_handler() = default;

public:

    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

    /// @cond

    bool handle_xsave(vcpu *vcpu);

    bool handle_xrstor(vcpu *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    xsave_handler(descriptor_handler &&)/* = default*/;
    xsave_handler &operator=(descriptor_handler &&)/* = default*/;

    xsave_handler(const descriptor_handler &) = delete;
    xsave_handler &operator=(const descriptor_handler &) = delete;

    /// @endcond
};

using xsave_handler_delegate_t = xsave_handler::handler_delegate_t;

}

#endif
