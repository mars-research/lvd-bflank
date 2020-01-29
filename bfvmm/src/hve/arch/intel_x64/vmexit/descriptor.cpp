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

// TIDY_EXCLUSION=-performance-move-const-arg
//
// Reason:
//     Tidy complains that the std::move(d)'s used in the add_handler calls
//     have no effect. Removing std::move however results in a compiler error
//     saying the lvalue (d) can't bind to the rvalue.
//

#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{

access_to_gdtr_or_idtr_handler::access_to_gdtr_or_idtr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::access_to_gdtr_or_idtr,
        ::handler_delegate_t::create<access_to_gdtr_or_idtr_handler, &access_to_gdtr_or_idtr_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler
// -----------------------------------------------------------------------------
void
access_to_gdtr_or_idtr_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

//
// Start reading under Table 27-8, and then go to Tables 27-10 and 27-11
//
//

bool
access_to_gdtr_or_idtr_handler::handle(vcpu *vcpu)
{

    //
    auto map = m_vcpu->map_gva_4k<uint8_t>(
                    vcpu->rip(),
                    
                    );

    info.val = map.get()[0] & 0x00000000000000FFULL;


    if (!info.ignore_write) {
        ::intel_x64::xcr0::set(info.val);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}



}
