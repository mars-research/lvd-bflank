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

bool
access_to_gdtr_or_idtr_handler::handle(vcpu *vcpu)
{

    // Good resource
    //  http://ref.x86asm.net/
    //  http://www.plantation-productions.com/Webster/www.artofasm.com/Windows/HTML/ISA.html
    //
    //   12657d:       0f 01 10                lgdt   (%rax)
    //   10701e:       0f 01 15 28 00 10 00    lgdt   0x100028(%rip)        # 20704d <__end+0x4404d>
    // Linux
    // 
    // ffffffff81000172:       0f 01 15 87 ae c0 00    lgdt   0xc0ae87(%rip)        # ffffffff81c0b000 <early_gdt_descr>
    //                             00 010 101 
    //                             ^   ^   
    //                             |   |
    //                             |   | - gdt (2)
    //                             |- 00 - rip   
    // ffffffff81029f36:       0f 01 55 f6             lgdt   -0xa(%rbp)
    //                             01 010 101
    //                             ^   ^   ^
    //                             |   |   |- rbp (101)
    //                             |   | - gdt (2)
    //                             |- 01 - register   

    // ffffffff8102a9ae:       0f 01 55 c0             lgdt   -0x40(%rbp)
    // ffffffff81041640:       0f 01 55 ce             lgdt   -0x32(%rbp)
    // ffffffff815e306d:       0f 01 90 15 01 00 00    lgdt   0x115(%rax)
    //                            10 010 000
    //                             ^   ^  ^ 
    //                             |   |  | - eax (000)
    //                             |   | - gdt (2)
    //                             |- 01 - register
    //
    // ffffffff8102a85b:       0f 01 1d d6 77 bf 00    lidt   0xbf77d6(%rip)        # ffffffff81c22038 <idt_descr>
    //                             00 011 101  
    // ffffffff8102a88f:       0f 01 1d a2 77 bf 00    lidt   0xbf77a2(%rip)        # ffffffff81c22038 <idt_descr>
    // ffffffff8102a9be:       0f 01 1d 73 76 bf 00    lidt   0xbf7673(%rip)        # ffffffff81c22038 <idt_descr>
    // ffffffff81037cf1:       0f 01 1d 98 06 7d 00    lidt   0x7d0698(%rip)        # ffffffff81808390 <no_idt>
    // ffffffff81041644:       0f 01 5d ce             lidt   -0x32(%rbp)
    // ffffffff815e12fe:       0f 01 1d 3c 0b 91 00    lidt   0x910b3c(%rip)        # ffffffff81ef1e41 <saved_context+0x121>
    // ffffffff81d06346:       0f 01 1d eb bc f1 ff    lidt   -0xe4315(%rip)        # ffffffff81c22038 <idt_descr>
    // ffffffff81d0d393:       0f 01 1d 9e 4c f1 ff    lidt   -0xeb362(%rip)        # ffffffff81c22038 <idt_descr>
    //
    // ffffffff815e1129:       0f 01 0d 11 0d 91 00    sidt   0x910d11(%rip)        # ffffffff81ef1e41 <saved_context+0x121>
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
