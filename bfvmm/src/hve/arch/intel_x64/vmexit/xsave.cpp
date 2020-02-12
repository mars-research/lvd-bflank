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


xsave_handler::xsave_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::xsaves,
        ::handler_delegate_t::create<xsave_handler, &xsave_handler::handle_xsave>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::xrstors,
        ::handler_delegate_t::create<xsave_handler, &xsave_handler::handle_xrstor>(this)
    );

}

// -----------------------------------------------------------------------------
// Add Handler
// -----------------------------------------------------------------------------
void
xsave_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------


uint64_t xsave_base(vcpu *vcpu) {
    
   using namespace ::intel_x64::vmcs;

   if (vm_exit_instruction_information::xsaves::base_reg_invalid::is_enabled()) {
        return 0;
    }

    switch (vm_exit_instruction_information::xsaves::index_reg::get()) {
        case vm_exit_instruction_information::xsaves::index_reg::rax: 
             return vcpu->rax(); 

        case vm_exit_instruction_information::xsaves::index_reg::rcx: 
             return vcpu->rcx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rdx: 
             return vcpu->rdx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rbx: 
             return vcpu->rbx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rsp: 
             return vcpu->rsp(); 

        case vm_exit_instruction_information::xsaves::index_reg::rbp: 
             return vcpu->rbp(); 

        case vm_exit_instruction_information::xsaves::index_reg::rsi: 
             return vcpu->rsi(); 

        case vm_exit_instruction_information::xsaves::index_reg::rdi: 
             return vcpu->rdi(); 

        case vm_exit_instruction_information::xsaves::index_reg::r8: 
             return vcpu->r08(); 

        case vm_exit_instruction_information::xsaves::index_reg::r9: 
             return vcpu->r09(); 

        case vm_exit_instruction_information::xsaves::index_reg::r10: 
             return vcpu->r10(); 

        case vm_exit_instruction_information::xsaves::index_reg::r11: 
             return vcpu->r11(); 

        case vm_exit_instruction_information::xsaves::index_reg::r12: 
             return vcpu->r12(); 

        case vm_exit_instruction_information::xsaves::index_reg::r13: 
             return vcpu->r13(); 

        case vm_exit_instruction_information::xsaves::index_reg::r14: 
             return vcpu->r14(); 

        case vm_exit_instruction_information::xsaves::index_reg::r15: 
             return vcpu->r15(); 

        default:
             return 0;
    };

    return 0; 


};

uint64_t xsave_index(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    if (vm_exit_instruction_information::xsaves::index_reg_invalid::is_enabled()) {
        return 0;
    }

    switch (vm_exit_instruction_information::xsaves::index_reg::get()) {
        case vm_exit_instruction_information::xsaves::index_reg::rax: 
             return vcpu->rax(); 

        case vm_exit_instruction_information::xsaves::index_reg::rcx: 
             return vcpu->rcx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rdx: 
             return vcpu->rdx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rbx: 
             return vcpu->rbx(); 

        case vm_exit_instruction_information::xsaves::index_reg::rsp: 
             return vcpu->rsp(); 

        case vm_exit_instruction_information::xsaves::index_reg::rbp: 
             return vcpu->rbp(); 

        case vm_exit_instruction_information::xsaves::index_reg::rsi: 
             return vcpu->rsi(); 

        case vm_exit_instruction_information::xsaves::index_reg::rdi: 
             return vcpu->rdi(); 

        case vm_exit_instruction_information::xsaves::index_reg::r8: 
             return vcpu->r08(); 

        case vm_exit_instruction_information::xsaves::index_reg::r9: 
             return vcpu->r09(); 

        case vm_exit_instruction_information::xsaves::index_reg::r10: 
             return vcpu->r10(); 

        case vm_exit_instruction_information::xsaves::index_reg::r11: 
             return vcpu->r11(); 

        case vm_exit_instruction_information::xsaves::index_reg::r12: 
             return vcpu->r12(); 

        case vm_exit_instruction_information::xsaves::index_reg::r13: 
             return vcpu->r13(); 

        case vm_exit_instruction_information::xsaves::index_reg::r14: 
             return vcpu->r14(); 

        case vm_exit_instruction_information::xsaves::index_reg::r15: 
             return vcpu->r15(); 

        default:
             return 0;
    };

    return 0; 

};

uint64_t xsave_scale(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    switch (vm_exit_instruction_information::xsaves::scaling::get()) {
        case vm_exit_instruction_information::xsaves::scaling::no_scaling: 
             return 1; 

        case vm_exit_instruction_information::xsaves::scaling::scale_by_2: 
             return 2; 

        case vm_exit_instruction_information::xsaves::scaling::scale_by_4: 
             return 4; 

        case vm_exit_instruction_information::xsaves::scaling::scale_by_8: 
             return 8; 

        default:
             return 1;
    };

    return 1; 

};

uint64_t xsave_dest_address(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    // 27.2.1 Basic VM-Exit Information
    // (under table 27-2
    auto displacement = vmcs_n::exit_qualification::xsaves::get(); 

    if (vm_exit_instruction_information::xsaves::index_reg_invalid::is_enabled() &&
        vm_exit_instruction_information::xsaves::base_reg_invalid::is_enabled()) {
        
        bfdebug_subnhex(0, "RIP relative displacement", displacement);
        return displacement;
    }

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "base", xsave_base(vcpu), msg);
        bfdebug_subnhex(0, "index", xsave_index(vcpu), msg);
        bfdebug_subnhex(0, "scale", xsave_scale(vcpu), msg);
        bfdebug_subnhex(0, "displacement", displacement, msg);
    });

    return xsave_base(vcpu) + xsave_index(vcpu) * xsave_scale(vcpu) + displacement;            
};


bool handle_xsave(vcpu *vcpu) {

    uint64_t address = xsave_dest_address(vcpu); 
    
    /* patch the xsave area size */
    auto map = vcpu->map_gva_4k<uint8_t>(address, 0);

    // Read xsave registers
    //uint64_t base = vcpu->idt_base(); 

    //*((uint64_t*)&map.get()[2]) = base; 

    return true;
};


bool handle_xrstor(vcpu *vcpu) {

    uint64_t address = xsave_dest_address(vcpu); 
    
    auto map = vcpu->map_gva_4k<uint8_t>(address, 10);

    //uint64_t base = *((uint64_t*)&map.get()[2]); 
    
    //vcpu->set_idt_limit(limit);

    return true;
};

bool
xsave_handler::handle_xsave(vcpu *vcpu)
{

    bfdebug_subnhex(0, "xsave at", vcpu->rip());
    handle_xsave(vcpu);

    return vcpu->advance();
}

bool
xsave_handler::handle_xrstor(vcpu *vcpu)
{

    bfdebug_subnhex(0, "xrstor at", vcpu->rip());
    handle_xrstor(vcpu);

    return vcpu->advance();
}



}
