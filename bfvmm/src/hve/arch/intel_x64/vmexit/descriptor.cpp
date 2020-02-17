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


descriptor_handler::descriptor_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::access_to_gdtr_or_idtr,
        ::handler_delegate_t::create<descriptor_handler, &descriptor_handler::handle_gdtr_or_idtr>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::access_to_ldtr_or_tr,
        ::handler_delegate_t::create<descriptor_handler, &descriptor_handler::handle_ldtr_or_tr>(this)
    );

}

// -----------------------------------------------------------------------------
// Add Handler
// -----------------------------------------------------------------------------
void
descriptor_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

//
// Start reading under Table 27-8, and then go to Tables 27-10 and 27-11
//
//
//   12657d:       0f 01 10                lgdt   (%rax)
//   10701e:       0f 01 15 28 00 10 00    lgdt   0x100028(%rip)        # 20704d <__end+0x4404d>
// Linux
// ffffffff81000172:       0f 01 15 87 ae c0 00    lgdt   0xc0ae87(%rip)        # ffffffff81c0b000 <early_gdt_descr>
// ffffffff81029f36:       0f 01 55 f6             lgdt   -0xa(%rbp)
// ffffffff8102a9ae:       0f 01 55 c0             lgdt   -0x40(%rbp)
// ffffffff81041640:       0f 01 55 ce             lgdt   -0x32(%rbp)
// ffffffff815e306d:       0f 01 90 15 01 00 00    lgdt   0x115(%rax)
// ffffffff8102a85b:       0f 01 1d d6 77 bf 00    lidt   0xbf77d6(%rip)        # ffffffff81c22038 <idt_descr>
// ffffffff8102a88f:       0f 01 1d a2 77 bf 00    lidt   0xbf77a2(%rip)        # ffffffff81c22038 <idt_descr>
// ffffffff8102a9be:       0f 01 1d 73 76 bf 00    lidt   0xbf7673(%rip)        # ffffffff81c22038 <idt_descr>
// ffffffff81037cf1:       0f 01 1d 98 06 7d 00    lidt   0x7d0698(%rip)        # ffffffff81808390 <no_idt>
// ffffffff81041644:       0f 01 5d ce             lidt   -0x32(%rbp)
// ffffffff815e12fe:       0f 01 1d 3c 0b 91 00    lidt   0x910b3c(%rip)        # ffffffff81ef1e41 <saved_context+0x121>
// ffffffff81d06346:       0f 01 1d eb bc f1 ff    lidt   -0xe4315(%rip)        # ffffffff81c22038 <idt_descr>
// ffffffff81d0d393:       0f 01 1d 9e 4c f1 ff    lidt   -0xeb362(%rip)        # ffffffff81c22038 <idt_descr>
// ffffffff815e1129:       0f 01 0d 11 0d 91 00    sidt   0x910d11(%rip)        # ffffffff81ef1e41 <saved_context+0x121>
//

uint64_t base(vcpu *vcpu) {
    
   using namespace ::intel_x64::vmcs;

   if (vm_exit_instruction_information::sgdt::base_reg_invalid::is_enabled()) {
        return 0;
    }

    switch (vm_exit_instruction_information::sgdt::base_reg::get()) {
        case vm_exit_instruction_information::sgdt::base_reg::rax:
             bfdebug_subnhex(0, "base rax", vcpu->rax());
             return vcpu->rax(); 

        case vm_exit_instruction_information::sgdt::base_reg::rcx:
             bfdebug_subnhex(0, "base rcx", vcpu->rcx());
             return vcpu->rcx(); 

        case vm_exit_instruction_information::sgdt::base_reg::rdx: 
             bfdebug_subnhex(0, "base rdx", vcpu->rdx());
             return vcpu->rdx(); 

        case vm_exit_instruction_information::sgdt::base_reg::rbx: 
             bfdebug_subnhex(0, "base rbx", vcpu->rbx());
             return vcpu->rbx(); 

        case vm_exit_instruction_information::sgdt::base_reg::rsp: 
             bfdebug_subnhex(0, "base rsp", vcpu->rsp());
             return vcpu->rsp(); 

        case vm_exit_instruction_information::sgdt::base_reg::rbp: 
             bfdebug_subnhex(0, "base rbp", vcpu->rbp());
             return vcpu->rbp(); 

        case vm_exit_instruction_information::sgdt::base_reg::rsi: 
             bfdebug_subnhex(0, "base rsi", vcpu->rsi());
             return vcpu->rsi(); 

        case vm_exit_instruction_information::sgdt::base_reg::rdi: 
             bfdebug_subnhex(0, "base rdi", vcpu->rdi());
             return vcpu->rdi(); 

        case vm_exit_instruction_information::sgdt::base_reg::r8: 
             bfdebug_subnhex(0, "base r08", vcpu->r08());
             return vcpu->r08(); 

        case vm_exit_instruction_information::sgdt::base_reg::r9:
             bfdebug_subnhex(0, "base r09", vcpu->r09());
             return vcpu->r09(); 

        case vm_exit_instruction_information::sgdt::base_reg::r10: 
             bfdebug_subnhex(0, "base r10", vcpu->r10());
             return vcpu->r10(); 

        case vm_exit_instruction_information::sgdt::base_reg::r11: 
             bfdebug_subnhex(0, "base r11", vcpu->r11());
             return vcpu->r11(); 

        case vm_exit_instruction_information::sgdt::base_reg::r12: 
             bfdebug_subnhex(0, "base r12", vcpu->r12());
             return vcpu->r12(); 

        case vm_exit_instruction_information::sgdt::base_reg::r13: 
             bfdebug_subnhex(0, "base r13", vcpu->r13());
             return vcpu->r13(); 

        case vm_exit_instruction_information::sgdt::base_reg::r14: 
             bfdebug_subnhex(0, "base r14", vcpu->r14());
             return vcpu->r14(); 

        case vm_exit_instruction_information::sgdt::base_reg::r15: 
             bfdebug_subnhex(0, "base r15", vcpu->r15());
             return vcpu->r15(); 

        default:
             return 0;
    };

  
    return 0; 


};

uint64_t index(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    if (vm_exit_instruction_information::sgdt::index_reg_invalid::is_enabled()) {
        return 0;
    }

    switch (vm_exit_instruction_information::sgdt::index_reg::get()) {
        case vm_exit_instruction_information::sgdt::index_reg::rax:
             bfdebug_subnhex(0, "index rax", vcpu->rax());
             return vcpu->rax(); 

        case vm_exit_instruction_information::sgdt::index_reg::rcx:
             bfdebug_subnhex(0, "index rcx", vcpu->rcx());
             return vcpu->rcx(); 

        case vm_exit_instruction_information::sgdt::index_reg::rdx: 
             bfdebug_subnhex(0, "index rdx", vcpu->rdx());
             return vcpu->rdx(); 

        case vm_exit_instruction_information::sgdt::index_reg::rbx: 
             bfdebug_subnhex(0, "index rbx", vcpu->rbx());
             return vcpu->rbx(); 

        case vm_exit_instruction_information::sgdt::index_reg::rsp: 
             bfdebug_subnhex(0, "index rsp", vcpu->rsp());
             return vcpu->rsp(); 

        case vm_exit_instruction_information::sgdt::index_reg::rbp: 
             bfdebug_subnhex(0, "index rbp", vcpu->rbp());
             return vcpu->rbp(); 

        case vm_exit_instruction_information::sgdt::index_reg::rsi: 
             bfdebug_subnhex(0, "index rsi", vcpu->rsi());
             return vcpu->rsi(); 

        case vm_exit_instruction_information::sgdt::index_reg::rdi: 
             bfdebug_subnhex(0, "index rdi", vcpu->rdi());
             return vcpu->rdi(); 

        case vm_exit_instruction_information::sgdt::index_reg::r8: 
             bfdebug_subnhex(0, "index r08", vcpu->r08());
             return vcpu->r08(); 

        case vm_exit_instruction_information::sgdt::index_reg::r9:
             bfdebug_subnhex(0, "index r09", vcpu->r09());
             return vcpu->r09(); 

        case vm_exit_instruction_information::sgdt::index_reg::r10: 
             bfdebug_subnhex(0, "index r10", vcpu->r10());
             return vcpu->r10(); 

        case vm_exit_instruction_information::sgdt::index_reg::r11: 
             bfdebug_subnhex(0, "index r11", vcpu->r11());
             return vcpu->r11(); 

        case vm_exit_instruction_information::sgdt::index_reg::r12: 
             bfdebug_subnhex(0, "index r12", vcpu->r12());
             return vcpu->r12(); 

        case vm_exit_instruction_information::sgdt::index_reg::r13: 
             bfdebug_subnhex(0, "index r13", vcpu->r13());
             return vcpu->r13(); 

        case vm_exit_instruction_information::sgdt::index_reg::r14: 
             bfdebug_subnhex(0, "index r14", vcpu->r14());
             return vcpu->r14(); 

        case vm_exit_instruction_information::sgdt::index_reg::r15: 
             bfdebug_subnhex(0, "index r15", vcpu->r15());
             return vcpu->r15(); 

        default:
             return 0;
    };

    return 0; 

};

uint64_t scale(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    switch (vm_exit_instruction_information::sgdt::scaling::get()) {
        case vm_exit_instruction_information::sgdt::scaling::no_scaling: 
             return 1; 

        case vm_exit_instruction_information::sgdt::scaling::scale_by_2: 
             return 2; 

        case vm_exit_instruction_information::sgdt::scaling::scale_by_4: 
             return 4; 

        case vm_exit_instruction_information::sgdt::scaling::scale_by_8: 
             return 8; 

        default:
             return 1;
    };

    return 1; 

};

uint64_t dest_address(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    // 27.2.1 Basic VM-Exit Information
    // (under table 27-2
    auto displacement = vmcs_n::exit_qualification::sgdt::get(); 

    if (vm_exit_instruction_information::sgdt::index_reg_invalid::is_enabled() &&
        vm_exit_instruction_information::sgdt::base_reg_invalid::is_enabled()) {
        
        bfdebug_subnhex(0, "RIP relative displacement", displacement);
        return displacement;
    }

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "base", base(vcpu), msg);
        bfdebug_subnhex(0, "index", index(vcpu), msg);
        bfdebug_subnhex(0, "scale", scale(vcpu), msg);
        bfdebug_subnhex(0, "displacement", displacement, msg);
    });

    return base(vcpu) + index(vcpu) * scale(vcpu) + displacement;            


};


bool handle_sidt(vcpu *vcpu) {

    uint64_t address = dest_address(vcpu);
    
    bfdebug_subnhex(0, "destination address", address);
    
    auto map = vcpu->map_gva_4k<uint8_t>(address, 10);

    uint64_t base = vcpu->idt_base(); 
    uint64_t limit = vcpu->idt_limit();     

    bfdebug_subnhex(0, "base", base);
    bfdebug_subnhex(0, "limit", limit);

    *((uint16_t*)&map.get()[0]) = (uint16_t) limit; 
    *((uint64_t*)&map.get()[2]) = base; 

    return true;
};

bool handle_sgdt(vcpu *vcpu) {

    uint64_t address = dest_address(vcpu); 
    
    auto map = vcpu->map_gva_4k<uint8_t>(address, 10);

    uint64_t base = vcpu->gdt_base(); 
    uint64_t limit = vcpu->gdt_limit();     

    *((uint16_t*)&map.get()[0]) = (uint16_t) limit; 
    *((uint64_t*)&map.get()[2]) = base; 

    return true;
};

bool handle_lidt(vcpu *vcpu) {

    uint64_t address = dest_address(vcpu); 
    
    auto map = vcpu->map_gva_4k<uint8_t>(address, 10);

    uint64_t base = *((uint64_t*)&map.get()[2]); 
    uint64_t limit = *((uint16_t*)&map.get()[0]);
    
    vcpu->set_idt_limit(limit);
    vcpu->set_idt_base(base);

    return true;
};

bool handle_lgdt(vcpu *vcpu) {

    uint64_t address = dest_address(vcpu); 
    
    auto map = vcpu->map_gva_4k<uint8_t>(address, 10);

    uint64_t base = *((uint64_t*)&map.get()[2]); 
    uint64_t limit = *((uint16_t*)&map.get()[0]);
    
    vcpu->set_gdt_limit(limit);
    vcpu->set_gdt_base(base);

    return true;
};

bool
descriptor_handler::handle_gdtr_or_idtr(vcpu *vcpu)
{

    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::sgdt;
    auto ii = instr_info::get();

    switch (instr_info::instruction_identity::get(ii)) {
        case instr_info::instruction_identity::sgdt:
            //bfdebug_subnhex(0, "sgdt at", vcpu->rip());
            handle_sgdt(vcpu);
            break;
    
        case instr_info::instruction_identity::sidt:

            //bfdebug_subnhex(0, "sidt at", vcpu->rip());
            handle_sidt(vcpu);
            break;

        case instr_info::instruction_identity::lgdt:
            //bfdebug_subnhex(0, "lgdt at", vcpu->rip());
            handle_lgdt(vcpu);
            break;

        case instr_info::instruction_identity::lidt:
            //bfdebug_subnhex(0, "lidt at", vcpu->rip());
            handle_lidt(vcpu);
            break;

        default:

            return false;
    }

    return vcpu->advance();
}

uint64_t get_selector_from_reg(vcpu *vcpu) {

    using namespace ::intel_x64::vmcs;

    switch (vm_exit_instruction_information::sldt::index_reg::get()) {
        case vm_exit_instruction_information::sldt::index_reg::rax: 
             return vcpu->rax(); 

        case vm_exit_instruction_information::sldt::index_reg::rcx: 
             return vcpu->rcx(); 

        case vm_exit_instruction_information::sldt::index_reg::rdx: 
             return vcpu->rdx(); 

        case vm_exit_instruction_information::sldt::index_reg::rbx: 
             return vcpu->rbx(); 

        case vm_exit_instruction_information::sldt::index_reg::rsp: 
             return vcpu->rsp(); 

        case vm_exit_instruction_information::sldt::index_reg::rbp: 
             return vcpu->rbp(); 

        case vm_exit_instruction_information::sldt::index_reg::rsi: 
             return vcpu->rsi(); 

        case vm_exit_instruction_information::sldt::index_reg::rdi: 
             return vcpu->rdi(); 

        case vm_exit_instruction_information::sldt::index_reg::r8: 
             return vcpu->r08(); 

        case vm_exit_instruction_information::sldt::index_reg::r9: 
             return vcpu->r09(); 

        case vm_exit_instruction_information::sldt::index_reg::r10: 
             return vcpu->r10(); 

        case vm_exit_instruction_information::sldt::index_reg::r11: 
             return vcpu->r11(); 

        case vm_exit_instruction_information::sldt::index_reg::r12: 
             return vcpu->r12(); 

        case vm_exit_instruction_information::sldt::index_reg::r13: 
             return vcpu->r13(); 

        case vm_exit_instruction_information::sldt::index_reg::r14: 
             return vcpu->r14(); 

        case vm_exit_instruction_information::sldt::index_reg::r15: 
             return vcpu->r15(); 

        default:
             return 0;
    };

    return 0; 

};

uint64_t set_selector_into_reg(vcpu *vcpu, uint64_t sel) {

    using namespace ::intel_x64::vmcs;

    switch (vm_exit_instruction_information::sldt::index_reg::get()) {
        case vm_exit_instruction_information::sldt::index_reg::rax: 
             vcpu->set_rax(sel); 
	     break;

        case vm_exit_instruction_information::sldt::index_reg::rcx: 
             vcpu->set_rcx(sel); 
	     break;

        case vm_exit_instruction_information::sldt::index_reg::rdx: 
             vcpu->set_rdx(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::rbx: 
             vcpu->set_rbx(sel); 
	     break;

        case vm_exit_instruction_information::sldt::index_reg::rsp: 
             vcpu->set_rsp(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::rbp: 
             vcpu->set_rbp(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::rsi: 
             vcpu->set_rsi(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::rdi: 
             vcpu->set_rdi(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r8: 
             vcpu->set_r08(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r9: 
             vcpu->set_r09(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r10: 
             vcpu->set_r10(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r11: 
             vcpu->set_r11(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r12: 
             vcpu->set_r12(sel); 
	     break;

        case vm_exit_instruction_information::sldt::index_reg::r13: 
             vcpu->set_r13(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r14: 
             vcpu->set_r14(sel); 
	     break; 

        case vm_exit_instruction_information::sldt::index_reg::r15: 
             vcpu->set_r15(sel); 
	     break; 

        default:
             return 0;
    };

    return 0; 

};


uint64_t get_selector_from_mem(vcpu *vcpu) {
    uint64_t address = dest_address(vcpu); 
    auto map = vcpu->map_gva_4k<uint16_t>(address, 1);

    uint64_t sel = map.get()[0];
    return sel; 
};

bool handle_sldt(vcpu *vcpu) {
    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::lldt;
    uint64_t sel;

    sel = vcpu->ldtr_selector();
    
    switch (instr_info::mem_reg::get()) {
            case instr_info::mem_reg::reg:
                    set_selector_into_reg(vcpu, sel); 
                    break; 
            case instr_info::mem_reg::mem:
                    uint64_t address = dest_address(vcpu); 
                    auto map = vcpu->map_gva_4k<uint16_t>(address, 1);
                    map.get()[0] = sel; 
                    break;   
    };

    return true;
};


bool handle_lldt(vcpu *vcpu) {
    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::lldt;
    uint64_t sel;

    switch (instr_info::mem_reg::get()) {
            case instr_info::mem_reg::reg:
                    sel = get_selector_from_reg(vcpu); 
                    break; 
            case instr_info::mem_reg::mem:
                    sel = get_selector_from_mem(vcpu); 
                    break;   
    };

    vcpu->set_ldtr_selector(sel);
    return true;
};

bool handle_str(vcpu *vcpu) {
    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::lldt;
    uint64_t sel;

    sel = vcpu->tr_selector();
    
    switch (instr_info::mem_reg::get()) {
            case instr_info::mem_reg::reg:
                    set_selector_into_reg(vcpu, sel); 
                    break; 
            case instr_info::mem_reg::mem:
                    uint64_t address = dest_address(vcpu); 
                    auto map = vcpu->map_gva_4k<uint16_t>(address, 1);
                    map.get()[0] = sel; 
                    break;   
    };

    return true;
};


bool handle_ltr(vcpu *vcpu) {
    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::lldt;
    uint64_t sel;

    switch (instr_info::mem_reg::get()) {
            case instr_info::mem_reg::reg:
                    sel = get_selector_from_reg(vcpu); 
                    break; 
            case instr_info::mem_reg::mem:
                    sel = get_selector_from_mem(vcpu); 
                    break;   
    };

    vcpu->set_tr_selector(sel);
    return true;
};


bool
descriptor_handler::handle_ldtr_or_tr(vcpu *vcpu)
{

    using namespace ::intel_x64::vmcs;

    namespace instr_info = vm_exit_instruction_information::lldt;
    auto ii = instr_info::get();

    switch (instr_info::instruction_identity::get(ii)) {
        case instr_info::instruction_identity::sldt:
            //bfdebug_subnhex(0, "sldt at", vcpu->rip());
            handle_sldt(vcpu);
            break;
    
        case instr_info::instruction_identity::str:

            //bfdebug_subnhex(0, "str at", vcpu->rip());
            handle_str(vcpu);
            break;

        case instr_info::instruction_identity::lldt:
            //bfdebug_subnhex(0, "lldt at", vcpu->rip());
            handle_lldt(vcpu);
            break;

        case instr_info::instruction_identity::ltr:
            //bfdebug_subnhex(0, "lidt at", vcpu->rip());
            handle_ltr(vcpu);
            break;

        default:

            return false;
    }

    return vcpu->advance();
}



}
