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

#include <hve/arch/intel_x64/vcpu.h>
#include <bfcallonce.h>
	    
void
WEAK_SYM vcpu_init_root(vcpu_t *vcpu)
{ bfignored(vcpu); }

void
WEAK_SYM vcpu_fini_root(vcpu_t *vcpu)
{ bfignored(vcpu); }

namespace bfvmm::intel_x64
{

static bool
handle_cpuid_feature_information(vcpu *vcpu)
{
    using namespace ::intel_x64::cpuid;

    // Currently, we do not support nested virtualization. As a result,
    // the EAPIs adds a default handler to disable support for VMXE here.
    //

    vcpu->set_rcx(
        clear_bit(vcpu->rcx(), feature_information::ecx::vmx::from)
    );

    return false;
}

static bool
handle_cpuid_0x4BF00000(vcpu *vcpu)
{
    /// Ack
    ///
    /// This can be used by an application to ack the existence of the
    /// hypervisor. This is useful because vmcall only exists if the hypervisor
    /// is running while cpuid can be run from any ring, and always exists
    /// which means it can be used to ack safely from any application.
    ///

    vcpu->dump_perf_counters();
    vcpu->set_rax(0x4BF00001);
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00010(vcpu *vcpu)
{
    /// Init
    ///
    /// Some initialization is required after the hypervisor has started. For
    /// example, any memory mapped resources such as ACPI or VT-d need to be
    /// initalized using the VMM's CR3, and not the hosts.
    ///

    vcpu_init_root(vcpu);
    return vcpu->advance();
}

bfn::once_flag flag;

static bool
handle_cpuid_0x4BF00011(vcpu *vcpu)
{
    /// Say Hi
    ///
    /// If the vCPU is a host vCPU and not a guest vCPU, we should say hi
    /// so that the user of Bareflank has a simple, reliable way to know
    /// that the hypervisor is running.
    ///

    bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
    //vcpu->dump_perf_counters(); 
    //bfn::call_once(flag, [&] {
    //    vcpu->dump("Dump sound VMCS"); 
    //});

    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00020(vcpu *vcpu)
{
    /// Fini
    ///
    /// Some teardown logic is required before the hypervisor stops running.
    /// These handlers can be used in these scenarios.
    ///

    vcpu_fini_root(vcpu);
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00021(vcpu *vcpu)
{
    /// Say Goobye
    ///
    /// The most reliable method for turning off the hypervisor is from the
    /// exit handler as it ensures that all of the destructors are executed
    /// after a promote, and not during. Also, say goodbye before we promote
    /// and turn off the hypervisor.
    ///

    bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
    vcpu->promote();

    throw std::runtime_error("unreachable exception");
}

static bool
handle_cpuid_lcds_syscall(vcpu *vcpu)
{
    unsigned long ebx = vcpu->rbx();
    unsigned long long ecx = vcpu->rcx();
    unsigned long long eptp_list = (ecx << 32) | ebx;
 
    bfdebug_transaction(0, [&](std::string * msg) {
         bfdebug_info(0, "lcds call");
         bfdebug_subnhex(0, "eptp_list", eptp_list, msg);
         bfdebug_subnhex(0, "rbx", vcpu->rbx(), msg);
         bfdebug_subnhex(0, "rcx", vcpu->rcx(), msg);
    });

    if (::intel_x64::vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::is_disabled()) {
	bfdebug_info(0, "secondary controlls needed for vmfunc are disabled");
        return false;
    }

    /* Enable vm functions */
    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::enable(); 

    /* enable EPT switching */
    ::intel_x64::vmcs::vm_function_controls::eptp_switching::enable(); 

    bfdebug_transaction(0, [&](std::string * msg) {
         bfdebug_subbool(0, "msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1()", 
			 ::intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1(), msg);
         bfdebug_subbool(0, "msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1()", 
			 ::intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1(), msg);
         bfdebug_subbool(0, "msrs::ia32_vmx_vmfunc::eptp_switching::is_allowed1();", 
			 ::intel_x64::msrs::ia32_vmx_vmfunc::eptp_switching::is_allowed1(), msg);
    });


    ::intel_x64::vmcs::eptp_list_address::set_if_exists(eptp_list);

    /* add guest kernel ept as entry 0 */
    bfdebug_transaction(0, [&](std::string * msg) {
         bfdebug_subnhex(0, "return kernel EPT", ::intel_x64::vmcs::ept_pointer::phys_addr::get(), msg);
	 bfdebug_subnhex(0, "eptp_list_address", ::intel_x64::vmcs::eptp_list_address::get_if_exists(), msg);
    });

    ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::dump(0);
    ::intel_x64::vmcs::vm_function_controls::eptp_switching::dump(0);

    vcpu->set_rax(0x0);
    vcpu->set_rbx(::intel_x64::vmcs::ept_pointer::get());
    vcpu->set_rcx(::intel_x64::vmcs::ept_pointer::get() >> 32);
    return vcpu->advance();

}

static bool
handle_cpuid_lcds_syscall_dump_stack(vcpu *vcpu)
{
    //vcpu->dump_instruction(); 
    vcpu->dump_stack(); 
    vcpu->set_rax(0x0);
    return vcpu->advance();
}

static bool
handle_cpuid_lcds_syscall_abort(vcpu *vcpu)
{
    vcpu->dump_instruction(vcpu->rip()); 
    vcpu->dump_stack(); 
    //vcpu->dump(); 
    vcpu->set_rax(0x0);
    vcpu->halt(); 
    return false; 
}

/* rbx - gpa
 * rcx - hpa of a page to be mapped */

static bool
handle_cpuid_lcds_syscall_map_page(vcpu *vcpu)
{
    uint64_t gpa = vcpu->rbx();
    uint64_t hpa = vcpu->rcx();
 
    bfdebug_transaction(0, [&](std::string * msg) {
         bfdebug_info(0, "lcds map page call");
         bfdebug_subnhex(0, "gpa", gpa, msg);
         bfdebug_subnhex(0, "hpa", hpa, msg);
    });

    auto gpa1_2m = bfn::upper(gpa, ::intel_x64::ept::pd::from);
    auto gpa1_4k = bfn::upper(gpa, ::intel_x64::ept::pt::from);
    auto gpa2_4k = bfn::upper(hpa, ::intel_x64::ept::pt::from);

    ept::identity_map_convert_2m_to_4k(
            *vcpu->get_ept_map(),
            gpa1_2m
    );

    auto [pte, unused] = vcpu->get_ept_map()->entry(gpa1_4k);
    ::intel_x64::ept::pt::entry::phys_addr::set(pte, gpa2_4k);

    vcpu->set_rax(0x0);
    return vcpu->advance();

}

static bool
handle_cpuid_lcds_syscall_illegal_exception(vcpu *vcpu)
{

    /* We have an exception m LCD
     * 
     * Our stack 
     * 
     *  ------------------------
     *     exception frame 
     *  -----------------------
     *     rax
     *
     */
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "Illegal exception from LCD", msg); 
    });

    vcpu->dump("Dumping illegal exception from LCD");

    vcpu->dump_exception_stack(); 
    vcpu->set_rax(0x0);
    //vcpu->halt();
    return true; 
}

static bool
handle_cpuid_lcds_syscall_illegal_nmi(vcpu *vcpu)
{

    /* We have an exception m LCD
     * 
     * Our stack 
     * 
     *  ------------------------
     *     exception frame 
     *  -----------------------
     *     rax
     *
     */
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "Illegal NMI while inside LCD", msg); 
    });

    vcpu->dump("Dumping illegal NMI while inside LCD");

    vcpu->dump_exception_stack(); 
    vcpu->set_rax(0x0);
    //vcpu->halt();
    return true; 
}

static bool
handle_cpuid_lcds_syscall_halt(vcpu *vcpu)
{

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "Halting the CPU", msg); 
    });

    vcpu->set_rax(0x0);
    vcpu->halt();
    return true; 
}

static bool
handle_cpuid_lcds_syscall_walk_gva(vcpu *vcpu)
{
    uint64_t gva = vcpu->rbx();
    uint64_t cr3 = vcpu->rcx();
    uint64_t verbose = vcpu->rdx(); 
    uint64_t ept_index = vcpu->r08(); 
    uint64_t gpa; 

    unsigned long long eptp_list = ::intel_x64::vmcs::eptp_list_address::get();

    if (bfn::upper(eptp_list) == 0) {
        bfdebug_info(0, "EPTP list is 0"); 
        return true;
    }


    auto map = vcpu->map_hpa_4k<uint64_t>(eptp_list);
    uint64_t eptp = bfn::upper(map.get()[ept_index]);

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "Walk gva:", gva, msg);
        bfdebug_subnhex(0, "cr3:", cr3, msg);
        bfdebug_subnhex(0, "eptp", eptp, msg); 
    });

    if (cr3 == 0 ) {
        gpa = gva; 
    } else {
        gpa = vcpu->lcd_gva_to_gpa(gva, cr3, eptp);  

        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_subnhex(0, "gpa", gpa, msg);
        });
    };

    uint64_t hpa = vcpu->lcd_gpa_to_hpa(gpa, eptp);

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "hpa", hpa, msg);
    });

    if (verbose) 
        vcpu->dump("Walking gva");
    
    //vcpu->set_rax(0x0);
    return vcpu->advance();
}

static const char *bfdebug_exit_to_str(unsigned int i) {
    switch(i) {
        case 0: return "nmi";
        case 1: return "external int";
        case 2: return "triple fault";
        case 3: return "init signal";
        case 4: return "startup ipi";
        case 5: return "smi";
        case 6: return "other smi";
        case 7: return "interrupt window";
        case 8: return "nmi window";
        case 9: return "task switch";
        case 10: return "cpuid";
        case 11: return "getsec";
        case 12: return "hlt";
        case 13: return "invd";
        case 14: return "invlpg";
        case 15: return "rdpmc";
        case 16: return "rdtsc";
        case 17: return "rsm";
        case 18: return "vmcall";
        case 19: return "vmclear";
        case 20: return "vmlaunch";
        case 21: return "vmptrld";
        case 22: return "vmptrst";
        case 23: return "vmread";
        case 24: return "vmresume";
        case 25: return "vmwrite";
        case 26: return "vmxoff";
        case 27: return "vmxon";
        case 28: return "control-reg access";
        case 29: return "mov dr";
        case 30: return "i/o instr";
        case 31: return "rdmsr";
        case 32: return "wrmsr";
        case 33: return "vm entry failure due to guest state";
        case 34: return "vm entry failure due to msr loading";
        case 35: return "35";
        case 36: return "mwait";
        case 37: return "monitor trap flag";
        case 38: return "38";
        case 39: return "monitor";
        case 40: return "pause";
        case 41: return "vm entry failure due to machine check";
        case 42: return "42";
        case 43: return "tpr below threshold";
        case 44: return "apic access";
        case 45: return "virtualized eoi";
        case 46: return "access to idtr or gdtr";
        case 47: return "access to ldtr or tr";
        case 48: return "ept violation";
        case 49: return "ept misconfiguration";
        case 50: return "invept";
        case 51: return "rdtscp";
        case 52: return "vmx-preemption timer expired";
        case 53: return "invvpid";
        case 54: return "wbinvd";
        case 55: return "xsetbv";
        case 56: return "apic write";
        case 57: return "rdrand";
        case 58: return "invpcid";
        case 59: return "vmfunc";
        case 60: return "encls";
        case 61: return "rdseed";
        case 62: return "page modification log full";
        case 63: return "xsaves";
        case 64: return "xrstors";
        default: return "unknown";
    };
};

static bool
handle_cpuid_lcds_syscall_dump_perf(vcpu *vcpu)
{

#ifdef BF_COUNT_EXTIS
    //vcpu->dump_instruction(); 
    //vcpu->dump_perf_counters();
    vcpu->set_rax(vcpu->m_exits_total);
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "Dumping VM exits", msg); 
        for (int i = 0; i < 65; i++) {
            if(vcpu->m_exits[i]) {
                bfdebug_subnhex(0, bfdebug_exit_to_str(i), vcpu->m_exits[i], msg);
                vcpu->m_exits[i] = 0; 
            }
        }
    });
#else
   bfdebug_info(0, "VM exit counting is not supported (recompile with BF_COUNT_EXTIS)"); 
#endif

    return vcpu->advance();
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu)
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle>(this)
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        handler_delegate_t::create<handle_cpuid_feature_information>()
    );

    this->add_emulator(
        0x4BF00000, handler_delegate_t::create<handle_cpuid_0x4BF00000>()
    );

    this->add_emulator(
        0x4BF00010, handler_delegate_t::create<handle_cpuid_0x4BF00010>()
    );

    this->add_emulator(
        0x4BF00011, handler_delegate_t::create<handle_cpuid_0x4BF00011>()
    );

    this->add_emulator(
        0x4BF00020, handler_delegate_t::create<handle_cpuid_0x4BF00020>()
    );

    this->add_emulator(
        0x4BF00021, handler_delegate_t::create<handle_cpuid_0x4BF00021>()
    );

    this->add_emulator(
        0x4BF00031, handler_delegate_t::create<handle_cpuid_lcds_syscall>()
    );

    this->add_emulator(
        0x4BF00032, handler_delegate_t::create<handle_cpuid_lcds_syscall_dump_stack>()
    );

    this->add_emulator(
        0x4BF00033, handler_delegate_t::create<handle_cpuid_lcds_syscall_abort>()
    );

    this->add_emulator(
        0x4BF00034, handler_delegate_t::create<handle_cpuid_lcds_syscall_map_page>()
    );

    this->add_emulator(
        0x4BF00035, handler_delegate_t::create<handle_cpuid_lcds_syscall_illegal_exception>()
    );

    this->add_emulator(
        0x4BF00036, handler_delegate_t::create<handle_cpuid_lcds_syscall_walk_gva>()
    );

    this->add_emulator(
        0x4BF00037, handler_delegate_t::create<handle_cpuid_lcds_syscall_dump_perf>()
    );

    this->add_emulator(
        0x4BF00038, handler_delegate_t::create<handle_cpuid_lcds_syscall_illegal_nmi>()
    );

    this->add_emulator(
        0x4BF00039, handler_delegate_t::create<handle_cpuid_lcds_syscall_halt>()
    );



}

// -----------------------------------------------------------------------------
// Public APIs
// -----------------------------------------------------------------------------

void
cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

void
cpuid_handler::add_emulator(
    leaf_t leaf, const handler_delegate_t &d)
{ m_emulators[leaf].push_front(d); }

void
cpuid_handler::execute(gsl::not_null<vcpu *> vcpu)
{
    vcpu->set_gr1(vcpu->rax());
    vcpu->set_gr2(vcpu->rcx());

    auto [rax, rbx, rcx, rdx] =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
        );

    vcpu->set_rax(rax);
    vcpu->set_rbx(rbx);
    vcpu->set_rcx(rcx);
    vcpu->set_rdx(rdx);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
execute_handlers(vcpu *vcpu, const std::list<handler_delegate_t> &handlers)
{
    for (const auto &d : handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

static bool
execute_emulators(vcpu *vcpu, const std::list<handler_delegate_t> &emulators)
{
    for (const auto &d : emulators) {
        if (d(vcpu)) {
            return true;
        }
    }

    return false;
}

bool
cpuid_handler::handle(vcpu *vcpu)
{
    const auto &emulators =
        m_emulators.find(vcpu->rax());

    if (emulators != m_emulators.end()) {
        return execute_emulators(vcpu, emulators->second);
    }

    if (m_whitelist) {
        vcpu->set_gr1(vcpu->rax());
        vcpu->set_gr2(vcpu->rcx());
        return false;
    }

    const auto &handlers =
        m_handlers.find(vcpu->rax());

    this->execute(vcpu);

    if (handlers != m_handlers.end()) {
        return execute_handlers(vcpu, handlers->second);
    }

    return vcpu->advance();
}

}
