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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfcallonce.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/exception.h>

//==============================================================================
// C Prototypes
//==============================================================================

extern "C" void exit_handler_entry(void) noexcept;

//==============================================================================
// Global State
//==============================================================================

static bfn::once_flag g_once_flag{};
static ::intel_x64::cr0::value_type g_cr0_reg{};
static ::intel_x64::cr3::value_type g_cr3_reg{};
static ::intel_x64::cr4::value_type g_cr4_reg{};
static ::intel_x64::msrs::value_type g_ia32_pat_msr{};
static ::intel_x64::msrs::value_type g_ia32_efer_msr{};

static void
setup()
{
    using namespace ::intel_x64;
    using namespace ::intel_x64::cpuid;

    using namespace bfvmm::x64;
    using attr_type = bfvmm::x64::cr3::mmap::attr_type;

    for (const auto &md : g_mm->descriptors()) {
        if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_E)) {
            g_cr3->map_4k(md.virt, md.phys, attr_type::read_execute);
            continue;
        }

        g_cr3->map_4k(md.virt, md.phys, attr_type::read_write);
    }

    g_ia32_efer_msr |= msrs::ia32_efer::lme::mask;
    g_ia32_efer_msr |= msrs::ia32_efer::lma::mask;
    g_ia32_efer_msr |= msrs::ia32_efer::nxe::mask;

    g_cr0_reg |= cr0::protection_enable::mask;
    g_cr0_reg |= cr0::monitor_coprocessor::mask;
    g_cr0_reg |= cr0::extension_type::mask;
    g_cr0_reg |= cr0::numeric_error::mask;
    g_cr0_reg |= cr0::write_protect::mask;
    g_cr0_reg |= cr0::paging::mask;

    g_cr3_reg = g_cr3->cr3();
    g_ia32_pat_msr = g_cr3->pat();

    g_cr4_reg |= cr4::v8086_mode_extensions::mask;
    g_cr4_reg |= cr4::protected_mode_virtual_interrupts::mask;
    g_cr4_reg |= cr4::time_stamp_disable::mask;
    g_cr4_reg |= cr4::debugging_extensions::mask;
    g_cr4_reg |= cr4::page_size_extensions::mask;
    g_cr4_reg |= cr4::physical_address_extensions::mask;
    g_cr4_reg |= cr4::machine_check_enable::mask;
    g_cr4_reg |= cr4::page_global_enable::mask;
    g_cr4_reg |= cr4::performance_monitor_counter_enable::mask;
    g_cr4_reg |= cr4::osfxsr::mask;
    g_cr4_reg |= cr4::osxmmexcpt::mask;
    g_cr4_reg |= cr4::vmx_enable_bit::mask;

    if (feature_information::ecx::xsave::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::osxsave::mask;
    }

    if (extended_feature_flags::subleaf0::ebx::smep::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::smep_enable_bit::mask;
    }

    if (extended_feature_flags::subleaf0::ebx::smap::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::smap_enable_bit::mask;
    }
}

//==============================================================================
// Implementation
//==============================================================================

namespace bfvmm::intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    vcpu_global_state_t *global_state
) :
    bfvmm::vcpu{id},
    m_global_state{global_state != nullptr ? global_state : & g_vcpu_global_state},

    m_msr_bitmap{make_page<uint8_t>()},
    m_io_bitmap_a{make_page<uint8_t>()},
    m_io_bitmap_b{make_page<uint8_t>()},

    m_ist1{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},
    m_stack{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},

    m_vmx{is_host_vm_vcpu() ? std::make_unique<vmx>() : nullptr},

    m_vmcs{this},
    m_exit_handler{this},

    m_control_register_handler{this},
    m_cpuid_handler{this},
    m_ept_misconfiguration_handler{this},
    m_ept_violation_handler{this},
    m_external_interrupt_handler{this},
    m_init_signal_handler{this},
    m_interrupt_window_handler{this},
    m_io_instruction_handler{this},
    m_monitor_trap_handler{this},
    m_nmi_window_handler{this},
    m_nmi_handler{this},
    m_preemption_timer_handler{this},
    m_rdmsr_handler{this},
    m_sipi_signal_handler{this},
    m_wrmsr_handler{this},
    m_xsetbv_handler{this},

    m_ept_handler{this},
    m_microcode_handler{this},
    m_vpid_handler{this}

#ifdef BF_COUNT_EXTIS
    ,
    m_exits_total{0},
    m_hashtable{this}
#endif

{
    using namespace vmcs_n;
    bfn::call_once(g_once_flag, setup);

    this->add_run_delegate(
        run_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::run_delegate>(this)
    );

    this->add_hlt_delegate(
        hlt_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::hlt_delegate>(this)
    );

    m_state.vcpu_ptr =
        reinterpret_cast<uintptr_t>(this);

    m_state.exit_handler_ptr =
        reinterpret_cast<uintptr_t>(&m_exit_handler);

    // Note:
    //
    // Up to this point, no modifications to the VMCS have been made. The only
    // thing that is done in the vCPU is the software state has been
    // initialized and set up. The remaining code, which is our last step is
    // to actually initialize the VMCS to its initial state. All of the VMCS
    // initialization logic can be found below. Also note that load() has
    // not been called yet, so any attempt to touch the VMCS prior to this
    // point will fail, ensuring that all of the initialization logic is
    // simple to follow.
    //

    this->load();

    this->write_host_state();
    this->write_control_state();

    if (this->is_host_vm_vcpu()) {
        this->write_guest_state();
    }

    m_vpid_handler.enable();
    m_nmi_handler.enable_exiting();

    /* Exit on all writes to CR0 and CR4 */
    m_control_register_handler.enable_wrcr0_exiting(~0UL);
    vmcs_n::cr0_read_shadow::set(guest_cr0::get());

    m_control_register_handler.enable_wrcr4_exiting(~0UL);
    vmcs_n::cr4_read_shadow::set(guest_cr4::get());

    /* Exit on writes to CR3 */

    ::intel_x64::msrs::ia32_vmx_misc::cr3_targets::dump(0); 
    if (::intel_x64::msrs::ia32_vmx_misc::cr3_targets::get() == 4) {
        ::intel_x64::vmcs::cr3_target_count::set(4); 
        ::intel_x64::vmcs::cr3_target_value_0::set(0);
        ::intel_x64::vmcs::cr3_target_value_1::set(0);
        ::intel_x64::vmcs::cr3_target_value_2::set(0);
        ::intel_x64::vmcs::cr3_target_value_3::set(0);
    };

    m_control_register_handler.enable_wrcr3_exiting(); 

    /* Trap on all MSR access */
    this->trap_on_all_rdmsr_accesses();
    this->trap_on_all_wrmsr_accesses();

    /* Trap on all I/O instructions */
    this->trap_on_all_io_instruction_accesses(); 

    /* Descriptor table exiting (LGDT, LIDT) */
    secondary_processor_based_vm_execution_controls::descriptor_table_exiting::enable(); 

    /* 
     * - Stores to control registers
     *   -- cr0, cr3, cr4
     * - MSRs
     * - I/O ports
     * - store to extra control register (xcr0) / xsetbv
     * 
     * ToDo: 
     * - debug registers (mov-DR)
     * - store GDT, IDT
     * - xrstor
     */

#ifdef BF_COUNT_EXTIS
    for (int i = 0; i < MAX_EXIT_REASONS; i++) {
        this->m_exits[i] = 0; 
    }
#endif

}

//==============================================================================
// Initial VMCS State
//==============================================================================

void
vcpu::write_host_state()
{
    using namespace ::intel_x64::vmcs;
    using namespace ::x64::access_rights;

    m_host_gdt.set(1, nullptr, 0xFFFFFFFF, ring0_cs_descriptor);
    m_host_gdt.set(2, nullptr, 0xFFFFFFFF, ring0_ss_descriptor);
    m_host_gdt.set(3, nullptr, 0xFFFFFFFF, ring0_fs_descriptor);
    m_host_gdt.set(4, nullptr, 0xFFFFFFFF, ring0_gs_descriptor);
    m_host_gdt.set(5, &m_host_tss, sizeof(m_host_tss), ring0_tr_descriptor);

    host_cs_selector::set(1 << 3);
    host_ss_selector::set(2 << 3);
    host_fs_selector::set(3 << 3);
    host_gs_selector::set(4 << 3);
    host_tr_selector::set(5 << 3);

    host_ia32_pat::set(g_ia32_pat_msr);
    host_ia32_efer::set(g_ia32_efer_msr);

    host_cr0::set(g_cr0_reg);
    host_cr3::set(g_cr3_reg);
    host_cr4::set(g_cr4_reg);

    host_gs_base::set(reinterpret_cast<uintptr_t>(&m_state));
    host_tr_base::set(m_host_gdt.base(5));

    host_gdtr_base::set(m_host_gdt.base());
    host_idtr_base::set(m_host_idt.base());

    m_host_tss.ist1 = setup_stack(m_ist1.get(), this->id());
    set_default_esrs(&m_host_idt, 8);

    host_rip::set(exit_handler_entry);
    host_rsp::set(setup_stack(m_stack.get(), this->id()));
}

void
vcpu::write_guest_state()
{
    using namespace ::intel_x64;
    using namespace ::intel_x64::vmcs;
    using namespace ::intel_x64::cpuid;

    using namespace ::x64::access_rights;
    using namespace ::x64::segment_register;

    x64::gdt guest_gdt;
    x64::idt guest_idt;

    auto es_index = es::index::get();
    auto cs_index = cs::index::get();
    auto ss_index = ss::index::get();
    auto ds_index = ds::index::get();
    auto fs_index = fs::index::get();
    auto gs_index = gs::index::get();
    auto ldtr_index = ldtr::index::get();
    auto tr_index = tr::index::get();

    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    guest_es_selector::set(es::get());
    guest_cs_selector::set(cs::get());
    guest_ss_selector::set(ss::get());
    guest_ds_selector::set(ds::get());
    guest_fs_selector::set(fs::get());
    guest_gs_selector::set(gs::get());
    guest_ldtr_selector::set(ldtr::get());
    guest_tr_selector::set(tr::get());

    guest_ia32_debugctl::set(msrs::ia32_debugctl::get());
    guest_ia32_pat::set(::x64::msrs::ia32_pat::get());
    guest_ia32_efer::set(msrs::ia32_efer::get());

    if (arch_perf_monitoring::eax::version_id::get() >= 2) {
        guest_ia32_perf_global_ctrl::set_if_exists(
            msrs::ia32_perf_global_ctrl::get()
        );
    }

    guest_gdtr_limit::set(guest_gdt.limit());
    guest_idtr_limit::set(guest_idt.limit());

    guest_gdtr_base::set(guest_gdt.base());
    guest_idtr_base::set(guest_idt.base());

    guest_es_limit::set(es_index != 0 ? guest_gdt.limit(es_index) : 0);
    guest_cs_limit::set(cs_index != 0 ? guest_gdt.limit(cs_index) : 0);
    guest_ss_limit::set(ss_index != 0 ? guest_gdt.limit(ss_index) : 0);
    guest_ds_limit::set(ds_index != 0 ? guest_gdt.limit(ds_index) : 0);
    guest_fs_limit::set(fs_index != 0 ? guest_gdt.limit(fs_index) : 0);
    guest_gs_limit::set(gs_index != 0 ? guest_gdt.limit(gs_index) : 0);
    guest_ldtr_limit::set(ldtr_index != 0 ? guest_gdt.limit(ldtr_index) : 0);
    guest_tr_limit::set(tr_index != 0 ? guest_gdt.limit(tr_index) : 0);

    guest_es_access_rights::set(es_index != 0 ? guest_gdt.access_rights(es_index) : unusable);
    guest_cs_access_rights::set(cs_index != 0 ? guest_gdt.access_rights(cs_index) : unusable);
    guest_ss_access_rights::set(ss_index != 0 ? guest_gdt.access_rights(ss_index) : unusable);
    guest_ds_access_rights::set(ds_index != 0 ? guest_gdt.access_rights(ds_index) : unusable);
    guest_fs_access_rights::set(fs_index != 0 ? guest_gdt.access_rights(fs_index) : unusable);
    guest_gs_access_rights::set(gs_index != 0 ? guest_gdt.access_rights(gs_index) : unusable);
    guest_ldtr_access_rights::set(ldtr_index != 0 ? guest_gdt.access_rights(ldtr_index) : unusable);
    guest_tr_access_rights::set(tr_index != 0 ? guest_gdt.access_rights(tr_index) : type::tss_busy | 0x80U);

    guest_es_base::set(es_index != 0 ? guest_gdt.base(es_index) : 0);
    guest_cs_base::set(cs_index != 0 ? guest_gdt.base(cs_index) : 0);
    guest_ss_base::set(ss_index != 0 ? guest_gdt.base(ss_index) : 0);
    guest_ds_base::set(ds_index != 0 ? guest_gdt.base(ds_index) : 0);
    guest_fs_base::set(msrs::ia32_fs_base::get());
    guest_gs_base::set(msrs::ia32_gs_base::get());
    guest_ldtr_base::set(ldtr_index != 0 ? guest_gdt.base(ldtr_index) : 0);
    guest_tr_base::set(tr_index != 0 ? guest_gdt.base(tr_index) : 0);

    guest_cr0::set(cr0::get() | ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get());
    guest_cr3::set(cr3::get());
    guest_cr4::set(cr4::get() | ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get());
    guest_dr7::set(dr7::get());

    guest_rflags::set(::x64::rflags::get());

    guest_ia32_sysenter_cs::set(msrs::ia32_sysenter_cs::get());
    guest_ia32_sysenter_esp::set(msrs::ia32_sysenter_esp::get());
    guest_ia32_sysenter_eip::set(msrs::ia32_sysenter_eip::get());

#if 0

    bfdebug_transaction(1, [&](std::string * msg) {
            bfdebug_info(1, "guest state", msg);

            bfdebug_subnhex(1, "es",  es::get(), msg);
            bfdebug_subnhex(1, "cs",  cs::get(), msg);
            bfdebug_subnhex(1, "ss",  ss::get(), msg);
            bfdebug_subnhex(1, "ds",  ds::get(), msg);
            bfdebug_subnhex(1, "fs",  fs::get(), msg);
            bfdebug_subnhex(1, "gs",  gs::get(), msg);
    
        bfdebug_subnhex(1, "ldtr",  ldtr::get(), msg);
            bfdebug_subnhex(1, "tr",  tr::get(), msg);
    
        bfdebug_subnhex(1, "msrs::ia32_debugctl",  msrs::ia32_debugctl::get(), msg);
            bfdebug_subnhex(1, "::x64::msrs::ia32_pat",  ::x64::msrs::ia32_pat::get(), msg);
        bfdebug_subnhex(1, "msrs::ia32_efer",  msrs::ia32_efer::get(), msg);
    });


    if (arch_perf_monitoring::eax::version_id::get() >= 2) {
        bfdebug_transaction(1, [&](std::string * msg) {
            bfdebug_subnhex(1, "msrs::ia32_perf_global_ctrl",  msrs::ia32_perf_global_ctrl::get(), msg);
        });
    }

    bfdebug_transaction(1, [&](std::string * msg) {
            bfdebug_subnhex(1, "guest_gdt.limit",  guest_gdt.limit(), msg);
            bfdebug_subnhex(1, "guest_idt.limit",  guest_idt.limit(), msg);
            bfdebug_subnhex(1, "guest_gdt.base",  guest_gdt.base(), msg);
            bfdebug_subnhex(1, "guest_idt.base",  guest_idt.base(), msg);

            bfdebug_subnhex(1, "es limit",  es_index != 0 ? guest_gdt.limit(es_index) : 0, msg);
            bfdebug_subnhex(1, "cs limit",  cs_index != 0 ? guest_gdt.limit(cs_index) : 0, msg);
            bfdebug_subnhex(1, "ss limit",  ss_index != 0 ? guest_gdt.limit(ss_index) : 0, msg);
            bfdebug_subnhex(1, "ds limit",  ds_index != 0 ? guest_gdt.limit(ds_index) : 0, msg);
            bfdebug_subnhex(1, "fs limit",  fs_index != 0 ? guest_gdt.limit(fs_index) : 0, msg);
            bfdebug_subnhex(1, "gs limit",  es_index != 0 ? guest_gdt.limit(gs_index) : 0, msg);
            bfdebug_subnhex(1, "ldtr limit",  ldtr_index != 0 ? guest_gdt.limit(ldtr_index) : 0, msg);
            bfdebug_subnhex(1, "tr limit",  tr_index != 0 ? guest_gdt.limit(tr_index) : 0, msg);

            bfdebug_subnhex(1, "es access rights",  es_index != 0 ? guest_gdt.access_rights(es_index) : unusable, msg);
            bfdebug_subnhex(1, "cs access rights",  cs_index != 0 ? guest_gdt.access_rights(cs_index) : unusable, msg);
            bfdebug_subnhex(1, "ss access rights",  ss_index != 0 ? guest_gdt.access_rights(ss_index) : unusable, msg);
            bfdebug_subnhex(1, "ds access rights",  ds_index != 0 ? guest_gdt.access_rights(ds_index) : unusable, msg);
            bfdebug_subnhex(1, "fs access rights",  fs_index != 0 ? guest_gdt.access_rights(fs_index) : unusable, msg);
            bfdebug_subnhex(1, "gs access rights",  gs_index != 0 ? guest_gdt.access_rights(gs_index) : unusable, msg);
            bfdebug_subnhex(1, "ldtr access rights",  ldtr_index != 0 ? guest_gdt.access_rights(ldtr_index) : unusable, msg);
            bfdebug_subnhex(1, "tr access rights",  tr_index != 0 ? guest_gdt.access_rights(tr_index) : type::tss_busy | 0x80U, msg);

            bfdebug_subnhex(1, "es base",  es_index != 0 ? guest_gdt.base(es_index) : 0, msg);
            bfdebug_subnhex(1, "cs base",  cs_index != 0 ? guest_gdt.base(cs_index) : 0, msg);
            bfdebug_subnhex(1, "ss base",  ss_index != 0 ? guest_gdt.base(ss_index) : 0, msg);
            bfdebug_subnhex(1, "ds base",  ds_index != 0 ? guest_gdt.base(ds_index) : 0, msg);

            bfdebug_subnhex(1, "fs base",  msrs::ia32_fs_base::get(), msg);
            bfdebug_subnhex(1, "gs base",  msrs::ia32_gs_base::get(), msg);

            bfdebug_subnhex(1, "ldtr base",  ldtr_index != 0 ? guest_gdt.base(ldtr_index) : 0, msg);
            bfdebug_subnhex(1, "tr base",  tr_index != 0 ? guest_gdt.base(tr_index) : 0, msg);

        bfdebug_subnhex(1, "cr0",  cr0::get() | ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get(), msg);
        bfdebug_subnhex(1, "cr3",  cr3::get(), msg);
        bfdebug_subnhex(1, "cr4",  cr4::get() | ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get(), msg);
        bfdebug_subnhex(1, "dr7",  dr7::get(), msg);

        bfdebug_subnhex(1, "rflags", ::x64::rflags::get(), msg);

        bfdebug_subnhex(1, "sysenter cs", msrs::ia32_sysenter_cs::get(), msg);
        bfdebug_subnhex(1, "sysenter esp", msrs::ia32_sysenter_esp::get(), msg);
        bfdebug_subnhex(1, "sysenter eip", msrs::ia32_sysenter_eip::get(), msg);

    });

    // ::intel_x64::vmcs::debug::dump(1);
#endif

}

void
vcpu::write_control_state()
{
    using namespace ::intel_x64::vmcs;

    auto ia32_vmx_pinbased_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_pinbased_ctls::get();
    auto ia32_vmx_procbased_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_procbased_ctls::get();
    auto ia32_vmx_exit_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_exit_ctls::get();
    auto ia32_vmx_entry_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_entry_ctls::get();

    pin_based_vm_execution_controls::set(
        ((ia32_vmx_pinbased_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_pinbased_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    primary_processor_based_vm_execution_controls::set(
        ((ia32_vmx_procbased_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_procbased_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    vm_exit_controls::set(
        ((ia32_vmx_exit_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_exit_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    vm_entry_controls::set(
        ((ia32_vmx_entry_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_entry_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    using namespace pin_based_vm_execution_controls;
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmap_a.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmap_b.get()));

    use_msr_bitmap::enable();
    //use_io_bitmaps::enable();
    unconditional_io_exiting::enable(); 

    activate_secondary_controls::enable_if_allowed();

    if (this->is_host_vm_vcpu()) {
        enable_rdtscp::enable_if_allowed();
        enable_invpcid::enable_if_allowed();
        enable_xsaves_xrstors::enable_if_allowed();
    }

    vm_exit_controls::save_debug_controls::enable();
    vm_exit_controls::host_address_space_size::enable();
    vm_exit_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    vm_exit_controls::save_ia32_pat::enable();
    vm_exit_controls::load_ia32_pat::enable();
    vm_exit_controls::save_ia32_efer::enable();
    vm_exit_controls::load_ia32_efer::enable();

    vm_entry_controls::load_debug_controls::enable();
    vm_entry_controls::ia_32e_mode_guest::enable();
    vm_entry_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    vm_entry_controls::load_ia32_pat::enable();
    vm_entry_controls::load_ia32_efer::enable();

}

//==============================================================================
// vCPU Delegates
//==============================================================================

void
vcpu::run_delegate(bfobject *obj)
{
    // TODO
    //
    // We need to implement a vCPU clear() function that is capable of
    // setting m_launched back to false and then clearing the VMCS. This
    // way, the next time this function is executed, a launch takes place
    // again. This is needed in order to perform a VMCS migration.
    //
    // Question: Do we need to re-setup all of the VMCS fields?
    //

    bfignored(obj);

    if (m_launched) {
        m_vmcs.resume();
    }
    else {

        m_launched = true;

        try {
            bfdebug_info(0, "launched vmm");    
            m_vmcs.load();
            m_vmcs.launch();
        }
        catch (...) {
            m_launched = false;
            throw;
        }

        ::x64::cpuid::get(0x4BF00010, 0, 0, 0);
        ::x64::cpuid::get(0x4BF00011, 0, 0, 0);
    }
}

void
vcpu::hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    ::x64::cpuid::get(0x4BF00020, 0, 0, 0);
    ::x64::cpuid::get(0x4BF00021, 0, 0, 0);
}

//==============================================================================
// VMCS Operations
//==============================================================================

void
vcpu::load()
{ m_vmcs.load(); }

void
vcpu::promote()
{ m_vmcs.promote(); }

bool
vcpu::advance()
{
    using namespace ::intel_x64::vmcs;

    this->set_rip(this->rip() + vm_exit_instruction_length::get());
    return true;
}

//==============================================================================
// Handler Operations
//==============================================================================

void
vcpu::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler.add_handler(reason, d); }

void
vcpu::add_exit_handler(
    const handler_delegate_t &d)
{ m_exit_handler.add_exit_handler(d); }

//==============================================================================
// Fault Handling
//==============================================================================

uint64_t
vcpu::lcd_gpa_to_hpa(uint64_t gpa, uint64_t eptp, bool verbose) {

    uint64_t hpa = eptp;  
   
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "eptl4 walk for gpa", gpa, msg);
        bfdebug_subnhex(0, "eptl4 (root) hpa", hpa, msg);

    });

    {
        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::intel_x64::ept::pml4::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::intel_x64::ept::pml4::entry::phys_addr::get(entry);

        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl4 etnry", entry, msg);
            });
    };


    {

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::intel_x64::ept::pdpt::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::intel_x64::ept::pdpt::entry::phys_addr::get(entry);

        if (::intel_x64::ept::pdpt::entry::ps::is_enabled(entry)) {
		    bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl3 etnry maps 1GB page", entry, msg);
            });
            return 0; 
        };

        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl3 etnry", entry, msg);
            });
    };


    {

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::intel_x64::ept::pd::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::intel_x64::ept::pd::entry::phys_addr::get(entry);

        if (::intel_x64::ept::pd::entry::ps::is_enabled(entry)) {
		    bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl2 etnry maps 2MB page", entry, msg);
            });
            return 0; 
        };


        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl2 etnry", entry, msg);
            });
    };

    {

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::intel_x64::ept::pt::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::intel_x64::ept::pt::entry::phys_addr::get(entry);

        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "eptl1 entry", entry, msg);
                bfdebug_subnhex(0, "eptl1 entry type", ::intel_x64::ept::pt::entry::memory_type::get(entry), msg);
                bfdebug_subnhex(0, "eptl1 entry ipat", ::intel_x64::ept::pt::entry::ignore_pat::is_enabled(entry), msg);
                bfdebug_subnhex(0, "hpa (frame)", hpa, msg);
                bfdebug_subnhex(0, "hpa", hpa + bfn::lower(gpa), msg);

            });
    };

    // if hpa is null, return null!
    return hpa ? hpa + bfn::lower(gpa) : 0ul;
};

uint64_t
vcpu::lcd_gpa_to_hpa(uint64_t gpa, bool verbose) {
    return lcd_gpa_to_hpa(gpa, ::intel_x64::vmcs::ept_pointer::phys_addr::get(), verbose);
};

uint64_t
vcpu::lcd_gva_to_gpa(uint64_t gva, uint64_t cr3, uint64_t eptp, bool verbose) {

    uint64_t gpa = cr3; 
    uint64_t hpa = 0; 

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "ptl4 walk for gva", gva, msg);
        bfdebug_subnhex(0, "ptl4 (root, aka CR3) gpa", gpa, msg);

    });

    {
        hpa = lcd_gpa_to_hpa(gpa, eptp);

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pml4::index(gva); 
        uint64_t entry = map.get()[index];

        gpa = ::x64::pml4::entry::phys_addr::get(entry);

        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "ptl4 etnry", entry, msg);
            });
    };


    {
        hpa = lcd_gpa_to_hpa(gpa, eptp);

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pdpt::index(gva); 
        uint64_t entry = map.get()[index];

        gpa = ::x64::pdpt::entry::phys_addr::get(entry);

        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "ptl3 etnry", entry, msg);
            });
    };


    {
        hpa = lcd_gpa_to_hpa(gpa, eptp);

        if(hpa == 0)
            return 0; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pd::index(gva); 
        uint64_t entry = map.get()[index];

        gpa = ::x64::pd::entry::phys_addr::get(entry);

        if (!::x64::pd::entry::ps::is_enabled(entry)) {
		    bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "ptl2 etnry doesn't map a 2MB page", entry, msg);
            });
        };


        if (verbose)
            bfdebug_transaction(0, [&](std::string * msg) {
                bfdebug_subnhex(0, "ptl2 etnry", entry, msg);
                bfdebug_subnhex(0, "gpa (frame)", gpa, msg);
                bfdebug_subnhex(0, "gpa", gpa + bfn::lower(gva, ::x64::pd::from), msg);
            });
    };

    return gpa + bfn::lower(gva, ::x64::pd::from); 
};

uint64_t
vcpu::lcd_gva_to_gpa(uint64_t gva, bool verbose) {
    return lcd_gva_to_gpa(gva, 
                ::intel_x64::vmcs::guest_cr3::get(), 
                ::intel_x64::vmcs::ept_pointer::phys_addr::get(), verbose);
};

void 
vcpu::dump_ept_entry(uint64_t gpa) {


    uint64_t hpa = ::intel_x64::vmcs::ept_pointer::phys_addr::get(); 
   
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "eptl4 walk for gpa", gpa, msg);
        bfdebug_subnhex(0, "eptl4 (root) hpa", hpa, msg);

    });

    {
        if (hpa == 0) 
            return; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pml4::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::x64::pml4::entry::phys_addr::get(entry);

        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_subnhex(0, "eptl4 etnry", entry, msg);
        });
    };


    {
        if (hpa == 0) 
            return; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pdpt::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::x64::pdpt::entry::phys_addr::get(entry);

        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_subnhex(0, "eptl3 etnry", entry, msg);
        });
    };


    {
        if (hpa == 0) 
            return; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pd::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::x64::pd::entry::phys_addr::get(entry);

        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_subnhex(0, "eptl2 etnry", entry, msg);
        });
    };

    {
        if (hpa == 0) 
            return; 

        auto map = this->map_hpa_4k<uint64_t>(hpa);
        uint64_t index = ::x64::pt::index(gpa); 
        uint64_t entry = map.get()[index];

        hpa = ::x64::pt::entry::phys_addr::get(entry);

        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_subnhex(0, "eptl1 etnry", entry, msg);
            bfdebug_subnhex(0, "hpa", hpa, msg);

        });
    };

}

void 
vcpu::dump_ept_pointers() {

    unsigned long long eptp = ::intel_x64::vmcs::ept_pointer::get();
    unsigned long long eptp_hpa = ::intel_x64::vmcs::ept_pointer::phys_addr::get(); 
    unsigned long long eptp_list = ::intel_x64::vmcs::eptp_list_address::get();
    unsigned long long current = 0;

    bfdebug_transaction(0, [&](std::string * msg) {
            bferror_subnhex(0, "ept_pointer", eptp, msg);
            ::intel_x64::vmcs::ept_pointer::dump(0, msg);
            bferror_subnhex(0, "eptp_list addres", eptp_list, msg);
            ::intel_x64::vmcs::eptp_list_address::dump(0, msg); 
//            bferror_subnhex(0, "eptp_index", eptp_index::get_if_exists(), msg);
//            eptp_index::dump(0, msg);
    });
    
    if (this->m_mmap->eptp() != eptp_hpa) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_info(0, "host EPT pointer doesn't match hardware (VMFUNC'ed?)", msg); 
            bfdebug_subnhex(0, "host EPT poiner", this->m_mmap->eptp(), msg); 
            bfdebug_subnhex(0, "hardware EPT poiner", eptp_hpa, msg);
        });
    }

    if(bfn::upper(eptp_list) != 0) {
        auto map = this->map_hpa_4k<uint64_t>(eptp_list);

        /* Dump as words (8 bytes) */
        while ( current < 16 ) {
            bfdebug_transaction(0, [&](std::string * msg) {
                std::string ln = "eptp list entry:";
                bfn::to_string(ln, current, 16);
                ln += " "; 
                bfn::to_string(ln, (unsigned long long)map.get()[current], 16);
                bfdebug_info(0, ln.c_str(), msg); 
            });
            current ++; 
        }
    };

}

#define PROC_NAME_MAX   16
#define IF_FLAG         (1 << 9)

#define IN_IRQ_SHIFT        0
#define IN_SOFTIRQ_SHIFT    1
#define IN_NMI_SHIFT        2

#define IN_IRQ              (1 << IN_IRQ_SHIFT)
#define IN_SOFTIRQ          (1 << IN_SOFTIRQ_SHIFT)
#define IN_NMI              (1 << IN_NMI_SHIFT)

#define EVENT_XMIT                      1
#define EVENT_MSIX_HANDLER              2
#define EVENT_NAPI_COMPLETE_DONE        3
#define EVENT_IRQ                       4
#define EVENT_NMI                       5
#define EVENT_EXCEPTION                 6
#define EVENT_IRQ_EXIT                  7
#define EVENT_SOFTIRQ_POLL              8
#define EVENT_NET_RX_ACTION             9
#define EVENT_VMFUNC_TRAMP_ENTRY        10
#define EVENT_VMFUNC_TRAMP_EXIT         11
#define EVENT_VMFUNC_SBOARD_KLCD_ENTER  12
#define EVENT_VMFUNC_SBOARD_KLCD_LEAVE  13
#define EVENT_DO_PAGE_FAULT             14
#define EVENT_DO_PAGE_FAULT_LEAVE       15
#define EVENT_DO_INT3                   16
#define EVENT_DO_INT3_LEAVE             17
#define EVENT_NMI_LEAVE                 18
#define EVENT_NMI_FULL                  19



struct ring_trace_entry {
	unsigned long rip;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long rdi;
	unsigned long lcd_stack;
	unsigned long gsbase;
	unsigned char context;
	unsigned char lcd_stack_bit;
	unsigned char lcd_nc;
	unsigned short pid;
	unsigned type;
	unsigned orig_type;
	char name[PROC_NAME_MAX];
};


struct ring_trace_header {
	unsigned long head;
	unsigned long size; 
};

struct ring_trace_buffer {
	struct ring_trace_header header; 
	struct ring_trace_entry entries[];
};


static const char *event_type_to_string(unsigned type)
{
    switch (type) {
        case EVENT_XMIT:
            return "XMIT";

        case EVENT_MSIX_HANDLER:
            return "MSIX_HANDLER";

        case EVENT_NAPI_COMPLETE_DONE:
            return "NAPI_COMP_DONE";

        case EVENT_IRQ:
            return "IRQ";

        case EVENT_NMI:
            return "NMI";

        case EVENT_EXCEPTION:
            return "EXCEPTION";

        case EVENT_IRQ_EXIT:
            return "IRQ_EXIT";

        case EVENT_SOFTIRQ_POLL:
            return "SOFTIRQ_POLL";

        case EVENT_NET_RX_ACTION:
            return "NET_RX_ACTION";

        case EVENT_VMFUNC_TRAMP_ENTRY:
            return "TRAMP_ENTRY";

        case EVENT_VMFUNC_TRAMP_EXIT:
            return "TRAMP_EXIT";

        case EVENT_VMFUNC_SBOARD_KLCD_ENTER:
            return "SBOARD_ENTER";

        case EVENT_VMFUNC_SBOARD_KLCD_LEAVE:
            return "SBOARD_LEAVE";

        case EVENT_DO_PAGE_FAULT:
            return "EVENT_DO_PAGE_FAULT";

        case EVENT_DO_PAGE_FAULT_LEAVE:
            return "EVENT_DO_PAGE_FAULT_LEAVE";

        case EVENT_DO_INT3:
            return "EVENT_DO_INT3";

        case EVENT_DO_INT3_LEAVE: 
            return "EVENT_DO_INT3_LEAVE";

        case EVENT_NMI_LEAVE:
            return "EVENT_NMI_LEAVE";

        case EVENT_NMI_FULL:
            return "EVENT_NMI_FULL";

        default:
            return "Undefined item";
    }
}

void vcpu::dump_ring_trace_buffer(struct ring_trace_buffer *trace_buf) 
{
    int i;
    unsigned long idx = trace_buf->header.head - 1;
    auto id = this->id();

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subndec(0, "head:", idx % trace_buf->header.size, msg);
    });

    for (i = 0; i < trace_buf->header.size; i++, idx--) {
        struct ring_trace_entry *entry = &trace_buf->entries[idx % trace_buf->header.size];
//      if (i == 0)
//          printk("head ==> ");

        bfdebug_transaction(0, [&](std::string * msg) {
        char buf[512] = {0};
#if 0
            std::string ln = "type: ";
            ln += event_type_to_string(entry->type);
            ln += "(";
            bfn::to_string(ln, entry->type, 16);
            ln += ") cpu: ";
            bfn::to_string(ln, this->id(), 10);
#endif
        sprintf(buf, "type:%16s(%x) cpu: %lu [%c|%c|%c] comm: %s pid: %d rip: %16lx rsp: %16lx "
                "rdi: %09lx gsbase: %16lx lcd_stack: %16lx[bmap: %x nc:%u] "
                "eflags: %08lx [IF: %d]\n",
                event_type_to_string(entry->type),
                entry->type,
                id,
                entry->context & (IN_NMI) ? 'N' : '-',
                entry->context & (IN_SOFTIRQ) ? 'S' : '-',
                entry->context & (IN_IRQ) ? 'I' : '-',
                entry->name, entry->pid, entry->rip,
                entry->rsp, entry->rdi, entry->gsbase, entry->lcd_stack,
                entry->lcd_stack_bit, entry->lcd_nc, entry->eflags,
                !!(entry->eflags & IF_FLAG));
            bfdebug_info(0, buf, msg);
        });
#if 0
        printk("type:%16s(%x) cpu: %d [%c|%c|%c] comm: %s pid: %d rip: %16lx rsp: %16lx "
                "rdi: %09lx gsbase: %16lx lcd_stack: %16lx[bmap: %x nc:%u] "
                "eflags: %08lx [IF: %d]\n",
                event_type_to_string(entry->type),
                entry->type,
                this->id(),
                entry->context & (IN_NMI) ? 'N' : '-',
                entry->context & (IN_SOFTIRQ) ? 'S' : '-',
                entry->context & (IN_IRQ) ? 'I' : '-',
                entry->name, entry->pid, entry->rip,
                entry->rsp, entry->rdi, entry->gsbase, entry->lcd_stack,
                entry->lcd_stack_bit, entry->lcd_nc, entry->eflags,
                !!(entry->eflags & IF_FLAG));
#endif
    }
}

void 
vcpu::dump_trace_log() {

    unsigned long eptp_list = ::intel_x64::vmcs::eptp_list_address::get();

    if(bfn::upper(eptp_list) == 0) {
        bfdebug_info(0, "EPT list pointer is NULL"); 
        return;
    };

    auto map = this->map_hpa_4k<uint64_t>(eptp_list);

    uint64_t trace_buffer_gva = map.get()[3];
    uint64_t trace_buffer_pages = map.get()[4];

#define PAGE_SIZE   4096
    uint64_t trace_buffer_size = trace_buffer_pages * PAGE_SIZE;

    if(bfn::upper(trace_buffer_gva) == 0) {
        bfdebug_info(0, "Trace buffer pointer is NULL"); 
        return;
    };

    if(bfn::upper(trace_buffer_size) == 0) {
        bfdebug_info(0, "Trace buffer size is NULL"); 
        return;
    };

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "Mapping trace buffer gpa:", trace_buffer_gva, msg);
        bferror_subnhex(0, "size (pages):", trace_buffer_pages, msg);
    });

    auto map_buffer = this->map_gva_4k<uint64_t>(trace_buffer_gva, trace_buffer_size);
    struct ring_trace_buffer *trace_buf = (struct ring_trace_buffer *) &map_buffer.get()[0];

    dump_ring_trace_buffer(trace_buf);

    return;
}

void 
vcpu::dump_instruction(uint64_t instr_gva) {
    /* Assume that entire stack page is mapped */
    unsigned long long size = 16; 
    unsigned long long current_address = instr_gva;

    //auto map = this->map_gva_4k<uint8_t>(instr_gva, size);
    uint64_t instr_gpa = lcd_gva_to_gpa(instr_gva, true);  

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "instr_gpa", instr_gpa, msg);
    });

    uint64_t instr_hpa = lcd_gpa_to_hpa(instr_gpa);

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "instr_hpa", instr_hpa, msg);
        bferror_subnhex(0, "bfn::upper(instr_hpa)", bfn::upper(instr_hpa), msg);
        bferror_subnhex(0, "bfn::lower(instr_hpa)", bfn::lower(instr_hpa), msg);
    });

    if (instr_hpa == 0) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_subnhex(0, "instr_hpa is null", instr_hpa, msg);
        });
    return; 
    }


    auto map = this->map_hpa_4k<uint8_t>(bfn::upper(instr_hpa));
    uint64_t offset = bfn::lower(instr_hpa); 


    bfdebug_transaction(0, [&](std::string * msg) {
        unsigned long long i = 0; 

        std::string ln = "instr starting at (rip):";
        bfn::to_string(ln, instr_gva, 16);
        ln += ":";

        /* Dump memory as individual bytes */
        while (current_address < instr_gva + size ) {
            bfn::to_string(ln, map.get()[offset + i], 16, false);
            ln += ", ";
            i ++; 
            current_address += sizeof(uint8_t);
        };
        bfdebug_info(0, ln.c_str(), msg); 
    }); 
}

#define PGSIZE          4096    
#define PGROUNDUP(sz)  (((sz)+PGSIZE-1) & ~(PGSIZE-1))

void 
vcpu::dump_as_stack(uint64_t *stack_hva, uint64_t stack) {
    unsigned long long roundup = PGROUNDUP(stack); 
    unsigned long long size = roundup - stack; 
    unsigned long long current = 0; 
    unsigned long long current_address = stack;
    unsigned long long current_rbp = this->rbp(); 

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "stack starting at", stack, msg);
        bferror_subnhex(0, "first frame (rbp)", this->rbp(), msg);
        bferror_subnhex(0, "top of stack page", roundup, msg);
    });

    if(size == 0) {
        bfdebug_info(0, "stack is empty"); 
        return;
    };

    /* Dump as words (8 bytes) */
    while ( current < 64 && (current_address < roundup)) {
        bfdebug_transaction(0, [&](std::string * msg) {

            if (current_rbp == stack + current * sizeof(void*)) {
                 std::string ln = "--- new frame --- (next rbp:";
                 bfn::to_string(ln, stack_hva[current], 16);
                
                 ln += ", saved ret:"; 
                 bfn::to_string(ln, stack_hva[current + 1], 16);
                 ln += ")"; 
                 
                 bfdebug_info(0, ln.c_str(), msg); 
                 current_rbp = stack_hva[current];  
            }

            std::string ln = "stack addr:";
            bfn::to_string(ln, current_address, 16);
            ln += " "; 
            bfn::to_string(ln, stack_hva[current], 16);
            bfdebug_info(0, ln.c_str(), msg); 
        });
        current ++; 
        current_address = stack + current * sizeof(void*); 
    }

};

void 
vcpu::dump_stack() {
    /* Assume that entire stack page is mapped */
    unsigned long long stack = this->rsp(); 
    uint64_t stack_gpa, stack_hpa;

//    if (this->m_mmap->eptp() != ::intel_x64::vmcs::ept_pointer::phys_addr::get()) {
//        bfdebug_transaction(0, [&](std::string * msg) {
//            bfdebug_info(0, "VMFUNC'ed not going to dump the stack (don't have EPT)", msg); 
//        });
//
//        return; 
//    };
  

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "Dumping stack from rsp", stack, msg);
    });

    stack_gpa = lcd_gva_to_gpa(stack);  

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "stack_gpa", stack_gpa, msg);
    });

    if (bfn::upper(stack_gpa) == 0) 
        return; 

    stack_hpa = lcd_gpa_to_hpa(stack_gpa);
    if (bfn::upper(stack_hpa) == 0) 
        return; 

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "stack_hpa", stack_hpa, msg);
        bfdebug_subnhex(0, "bfn::upper(stack_hpa)", bfn::upper(stack_hpa), msg);
        bfdebug_subnhex(0, "bfn::lower(stack_hpa)", bfn::lower(stack_hpa), msg);
    });

    auto map = this->map_hpa_4k<uint64_t>(bfn::upper(stack_hpa));

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "mapped stack page ok", msg);
    });

    dump_as_stack(&map.get()[0], stack); 
}

void 
vcpu::dump_exception_stack() {
    /* Assume that entire stack page is mapped */
    unsigned long long stack = this->rsp(); 
    unsigned long long roundup = PGROUNDUP(stack); 
    unsigned long long size = roundup - stack; 
    uint64_t stack_gpa, stack_hpa;

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "Exception stack starting at (rsp)", this->rsp(), msg);
        bfdebug_subnhex(0, "roundup page", roundup, msg);
    });

    if (size == 0) {
        bfdebug_info(0, "Exception stack is empty"); 
        return;
    };

    stack_gpa = lcd_gva_to_gpa(stack);  

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "stack_gpa", stack_gpa, msg);
    });

    if (bfn::upper(stack_gpa) == 0) 
        return; 

    stack_hpa = lcd_gpa_to_hpa(stack_gpa);

    if (bfn::upper(stack_hpa) == 0) 
        return; 

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "stack_hpa", stack_hpa, msg);
        bferror_subnhex(0, "bfn::upper(stack_hpa)", bfn::upper(stack_hpa), msg);
        bferror_subnhex(0, "bfn::lower(stack_hpa)", bfn::lower(stack_hpa), msg);
    });

    auto map = this->map_hpa_4k<uint64_t>(bfn::upper(stack_hpa));
    uint64_t offset = bfn::lower(stack_hpa); 

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_info(0, "mapped ok, exception frame:", msg);
    });

    if ((offset % sizeof(uint64_t)) != 0) {
        bfdebug_transaction(0, [&](std::string * msg) {
                bferror_subnhex(0, "offset \% sizeof(uint64_t)", offset % sizeof(uint64_t), msg);
        });
    };

    // Ideally 7 values are pushed onto the stack whenever exception happens.
    // The offsets are as follows.  However, some exceptions such as debug
    // pushes only 6 values.
    auto regs_on_stack = size / sizeof(uint64_t);
    auto rax_off = 0;
    auto err_off = 1;
    auto rip_off = 2;
    auto cs_off = 3;
    auto flags_off = 4;
    auto rsp_off = 5;
    auto ss_off = 6;

    if (regs_on_stack < 7) {
        bfdebug_transaction(0, [&](std::string * msg) {
                bferror_subnhex(0, "WARN: exception stack size: ", size, msg);
        });
    }

    if (regs_on_stack == 6) {
        rax_off = 0;
        rip_off = 1;
        cs_off = 2;
        flags_off = 3;
        rsp_off = 4;
        ss_off = 5;
    }

    bfdebug_transaction(0, [&](std::string * msg) {
            bferror_subnhex(0, "saved rax",  map.get()[offset/sizeof(uint64_t) + rax_off], msg);

            if (regs_on_stack == 7)
                bferror_subnhex(0, "error code",  map.get()[offset/sizeof(uint64_t) + err_off], msg);

            bferror_subnhex(0, "rip",  map.get()[offset/sizeof(uint64_t) + rip_off], msg);
            bferror_subnhex(0, "cs",  map.get()[offset/sizeof(uint64_t) + cs_off], msg);
            bferror_subnhex(0, "flags",  map.get()[offset/sizeof(uint64_t) + flags_off], msg);
            bferror_subnhex(0, "rsp",  map.get()[offset/sizeof(uint64_t) + rsp_off], msg);
            bferror_subnhex(0, "ss",  map.get()[offset/sizeof(uint64_t) + ss_off], msg);
            });

    /* Dump instruction pointed by the RIP onthe frame */
    dump_instruction(map.get()[offset/sizeof(uint64_t) + rip_off]);

//    bfdebug_transaction(0, [&](std::string * msg) {
//        bferror_subnhex(0, "s1",  map.get()[offset/sizeof(uint64_t) + 7], msg);
//        bferror_subnhex(0, "s2",  map.get()[offset/sizeof(uint64_t) + 8], msg);
//        bferror_subnhex(0, "s3",  map.get()[offset/sizeof(uint64_t) + 9], msg);
//        bferror_subnhex(0, "s4",  map.get()[offset/sizeof(uint64_t) + 10], msg);
//        bferror_subnhex(0, "s5",  map.get()[offset/sizeof(uint64_t) + 11], msg);
//        bferror_subnhex(0, "s6",  map.get()[offset/sizeof(uint64_t) + 12], msg);
//        bferror_subnhex(0, "s7",  map.get()[offset/sizeof(uint64_t) + 13], msg);
//    });

    uint64_t saved_rsp = map.get()[offset/sizeof(uint64_t) + rsp_off];
    if ((saved_rsp >= stack) && (saved_rsp < roundup)) {
        /* Dump the stack of the program right before the 
         * exception, in this case it's on the same page */
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_info(0, "Dump stack saved in the exception frame:", msg);
        });

        uint64_t offset = bfn::lower(stack_hpa); 

        dump_as_stack(&map.get()[bfn::lower(saved_rsp)/sizeof(uint64_t)], saved_rsp); 

        /* RBP is pointing somewhere else... lets dump that somewhere else in 
         * case there is something useful there */
        if(!((this->rbp() >= stack) && (this->rbp() < roundup))) {
            uint64_t rbp_stack;
            uint64_t rbp_stack_gpa, rbp_stack_hpa;

            bfdebug_transaction(0, [&](std::string * msg) {
                bferror_info(0, "Dump stack starting from rbp:", msg);
            });

            rbp_stack = this->rbp();
            rbp_stack_gpa = lcd_gva_to_gpa(rbp_stack);  

            bfdebug_transaction(0, [&](std::string * msg) {
                bferror_subnhex(0, "rbp_stack_gpa", rbp_stack_gpa, msg);
            });

            rbp_stack_hpa = lcd_gpa_to_hpa(stack_gpa);

            bfdebug_transaction(0, [&](std::string * msg) {
                bferror_subnhex(0, "rbp_stack_hpa", rbp_stack_hpa, msg);
                bferror_subnhex(0, "bfn::upper(rbp_stack_hpa)", bfn::upper(rbp_stack_hpa), msg);
                bferror_subnhex(0, "bfn::lower(rbp_stack_hpa)", bfn::lower(rbp_stack_hpa), msg);
            });

            auto rbp_map = this->map_hpa_4k<uint64_t>(bfn::upper(rbp_stack_hpa));
            uint64_t offset = bfn::lower(rbp_stack_hpa); 

            bfdebug_transaction(0, [&](std::string * msg) {
                bferror_info(0, "mapped ok, rbp stack:", msg);
            });

            if ((offset % sizeof(uint64_t)) != 0) {
                bfdebug_transaction(0, [&](std::string * msg) {
                    bferror_subnhex(0, "offset \% sizeof(uint64_t)", offset % sizeof(uint64_t), msg);
                });
            };

            dump_as_stack(&rbp_map.get()[offset/sizeof(uint64_t)], rbp_stack); 
        }
    }
}

static uint64_t idt_entry_offset(uint64_t *idt, unsigned int index)
{
    auto sd1 = idt[(index * 2U) + 0U];
    auto sd2 = idt[(index * 2U) + 1U];

    auto base_15_00 = ((sd1 & 0x000000000000FFFFULL) >> 0);
    auto base_31_16 = ((sd1 & 0xFFFF000000000000ULL) >> 32);
    auto base_63_32 = ((sd2 & 0x00000000FFFFFFFFULL) << 32);

    return base_63_32 | base_31_16 | base_15_00;
};

void 
vcpu::dump_idt() {
    unsigned long long idt = ::intel_x64::vmcs::guest_idtr_base::get();
    unsigned long long idt_size = ::intel_x64::vmcs::guest_idtr_limit::get();
    unsigned long long idt_gpa, idt_hpa;

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_subnhex(0, "Dump IDT at", idt, msg);
    });

    idt_gpa = lcd_gva_to_gpa(idt);  

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "idt_gpa", idt_gpa, msg);
    });

    if (bfn::upper(idt_gpa) == 0) 
        return; 

    idt_hpa = lcd_gpa_to_hpa(idt_gpa);
    if (bfn::upper(idt_hpa) == 0) 
        return; 

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "idt_hpa", idt_hpa, msg);
        bferror_subndec(0, "idt size", idt_size, msg);
    });

    auto map = this->map_hpa_4k<uint64_t>(bfn::upper(idt_hpa));

    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_info(0, "mapped idt ok", msg);
    });

    /* Assume IDT is page aligned */
    for (int i = 0; i < 32; i++) {
        uint64_t offset = idt_entry_offset(&map.get()[0], i); 

        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_subndec(0, "entry", i, msg);
            bferror_subnhex(0, "offset", offset, msg);
        });
    }

}


void
vcpu::dump(const char *str)
{
    using namespace ::intel_x64::vmcs;

    bfdebug_transaction(0, [&](std::string * msg) {

        bferror_lnbr(0, msg);
        bferror_info(0, str, msg);
        bferror_brk1(0, msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "general purpose registers", msg);
        bferror_subnhex(0, "rax", this->rax(), msg);
        bferror_subnhex(0, "rbx", this->rbx(), msg);
        bferror_subnhex(0, "rcx", this->rcx(), msg);
        bferror_subnhex(0, "rdx", this->rdx(), msg);
        bferror_subnhex(0, "rbp", this->rbp(), msg);
        bferror_subnhex(0, "rsi", this->rsi(), msg);
        bferror_subnhex(0, "rdi", this->rdi(), msg);
        bferror_subnhex(0, "r08", this->r08(), msg);
        bferror_subnhex(0, "r09", this->r09(), msg);
        bferror_subnhex(0, "r10", this->r10(), msg);
        bferror_subnhex(0, "r11", this->r11(), msg);
        bferror_subnhex(0, "r12", this->r12(), msg);
        bferror_subnhex(0, "r13", this->r13(), msg);
        bferror_subnhex(0, "r14", this->r14(), msg);
        bferror_subnhex(0, "r15", this->r15(), msg);
        bferror_subnhex(0, "rip", this->rip(), msg);
        bferror_subnhex(0, "rsp", this->rsp(), msg);
        bferror_subnhex(0, "gr1", this->gr1(), msg);
        bferror_subnhex(0, "gr2", this->gr2(), msg);
        bferror_subnhex(0, "gr3", this->gr3(), msg);
        bferror_subnhex(0, "gr4", this->gr4(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "control registers", msg);
        bferror_subnhex(0, "cr0", guest_cr0::get(), msg);
        bferror_subnhex(0, "cr2", ::intel_x64::cr2::get(), msg);
        bferror_subnhex(0, "cr3", guest_cr3::get(), msg);
        bferror_subnhex(0, "cr4", guest_cr4::get(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "addressing", msg);
        bferror_subnhex(0, "linear address", guest_linear_address::get(), msg);
        bferror_subnhex(0, "physical address", guest_physical_address::get(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "exit info", msg);
        bferror_subnhex(0, "reason", exit_reason::get(), msg);
        bferror_subtext(0, "description", exit_reason::basic_exit_reason::description(), msg);
        bferror_subnhex(0, "qualification", exit_qualification::get(), msg);
    });

    if (exit_reason::vm_entry_failure::is_enabled()) {
        m_vmcs.check();
    }

    dump_perf_counters();

    ::intel_x64::vmcs::debug::dump();

    dump_ept_pointers();
    auto err_gpa = lcd_gva_to_gpa(guest_linear_address::get());
    uint64_t err_hpa = lcd_gpa_to_hpa(err_gpa);
    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_subnhex(0, "err_hpa", err_hpa, msg);
    });
    dump_instruction(this->rip()); 
    dump_stack();
    
    dump_trace_log();

    bfdebug_info(0, "Done dumping state");
}

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());
    ::x64::pm::stop();
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

void
vcpu::add_wrcr0_handler(
    vmcs_n::value_type mask, const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr0_handler(d);
    m_control_register_handler.enable_wrcr0_exiting(mask);
}

void
vcpu::add_rdcr3_handler(
    const handler_delegate_t &d)
{
    m_control_register_handler.add_rdcr3_handler(d);
    m_control_register_handler.enable_rdcr3_exiting();
}

void
vcpu::add_wrcr3_handler(
    const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr3_handler(d);
    m_control_register_handler.enable_wrcr3_exiting();
}

void
vcpu::add_wrcr4_handler(
    vmcs_n::value_type mask, const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr4_handler(d);
    m_control_register_handler.enable_wrcr4_exiting(mask);
}

void
vcpu::execute_wrcr0()
{ m_control_register_handler.execute_wrcr0(this); }

void
vcpu::execute_rdcr3()
{ m_control_register_handler.execute_rdcr3(this); }

void
vcpu::execute_wrcr3()
{ m_control_register_handler.execute_wrcr3(this); }

void
vcpu::execute_wrcr4()
{ m_control_register_handler.execute_wrcr4(this); }

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

void
vcpu::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const handler_delegate_t &d)
{ m_cpuid_handler.add_handler(leaf, d); }

void
vcpu::add_cpuid_emulator(
    cpuid_handler::leaf_t leaf, const handler_delegate_t &d)
{ m_cpuid_handler.add_emulator(leaf, d); }

void
vcpu::execute_cpuid()
{ m_cpuid_handler.execute(this); }

void
vcpu::enable_cpuid_whitelisting() noexcept
{ m_cpuid_handler.enable_whitelisting(); }

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

void
vcpu::add_ept_misconfiguration_handler(
    const ept_misconfiguration_handler::handler_delegate_t &d)
{ m_ept_misconfiguration_handler.add_handler(d); }

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

void
vcpu::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_read_handler(d); }

void
vcpu::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_write_handler(d); }

void
vcpu::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_execute_handler(d); }

void
vcpu::add_default_ept_read_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_read_handler(d); }

void
vcpu::add_default_ept_write_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_write_handler(d); }

void
vcpu::add_default_ept_execute_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_execute_handler(d); }

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

void
vcpu::add_external_interrupt_handler(
    const external_interrupt_handler::handler_delegate_t &d)
{
    m_external_interrupt_handler.add_handler(d);
    m_external_interrupt_handler.enable_exiting();
}

void
vcpu::disable_external_interrupts()
{ m_external_interrupt_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

void
vcpu::queue_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.queue_external_interrupt(vector); }

void
vcpu::inject_exception(uint64_t vector, uint64_t ec)
{ m_interrupt_window_handler.inject_exception(vector, ec); }

void
vcpu::inject_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.inject_external_interrupt(vector); }

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

void
vcpu::trap_on_all_io_instruction_accesses()
{ m_io_instruction_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_all_io_instruction_accesses()
{ m_io_instruction_handler.pass_through_all_accesses(); }

void
vcpu::pass_through_io_accesses(vmcs_n::value_type port)
{ m_io_instruction_handler.pass_through_access(port); }

void
vcpu::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    m_io_instruction_handler.trap_on_access(port);
    m_io_instruction_handler.add_handler(port, in_d, out_d);
}

void
vcpu::emulate_io_instruction(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    this->add_io_instruction_handler(port, in_d, out_d);
    m_io_instruction_handler.emulate(port);
}

void
vcpu::add_default_io_instruction_handler(
    const ::handler_delegate_t &d)
{ m_io_instruction_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

void
vcpu::add_monitor_trap_handler(
    const monitor_trap_handler::handler_delegate_t &d)
{ m_monitor_trap_handler.add_handler(d); }

void
vcpu::enable_monitor_trap_flag()
{ m_monitor_trap_handler.enable(); }

//--------------------------------------------------------------------------
// Non-Maskable Interrupt Window
//--------------------------------------------------------------------------

void
vcpu::queue_nmi()
{ m_nmi_window_handler.queue_nmi(); }

void
vcpu::inject_nmi()
{ m_nmi_window_handler.inject_nmi(); }

//--------------------------------------------------------------------------
// Non-Maskable Interrupts
//--------------------------------------------------------------------------

void
vcpu::add_nmi_handler(
    const nmi_handler::handler_delegate_t &d)
{
    m_nmi_handler.add_handler(d);
    m_nmi_handler.enable_exiting();
}

void
vcpu::enable_nmis()
{ m_nmi_handler.enable_exiting(); }

void
vcpu::disable_nmis()
{ m_nmi_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_rdmsr_accesses()
{ m_rdmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_rdmsr_accesses()
{ m_rdmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    m_rdmsr_handler.trap_on_access(msr);
    m_rdmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_rdmsr(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    this->add_rdmsr_handler(msr, d);
    m_rdmsr_handler.emulate(msr);
}

void
vcpu::add_default_rdmsr_handler(
    const ::handler_delegate_t &d)
{ m_rdmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_wrmsr_accesses()
{ m_wrmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_wrmsr_accesses()
{ m_wrmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    m_wrmsr_handler.trap_on_access(msr);
    m_wrmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_wrmsr(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    this->add_wrmsr_handler(msr, d);
    m_wrmsr_handler.emulate(msr);
}

void
vcpu::add_default_wrmsr_handler(
    const ::handler_delegate_t &d)
{ m_wrmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// XSetBV
//--------------------------------------------------------------------------

void
vcpu::add_xsetbv_handler(
    const xsetbv_handler::handler_delegate_t &d)
{ m_xsetbv_handler.add_handler(d); }

//--------------------------------------------------------------------------
// VMX preemption timer
//--------------------------------------------------------------------------

void
vcpu::add_preemption_timer_handler(
    const preemption_timer_handler::handler_delegate_t &d)
{ m_preemption_timer_handler.add_handler(d); }

void
vcpu::set_preemption_timer(
    const preemption_timer_handler::value_t val)
{
    m_preemption_timer_handler.enable_exiting();
    m_preemption_timer_handler.set_timer(val);
}

preemption_timer_handler::value_t
vcpu::get_preemption_timer()
{ return m_preemption_timer_handler.get_timer(); }

void
vcpu::enable_preemption_timer()
{ m_preemption_timer_handler.enable_exiting(); }

void
vcpu::disable_preemption_timer()
{ m_preemption_timer_handler.disable_exiting(); }

//==========================================================================
// EPT
//==========================================================================

void
vcpu::set_eptp(ept::mmap &map)
{
    m_ept_handler.set_eptp(&map);
    m_mmap = &map;
}

void
vcpu::disable_ept()
{
    m_ept_handler.set_eptp(nullptr);
    m_mmap = nullptr;
}

//==========================================================================
// VPID
//==========================================================================

void
vcpu::enable_vpid()
{ m_vpid_handler.enable(); }

void
vcpu::disable_vpid()
{ m_vpid_handler.disable(); }

//==========================================================================
// Helpers
//==========================================================================

void
vcpu::trap_on_msr_access(vmcs_n::value_type msr)
{
    this->trap_on_rdmsr_access(msr);
    this->trap_on_wrmsr_access(msr);
}

void
vcpu::pass_through_msr_access(vmcs_n::value_type msr)
{
    this->pass_through_rdmsr_access(msr);
    this->pass_through_wrmsr_access(msr);
}

//==============================================================================
// Memory Mapping
//==============================================================================

/// TODO
///
/// There are several things that still need to be implemented for memory
/// mapping to make this a complete set of APIs.
/// - Currently, there is no support for a 32bit guest. We currently assume
///   that CR3 is 64bit.
/// - Currently, we have a lot of support for the different page sizes, but
///   we do not handle them in the guest WRT to mapping a GVA to the VMM. We
///   only support 4k granularity.

std::pair<uintptr_t, uintptr_t>
vcpu::gpa_to_hpa(uintptr_t gpa)
{
    if (m_mmap == nullptr) {
        return {gpa, 0};
    }

    return m_mmap->virt_to_phys(gpa);
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_gpa(uint64_t gva)
{
    using namespace ::x64;
    using namespace vmcs_n;

    if (guest_cr0::paging::is_disabled()) {
        return {gva, 0};
    }

    // -------------------------------------------------------------------------
    // PML4

    auto pml4_pte =
        get_entry(bfn::upper(this->cr3()), pml4::index(gva));

    if (pml4::entry::present::is_disabled(pml4_pte)) {
        throw std::runtime_error("pml4_pte is not present");
    }

    // -------------------------------------------------------------------------
    // PDPT

    auto pdpt_pte =
        get_entry(pml4::entry::phys_addr::get(pml4_pte), pdpt::index(gva));

    if (pdpt::entry::present::is_disabled(pdpt_pte)) {
        throw std::runtime_error("pdpt_pte is not present");
    }

    if (pdpt::entry::ps::is_enabled(pdpt_pte)) {
        return {
            pdpt::entry::phys_addr::get(pdpt_pte) | bfn::lower(gva, pdpt::from),
            pdpt::from
        };
    }

    // -------------------------------------------------------------------------
    // PD

    auto pd_pte =
        get_entry(pdpt::entry::phys_addr::get(pdpt_pte), pd::index(gva));

    if (pd::entry::present::is_disabled(pd_pte)) {
        throw std::runtime_error("pd_pte is not present");
    }

    if (pd::entry::ps::is_enabled(pd_pte)) {
        return {
            pd::entry::phys_addr::get(pd_pte) | bfn::lower(gva, pd::from),
            pd::from
        };
    }

    // -------------------------------------------------------------------------
    // PT

    auto pt_pte =
        get_entry(pd::entry::phys_addr::get(pd_pte), pt::index(gva));

    if (pt::entry::present::is_disabled(pt_pte)) {
        throw std::runtime_error("pt_pte is not present");
    }

    return {
        pt::entry::phys_addr::get(pt_pte) | bfn::lower(gva, pt::from),
        pt::from
    };
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_hpa(uint64_t gva)
{
    auto ret = this->gva_to_gpa(gva);

    if (m_mmap == nullptr) {
        return ret;
    }

    return this->gpa_to_hpa(ret.first);
}

void
vcpu::map_1g_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_2m_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_4k_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

uintptr_t
vcpu::get_entry(uintptr_t tble_gpa, std::ptrdiff_t index)
{
    auto tble = this->map_gpa_4k<uintptr_t>(tble_gpa);
    auto span = gsl::span(tble.get(), ::x64::pt::num_entries);

    return span[index];
}

//==============================================================================
// Registers
//==============================================================================

uint64_t
vcpu::rax() const noexcept
{ return m_state.rax; }

void
vcpu::set_rax(uint64_t val) noexcept
{ m_state.rax = val; }

uint64_t
vcpu::rbx() const noexcept
{ return m_state.rbx; }

void
vcpu::set_rbx(uint64_t val) noexcept
{ m_state.rbx = val; }

uint64_t
vcpu::rcx() const noexcept
{ return m_state.rcx; }

void
vcpu::set_rcx(uint64_t val) noexcept
{ m_state.rcx = val; }

uint64_t
vcpu::rdx() const noexcept
{ return m_state.rdx; }

void
vcpu::set_rdx(uint64_t val) noexcept
{ m_state.rdx = val; }

uint64_t
vcpu::rbp() const noexcept
{ return m_state.rbp; }

void
vcpu::set_rbp(uint64_t val) noexcept
{ m_state.rbp = val; }

uint64_t
vcpu::rsi() const noexcept
{ return m_state.rsi; }

void
vcpu::set_rsi(uint64_t val) noexcept
{ m_state.rsi = val; }

uint64_t
vcpu::rdi() const noexcept
{ return m_state.rdi; }

void
vcpu::set_rdi(uint64_t val) noexcept
{ m_state.rdi = val; }

uint64_t
vcpu::r08() const noexcept
{ return m_state.r08; }

void
vcpu::set_r08(uint64_t val) noexcept
{ m_state.r08 = val; }

uint64_t
vcpu::r09() const noexcept
{ return m_state.r09; }

void
vcpu::set_r09(uint64_t val) noexcept
{ m_state.r09 = val; }

uint64_t
vcpu::r10() const noexcept
{ return m_state.r10; }

void
vcpu::set_r10(uint64_t val) noexcept
{ m_state.r10 = val; }

uint64_t
vcpu::r11() const noexcept
{ return m_state.r11; }

void
vcpu::set_r11(uint64_t val) noexcept
{ m_state.r11 = val; }

uint64_t
vcpu::r12() const noexcept
{ return m_state.r12; }

void
vcpu::set_r12(uint64_t val) noexcept
{ m_state.r12 = val; }

uint64_t
vcpu::r13() const noexcept
{ return m_state.r13; }

void
vcpu::set_r13(uint64_t val) noexcept
{ m_state.r13 = val; }

uint64_t
vcpu::r14() const noexcept
{ return m_state.r14; }

void
vcpu::set_r14(uint64_t val) noexcept
{ m_state.r14 = val; }

uint64_t
vcpu::r15() const noexcept
{ return m_state.r15; }

void
vcpu::set_r15(uint64_t val) noexcept
{ m_state.r15 = val; }

uint64_t
vcpu::rip() const noexcept
{ return m_state.rip; }

void
vcpu::set_rip(uint64_t val) noexcept
{ m_state.rip = val; }

uint64_t
vcpu::rsp() const noexcept
{ return m_state.rsp; }

void
vcpu::set_rsp(uint64_t val) noexcept
{ m_state.rsp = val; }

uint64_t
vcpu::gdt_base() const noexcept
{ return vmcs_n::guest_gdtr_base::get(); }

void
vcpu::set_gdt_base(uint64_t val) noexcept
{ vmcs_n::guest_gdtr_base::set(val); }

uint64_t
vcpu::gdt_limit() const noexcept
{ return vmcs_n::guest_gdtr_limit::get(); }

void
vcpu::set_gdt_limit(uint64_t val) noexcept
{ vmcs_n::guest_gdtr_limit::set(val); }

uint64_t
vcpu::idt_base() const noexcept
{ return vmcs_n::guest_idtr_base::get(); }

void
vcpu::set_idt_base(uint64_t val) noexcept
{ vmcs_n::guest_idtr_base::set(val); }

uint64_t
vcpu::idt_limit() const noexcept
{ return vmcs_n::guest_idtr_limit::get(); }

void
vcpu::set_idt_limit(uint64_t val) noexcept
{ vmcs_n::guest_idtr_limit::set(val); }

uint64_t
vcpu::cr0() const noexcept
{ return vmcs_n::cr0_read_shadow::get(); }

void
vcpu::set_cr0(uint64_t val) noexcept
{
    vmcs_n::cr0_read_shadow::set(val);
    vmcs_n::guest_cr0::set(val | m_global_state->ia32_vmx_cr0_fixed0);
}

uint64_t
vcpu::cr3() const noexcept
{ return vmcs_n::guest_cr3::get(); }

void
vcpu::set_cr3(uint64_t val) noexcept
{
    vmcs_n::guest_cr3::set(val & 0x7FFFFFFFFFFFFFFF);
}

uint64_t
vcpu::cr4() const noexcept
{ return vmcs_n::cr4_read_shadow::get(); }

void
vcpu::set_cr4(uint64_t val) noexcept
{
    vmcs_n::cr4_read_shadow::set(val);
    vmcs_n::guest_cr4::set(val | m_global_state->ia32_vmx_cr4_fixed0);
}

uint64_t
vcpu::ia32_efer() const noexcept
{ return vmcs_n::guest_ia32_efer::get(); }

void
vcpu::set_ia32_efer(uint64_t val) noexcept
{ vmcs_n::guest_ia32_efer::set(val); }

uint64_t
vcpu::ia32_pat() const noexcept
{ return vmcs_n::guest_ia32_pat::get(); }

void
vcpu::set_ia32_pat(uint64_t val) noexcept
{ vmcs_n::guest_ia32_pat::set(val); }


uint64_t
vcpu::es_selector() const noexcept
{ return vmcs_n::guest_es_selector::get(); }

void
vcpu::set_es_selector(uint64_t val) noexcept
{ vmcs_n::guest_es_selector::set(val); }

uint64_t
vcpu::es_base() const noexcept
{ return vmcs_n::guest_es_base::get(); }

void
vcpu::set_es_base(uint64_t val) noexcept
{ vmcs_n::guest_es_base::set(val); }

uint64_t
vcpu::es_limit() const noexcept
{ return vmcs_n::guest_es_limit::get(); }

void
vcpu::set_es_limit(uint64_t val) noexcept
{ vmcs_n::guest_es_limit::set(val); }

uint64_t
vcpu::es_access_rights() const noexcept
{ return vmcs_n::guest_es_access_rights::get(); }

void
vcpu::set_es_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_es_access_rights::set(val); }

uint64_t
vcpu::cs_selector() const noexcept
{ return vmcs_n::guest_cs_selector::get(); }

void
vcpu::set_cs_selector(uint64_t val) noexcept
{ vmcs_n::guest_cs_selector::set(val); }

uint64_t
vcpu::cs_base() const noexcept
{ return vmcs_n::guest_cs_base::get(); }

void
vcpu::set_cs_base(uint64_t val) noexcept
{ vmcs_n::guest_cs_base::set(val); }

uint64_t
vcpu::cs_limit() const noexcept
{ return vmcs_n::guest_cs_limit::get(); }

void
vcpu::set_cs_limit(uint64_t val) noexcept
{ vmcs_n::guest_cs_limit::set(val); }

uint64_t
vcpu::cs_access_rights() const noexcept
{ return vmcs_n::guest_cs_access_rights::get(); }

void
vcpu::set_cs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_cs_access_rights::set(val); }

uint64_t
vcpu::ss_selector() const noexcept
{ return vmcs_n::guest_ss_selector::get(); }

void
vcpu::set_ss_selector(uint64_t val) noexcept
{ vmcs_n::guest_ss_selector::set(val); }

uint64_t
vcpu::ss_base() const noexcept
{ return vmcs_n::guest_ss_base::get(); }

void
vcpu::set_ss_base(uint64_t val) noexcept
{ vmcs_n::guest_ss_base::set(val); }

uint64_t
vcpu::ss_limit() const noexcept
{ return vmcs_n::guest_ss_limit::get(); }

void
vcpu::set_ss_limit(uint64_t val) noexcept
{ vmcs_n::guest_ss_limit::set(val); }

uint64_t
vcpu::ss_access_rights() const noexcept
{ return vmcs_n::guest_ss_access_rights::get(); }

void
vcpu::set_ss_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ss_access_rights::set(val); }

uint64_t
vcpu::ds_selector() const noexcept
{ return vmcs_n::guest_ds_selector::get(); }

void
vcpu::set_ds_selector(uint64_t val) noexcept
{ vmcs_n::guest_ds_selector::set(val); }

uint64_t
vcpu::ds_base() const noexcept
{ return vmcs_n::guest_ds_base::get(); }

void
vcpu::set_ds_base(uint64_t val) noexcept
{ vmcs_n::guest_ds_base::set(val); }

uint64_t
vcpu::ds_limit() const noexcept
{ return vmcs_n::guest_ds_limit::get(); }

void
vcpu::set_ds_limit(uint64_t val) noexcept
{ vmcs_n::guest_ds_limit::set(val); }

uint64_t
vcpu::ds_access_rights() const noexcept
{ return vmcs_n::guest_ds_access_rights::get(); }

void
vcpu::set_ds_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ds_access_rights::set(val); }

uint64_t
vcpu::fs_selector() const noexcept
{ return vmcs_n::guest_fs_selector::get(); }

void
vcpu::set_fs_selector(uint64_t val) noexcept
{ vmcs_n::guest_fs_selector::set(val); }

uint64_t
vcpu::fs_base() const noexcept
{ return vmcs_n::guest_fs_base::get(); }

void
vcpu::set_fs_base(uint64_t val) noexcept
{ vmcs_n::guest_fs_base::set(val); }

uint64_t
vcpu::fs_limit() const noexcept
{ return vmcs_n::guest_fs_limit::get(); }

void
vcpu::set_fs_limit(uint64_t val) noexcept
{ vmcs_n::guest_fs_limit::set(val); }

uint64_t
vcpu::fs_access_rights() const noexcept
{ return vmcs_n::guest_fs_access_rights::get(); }

void
vcpu::set_fs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_fs_access_rights::set(val); }

uint64_t
vcpu::gs_selector() const noexcept
{ return vmcs_n::guest_gs_selector::get(); }

void
vcpu::set_gs_selector(uint64_t val) noexcept
{ vmcs_n::guest_gs_selector::set(val); }

uint64_t
vcpu::gs_base() const noexcept
{ return vmcs_n::guest_gs_base::get(); }

void
vcpu::set_gs_base(uint64_t val) noexcept
{ vmcs_n::guest_gs_base::set(val); }

uint64_t
vcpu::gs_limit() const noexcept
{ return vmcs_n::guest_gs_limit::get(); }

void
vcpu::set_gs_limit(uint64_t val) noexcept
{ vmcs_n::guest_gs_limit::set(val); }

uint64_t
vcpu::gs_access_rights() const noexcept
{ return vmcs_n::guest_gs_access_rights::get(); }

void
vcpu::set_gs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_gs_access_rights::set(val); }

uint64_t
vcpu::tr_selector() const noexcept
{ return vmcs_n::guest_tr_selector::get(); }

void
vcpu::set_tr_selector(uint64_t val) noexcept
{ vmcs_n::guest_tr_selector::set(val); }

uint64_t
vcpu::tr_base() const noexcept
{ return vmcs_n::guest_tr_base::get(); }

void
vcpu::set_tr_base(uint64_t val) noexcept
{ vmcs_n::guest_tr_base::set(val); }

uint64_t
vcpu::tr_limit() const noexcept
{ return vmcs_n::guest_tr_limit::get(); }

void
vcpu::set_tr_limit(uint64_t val) noexcept
{ vmcs_n::guest_tr_limit::set(val); }

uint64_t
vcpu::tr_access_rights() const noexcept
{ return vmcs_n::guest_tr_access_rights::get(); }

void
vcpu::set_tr_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_tr_access_rights::set(val); }

uint64_t
vcpu::ldtr_selector() const noexcept
{ return vmcs_n::guest_ldtr_selector::get(); }

void
vcpu::set_ldtr_selector(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_selector::set(val); }

uint64_t
vcpu::ldtr_base() const noexcept
{ return vmcs_n::guest_ldtr_base::get(); }

void
vcpu::set_ldtr_base(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_base::set(val); }

uint64_t
vcpu::ldtr_limit() const noexcept
{ return vmcs_n::guest_ldtr_limit::get(); }

void
vcpu::set_ldtr_limit(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_limit::set(val); }

uint64_t
vcpu::ldtr_access_rights() const noexcept
{ return vmcs_n::guest_ldtr_access_rights::get(); }

void
vcpu::set_ldtr_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_access_rights::set(val); }

//==============================================================================
// General Registers
//==============================================================================

uint64_t
vcpu::gr1() const noexcept
{ return m_gr1; }

void
vcpu::set_gr1(uint64_t val) noexcept
{ m_gr1 = val; }

uint64_t
vcpu::gr2() const noexcept
{ return m_gr2; }

void
vcpu::set_gr2(uint64_t val) noexcept
{ m_gr2 = val; }

uint64_t
vcpu::gr3() const noexcept
{ return m_gr3; }

void
vcpu::set_gr3(uint64_t val) noexcept
{ m_gr3 = val; }

uint64_t
vcpu::gr4() const noexcept
{ return m_gr4; }

void
vcpu::set_gr4(uint64_t val) noexcept
{ m_gr4 = val; }

}
