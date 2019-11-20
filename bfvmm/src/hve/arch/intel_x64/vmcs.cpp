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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/vmcs.h>
#include <hve/arch/intel_x64/check.h>
#include <hve/arch/intel_x64/vcpu.h>

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void vmcs_launch(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

extern "C" void vmcs_promote(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

extern "C" void vmcs_resume(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

vmcs::vmcs(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_vmcs_region{make_page<uint32_t>()},
    m_vmcs_region_phys{g_mm->virtptr_to_physint(m_vmcs_region.get())}
{
    this->clear();

    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(::intel_x64::msrs::ia32_vmx_basic::revision_id::get());

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "vmcs region", msg);
        bfdebug_subnhex(1, "virt address", m_vmcs_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmcs_region_phys, msg);
    });
}

void
vmcs::launch()
{
    try {
        if (m_vcpu->is_host_vm_vcpu()) {
            ::intel_x64::vm::launch_demote();
        }
        else {
            vmcs_launch(m_vcpu->state().get());
            throw std::runtime_error("vmcs launch failed");
        }
    }
    catch (...) {
        auto e = std::current_exception();

        this->check();
        std::rethrow_exception(e);
    }
}

void
vmcs::promote()
{
    vmcs_promote(m_vcpu->state());
    throw std::runtime_error("vmcs promote failed");
}

void
vmcs::resume()
{
    vmcs_resume(m_vcpu->state());

    this->check();
    throw std::runtime_error("vmcs resume failed");
}

void
vmcs::load()
{ ::intel_x64::vm::load(&m_vmcs_region_phys); }

void
vmcs::clear()
{ ::intel_x64::vm::clear(&m_vmcs_region_phys); }

bool
vmcs::check() const noexcept
{
    try {
        check::all();
    }
    catch (std::exception &e) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, typeid(e).name(), msg);
            bferror_brk1(0, msg);
            bferror_info(0, e.what(), msg);
        });

        return false;
    }

    return true;
}

// Table C-1. Basic Exit Reasons
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
        case 65: return "65";
        case 66: return "66";
        case 67: return "67";
        case 68: return "68";
        case 69: return "69";
	case 70: return "70";
        case 71: return "71";
        case 72: return "72";
        case 73: return "73";
        case 74: return "74";
        case 75: return "75";
        case 76: return "76";
        case 77: return "77";
        case 78: return "78";
        case 79: return "79";
	case 80: return "80";
        case 81: return "81";
        case 82: return "82";
        case 83: return "83";
        case 84: return "84";
        case 85: return "85";
        case 86: return "86";
        case 87: return "87";
        case 88: return "88";
        case 89: return "89";
	case 90: return "90";
        case 91: return "91";
        case 92: return "92";
        case 93: return "93";
        case 94: return "94";
        case 95: return "95";
        case 96: return "96";
        case 97: return "97";
        case 98: return "98";
        case 99: return "99";
	case 100: return "100";
        case 101: return "101";
        case 102: return "102";
        case 103: return "103";
        case 104: return "104";
        case 105: return "105";
        case 106: return "106";
        case 107: return "107";
        case 108: return "108";
        case 109: return "109";
	case 110: return "110";
        case 111: return "111";
        case 112: return "112";
        case 113: return "113";
        case 114: return "114";
        case 115: return "115";
        case 116: return "116";
        case 117: return "117";
        case 118: return "118";
        case 119: return "119";
	case 120: return "120";
        case 121: return "121";
        case 122: return "122";
        case 123: return "123";
        case 124: return "124";
        case 125: return "125";
        case 126: return "126";
        case 127: return "127";

        default: return "unknown";
    };
};


void
vcpu::dump_perf_counters(void)
{

#ifdef BF_COUNT_EXTIS
    //vcpu->dump_instruction(); 
    //vcpu->dump_perf_counters();
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_info(0, "Dumping VM exits", msg);
        bfdebug_subndec(0, "total_exits", this->m_exits_total, msg);
        	
        for (int i = 0; i < MAX_EXIT_REASONS; i++) {
            if(this->m_exits[i]) {
                bfdebug_subndec(0, bfdebug_exit_to_str(i), this->m_exits[i], msg);
                this->m_exits[i] = 0; 
            }
        }
    });
    this->m_exits_total = 0;
    vmcs_n::cr0_guest_host_mask::dump(0); 
    vmcs_n::cr0_read_shadow::dump(0); 
    vmcs_n::cr4_guest_host_mask::dump(0);
    vmcs_n::cr4_read_shadow::dump(0); 
#else
   bfdebug_info(0, "VM exit counting is not supported (recompile with BF_COUNT_EXTIS)"); 
#endif


}

}
