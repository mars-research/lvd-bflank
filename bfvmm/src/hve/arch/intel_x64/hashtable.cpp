
#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{


hashtable::hashtable(
    gsl::not_null<vcpu *> vcpu
)
    //m_vcpu{vcpu},
    //m_hashmap{0},
{
	m_isfull = false;
	m_vcpu = vcpu;
	for (auto i = 0; i < 512; i++) {
		m_hashmap[i].k = m_hashmap[i].v = 0;
	}
}

// returns the index at which the key is found
int hashtable::find(
    uint32_t key)
{
    for (auto i = 0; i < 512; i++) {
        if (m_hashmap[i].k == key)
            return i;
    }
    return -1;
}

uint32_t hashtable::get_free_idx(void)
{
    for (auto i = 0; i < 512; i++) {
        if (m_hashmap[i].k == 0)
            return i;
    }
    return -1;
}

void hashtable::dump(void) {
    bfdebug_transaction(0, [&](std::string * msg) {
    	for (auto i = 0; i < 512; i++) {
            if (m_hashmap[i].k != 0) {
                bfdebug_subnhex(0, "msr:", m_hashmap[i].k, msg);
                bfdebug_subndec(0, "count:", m_hashmap[i].v, msg);
		m_hashmap[i].init();
            }
	}
    });
}

bool hashtable::insert(
    uint32_t key)
{
    auto idx = find(key);

    // not found
    if (idx == -1) {
        idx = get_free_idx();

        if (idx == -1) {
            return false;
        } else {
            // got a free spot! insert
            m_hashmap[idx].k = key;
            m_hashmap[idx].v = 1;
        }
    } else {
        //found key, increment counter
        m_hashmap[idx].v++;
    }
    return true;
}


}
