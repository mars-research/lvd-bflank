#ifndef HASHTABLE_INTEL_X64_H
#define HASHTABLE_INTEL_X64_H

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

struct kv {
    uint32_t k;
    uint32_t v;

    void init() {
	k = v = 0;
    }
};

/// Hashtable provider
///
/// Provides hashtable (like) functionality
///
class EXPORT_HVE hashtable
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this rdmsr handler
    ///
    hashtable(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~hashtable() = default;

    bool insert(uint32_t key);
    int find(uint32_t key);
    uint32_t get_free_idx(void);
    void dump(void);

private:
    kv m_hashmap[512];
    bool m_isfull; 
    vcpu *m_vcpu;

public:
    hashtable(hashtable &&) = default;
    hashtable &operator=(hashtable &&) = default;

    hashtable(const hashtable &) = delete;
    hashtable &operator=(const hashtable &) = delete;

};

}

#endif
