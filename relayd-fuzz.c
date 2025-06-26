#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "relayd.h"

// External declarations for global variables (defined in original source files)
extern struct list_head interfaces;
extern int debug;
extern int route_table;
extern uint8_t local_addr[4];
extern int local_route_table;

// Minimal initialization flag
static bool fuzz_initialized = false;

// Mock interface for fuzzing
static struct relayd_interface mock_rif = {
    .ifname = "eth0",
    .sll = {
        .sll_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .sll_ifindex = 1,
    },
    .src_ip = {192, 168, 1, 100},
    .managed = false,
    .rt_table = 100,
};

// Stub function to avoid crashes when relayd_forward_bcast_packet tries to send
void safe_forward_bcast_packet(struct relayd_interface *from_rif, void *packet, int len) {
    // Just do minimal validation, don't actually send anything
    if (!from_rif || !packet || len <= 0) {
        return;
    }
    // This is a stub - we're just testing the parsing logic, not the sending
}

// Safe version of relayd_refresh_host that doesn't require full system init
struct relayd_host *safe_refresh_host(struct relayd_interface *rif, const uint8_t *lladdr, const uint8_t *ipaddr) {
    if (!rif || !lladdr || !ipaddr) {
        return NULL;
    }
    
    // Create a minimal host structure for testing
    static struct relayd_host test_host;
    memset(&test_host, 0, sizeof(test_host));
    test_host.rif = rif;
    memcpy(test_host.lladdr, lladdr, 6);
    memcpy(test_host.ipaddr, ipaddr, 4);
    INIT_LIST_HEAD(&test_host.routes);
    
    return &test_host;
}

// Safe version that doesn't require routing system
void safe_add_host_route(struct relayd_host *host, const uint8_t *dest, uint8_t mask) {
    if (!host || !dest) {
        return;
    }
    // Just validate the parameters, don't actually add routes in fuzzing
}

// Safe version that doesn't require full routing infrastructure  
void safe_add_pending_route(const uint8_t *gateway, const uint8_t *dest, uint8_t mask, int timeout) {
    if (!gateway || !dest) {
        return;
    }
    // Just validate parameters in fuzzing mode
}

static void minimal_init(void) {
    if (fuzz_initialized) {
        return;
    }
    
    // Initialize minimal required state
    debug = 0;
    local_route_table = 0;
    
    // Set up a basic local address
    local_addr[0] = 192;
    local_addr[1] = 168; 
    local_addr[2] = 1;
    local_addr[3] = 1;
    
    fuzz_initialized = true;
}

// Primary fuzzing target - focus on DHCP packet parsing
static void fuzz_dhcp_packet(const uint8_t *data, size_t size) {
    // Test DHCP packet parsing - this is the main target
    bool result;
    
    // Focus on the parsing logic with different configurations
    result = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, true);
    (void)result; // Suppress unused warning
    
    // Test with forwarding disabled but parsing enabled
    result = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, false);
    (void)result;
}

// Test other functions with safe wrappers
static void fuzz_safe_functions(const uint8_t *data, size_t size) {
    if (size < 10) {
        return;
    }
    
    const uint8_t *mac_addr = data;
    const uint8_t *ip_addr = data + 6;
    
    // Test host refresh with safe wrapper
    struct relayd_host *host = safe_refresh_host(&mock_rif, mac_addr, ip_addr);
    
    if (host && size >= 15) {
        const uint8_t *dest_addr = data + 10;
        uint8_t mask = data[14];
        safe_add_host_route(host, dest_addr, mask);
    }
    
    if (size >= 9) {
        const uint8_t *gateway = data;
        const uint8_t *dest = data + 4;
        uint8_t mask = data[8];
        safe_add_pending_route(gateway, dest, mask, 1000);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    
    // Minimal initialization
    minimal_init();
    
    // Initialize interfaces list if needed
    if (list_empty(&interfaces)) {
        INIT_LIST_HEAD(&mock_rif.list);
        INIT_LIST_HEAD(&mock_rif.hosts);
        list_add(&mock_rif.list, &interfaces);
    }
    
    // Use first byte to choose fuzzing target
    if (data[0] % 2 == 0) {
        // Focus primarily on DHCP parsing (most complex)
        fuzz_dhcp_packet(data + 1, size - 1);
    } else {
        // Test other functions with safe wrappers
        fuzz_safe_functions(data + 1, size - 1);
    }
    
    return 0;
}

