#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "relayd.h"

// Global variables needed by the functions
LIST_HEAD(interfaces);
int debug = 0;
int route_table = 16800;
uint8_t local_addr[4] = {192, 168, 1, 1};
int local_route_table = 1;

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

// Simulate DHCP packet structures for fuzzing
static void fuzz_dhcp_packet(const uint8_t *data, size_t size) {
    // Test DHCP packet parsing with different forward/parse configurations
    // This is the main public API function that processes network data
    bool results[4];
    
    // Test all combinations of forward and parse flags
    results[0] = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, true);
    results[1] = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, true);
    results[2] = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, false);
    results[3] = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, false);
    
    // Suppress unused variable warning
    (void)results;
}

// Test broadcast packet forwarding
static void fuzz_broadcast_packet(const uint8_t *data, size_t size) {
    if (size < 14) { // Minimum ethernet header size
        return;
    }
    
    // Test broadcast packet forwarding
    relayd_forward_bcast_packet(&mock_rif, (void *)data, size);
}

// Test host refresh functionality with crafted MAC/IP combinations
static void fuzz_host_refresh(const uint8_t *data, size_t size) {
    if (size < 10) { // Need at least 6 bytes MAC + 4 bytes IP
        return;
    }
    
    const uint8_t *mac_addr = data;
    const uint8_t *ip_addr = data + 6;
    
    // Test host refresh with fuzzer-provided MAC and IP addresses
    relayd_refresh_host(&mock_rif, mac_addr, ip_addr);
}

// Test route addition functionality
static void fuzz_host_route(const uint8_t *data, size_t size) {
    if (size < 11) { // Need MAC(6) + IP(4) + mask(1)
        return;
    }
    
    // First create a host
    const uint8_t *mac_addr = data;
    const uint8_t *ip_addr = data + 6;
    const uint8_t *dest_addr = data + 10;
    uint8_t mask = (size > 14) ? data[14] : 24;
    
    struct relayd_host *host = relayd_refresh_host(&mock_rif, mac_addr, ip_addr);
    if (host && size >= 14) {
        // Test route addition with fuzzer data
        relayd_add_host_route(host, dest_addr, mask);
    }
}

// Test pending route functionality
static void fuzz_pending_route(const uint8_t *data, size_t size) {
    if (size < 9) { // Need gateway(4) + dest(4) + mask(1)
        return;
    }
    
    const uint8_t *gateway = data;
    const uint8_t *dest = data + 4;
    uint8_t mask = data[8];
    int timeout = (size > 9) ? ((data[9] % 100) * 1000) : 10000; // Limit timeout
    
    relayd_add_pending_route(gateway, dest, mask, timeout);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }
    
    // Initialize the interfaces list if empty
    if (list_empty(&interfaces)) {
        INIT_LIST_HEAD(&mock_rif.list);
        INIT_LIST_HEAD(&mock_rif.hosts);
        list_add(&mock_rif.list, &interfaces);
    }
    
    // Use first byte to determine which fuzzing target to use
    uint8_t fuzz_type = data[0] % 5;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (fuzz_type) {
        case 0:
            // Fuzz DHCP packet parsing - most complex parsing logic
            fuzz_dhcp_packet(fuzz_data, fuzz_size);
            break;
            
        case 1:
            // Fuzz broadcast packet forwarding
            fuzz_broadcast_packet(fuzz_data, fuzz_size);
            break;
            
        case 2:
            // Fuzz host refresh functionality
            fuzz_host_refresh(fuzz_data, fuzz_size);
            break;
            
        case 3:
            // Fuzz host route addition
            fuzz_host_route(fuzz_data, fuzz_size);
            break;
            
        case 4:
            // Fuzz pending route addition
            fuzz_pending_route(fuzz_data, fuzz_size);
            break;
    }
    
    return 0;
}

