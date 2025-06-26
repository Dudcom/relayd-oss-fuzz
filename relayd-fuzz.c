#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>

#include "relayd.h"

// External declarations for global variables (defined in main_for_fuzz.c)
extern struct list_head interfaces;
extern int debug;
extern uint8_t local_addr[4];
extern int local_route_table;

// Static variables from main.c - these need to be declared extern since they're static in main.c
// We'll initialize them in our init function
static int host_timeout;
static int host_ping_tries;
static int inet_sock;
static int forward_bcast;
static int forward_dhcp;
static int parse_dhcp;

// Initialize flag
static bool fuzz_initialized = false;

// Debug printing
#define FUZZ_DEBUG(fmt, ...) fprintf(stderr, "[FUZZ_DEBUG] " fmt "\n", ##__VA_ARGS__)

// Mock interface for fuzzing - mimic the original structure exactly
static struct relayd_interface mock_rif = {
    .ifname = "eth0",
    .sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = 0, // Will be set during init
        .sll_ifindex = 1,
        .sll_hatype = ARPHRD_ETHER,
        .sll_pkttype = PACKET_BROADCAST,
        .sll_halen = ETH_ALEN,
        .sll_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    },
    .src_ip = {192, 168, 1, 100},
    .managed = false,
    .rt_table = 100,
};

// Initialize the fuzzing environment to match main() as closely as possible
static void init_fuzzing_environment(void) {
    if (fuzz_initialized) {
        return;
    }
    
    FUZZ_DEBUG("Starting fuzzing environment initialization");
    
    // Initialize global variables exactly like main()
    debug = 1; // Enable debug for better visibility
    
    // Create inet socket like main() does
    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (inet_sock < 0) {
        FUZZ_DEBUG("Warning: Could not create inet_sock, setting to -1");
        inet_sock = -1; // Set to invalid but safe value
    } else {
        FUZZ_DEBUG("Created inet_sock: %d", inet_sock);
    }
    
    // Set timeouts and flags like main()
    host_timeout = 30;
    host_ping_tries = 5;
    forward_bcast = 1;   // Enable for testing
    forward_dhcp = 1;    // Enable for testing
    parse_dhcp = 1;      // Enable for testing
    local_route_table = 0;
    
    // Set up local address
    local_addr[0] = 192;
    local_addr[1] = 168;
    local_addr[2] = 1;
    local_addr[3] = 1;
    
    FUZZ_DEBUG("Set host_timeout=%d, host_ping_tries=%d", host_timeout, host_ping_tries);
    FUZZ_DEBUG("Set forward_bcast=%d, forward_dhcp=%d, parse_dhcp=%d", 
               forward_bcast, forward_dhcp, parse_dhcp);
    
    // Initialize the mock interface lists
    INIT_LIST_HEAD(&mock_rif.list);
    INIT_LIST_HEAD(&mock_rif.hosts);
    
    FUZZ_DEBUG("Initialized mock interface lists");
    
    fuzz_initialized = true;
    FUZZ_DEBUG("Fuzzing environment initialization complete");
}

// Test DHCP packet parsing - the main target
static void fuzz_dhcp_packet(const uint8_t *data, size_t size) {
    FUZZ_DEBUG("Testing DHCP packet parsing with %zu bytes", size);
    
    if (size < 20) { // Need minimum for meaningful DHCP test
        FUZZ_DEBUG("Skipping DHCP test - too small (%zu bytes)", size);
        return;
    }
    
    bool result;
    
    FUZZ_DEBUG("Calling relayd_handle_dhcp_packet with forward=true, parse=true");
    result = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, true);
    FUZZ_DEBUG("relayd_handle_dhcp_packet result: %d", result);
    
    FUZZ_DEBUG("Calling relayd_handle_dhcp_packet with forward=false, parse=true");
    result = relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, true);
    FUZZ_DEBUG("relayd_handle_dhcp_packet result: %d", result);
    
    FUZZ_DEBUG("DHCP packet testing complete");
}

// Test broadcast packet forwarding
static void fuzz_broadcast_packet(const uint8_t *data, size_t size) {
    FUZZ_DEBUG("Testing broadcast packet forwarding with %zu bytes", size);
    
    if (size < 14) { // Minimum ethernet header
        FUZZ_DEBUG("Skipping broadcast test - too small (%zu bytes)", size);
        return;
    }
    
    FUZZ_DEBUG("Calling relayd_forward_bcast_packet");
    relayd_forward_bcast_packet(&mock_rif, (void *)data, size);
    FUZZ_DEBUG("Broadcast packet forwarding complete");
}

// Test host refresh functionality
static void fuzz_host_refresh(const uint8_t *data, size_t size) {
    FUZZ_DEBUG("Testing host refresh with %zu bytes", size);
    
    if (size < 10) { // Need 6 bytes MAC + 4 bytes IP
        FUZZ_DEBUG("Skipping host refresh test - too small (%zu bytes)", size);
        return;
    }
    
    const uint8_t *mac_addr = data;
    const uint8_t *ip_addr = data + 6;
    
    FUZZ_DEBUG("Testing with MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
               mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    FUZZ_DEBUG("Testing with IP: %d.%d.%d.%d", 
               ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    
    FUZZ_DEBUG("Calling relayd_refresh_host");
    struct relayd_host *host = relayd_refresh_host(&mock_rif, mac_addr, ip_addr);
    FUZZ_DEBUG("relayd_refresh_host returned: %p", (void*)host);
    
    if (host && size >= 15) {
        const uint8_t *dest_addr = data + 10;
        uint8_t mask = data[14];
        
        FUZZ_DEBUG("Testing route addition to %d.%d.%d.%d/%d", 
                   dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], mask);
        
        FUZZ_DEBUG("Calling relayd_add_host_route");
        relayd_add_host_route(host, dest_addr, mask);
        FUZZ_DEBUG("Host route addition complete");
    }
    
    FUZZ_DEBUG("Host refresh testing complete");
}

// Test pending route functionality
static void fuzz_pending_route(const uint8_t *data, size_t size) {
    FUZZ_DEBUG("Testing pending route with %zu bytes", size);
    
    if (size < 9) { // Need gateway(4) + dest(4) + mask(1)
        FUZZ_DEBUG("Skipping pending route test - too small (%zu bytes)", size);
        return;
    }
    
    const uint8_t *gateway = data;
    const uint8_t *dest = data + 4;
    uint8_t mask = data[8];
    int timeout = (size > 9) ? ((data[9] % 10) * 1000) : 5000; // Shorter timeout for fuzzing
    
    FUZZ_DEBUG("Testing route via gateway %d.%d.%d.%d to %d.%d.%d.%d/%d timeout=%d",
               gateway[0], gateway[1], gateway[2], gateway[3],
               dest[0], dest[1], dest[2], dest[3], mask, timeout);
    
    FUZZ_DEBUG("Calling relayd_add_pending_route");
    relayd_add_pending_route(gateway, dest, mask, timeout);
    FUZZ_DEBUG("Pending route addition complete");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FUZZ_DEBUG("=== LLVMFuzzerTestOneInput called with %zu bytes ===", size);
    
    if (size < 1) {
        FUZZ_DEBUG("Input too small, returning");
        return 0;
    }
    
    // Initialize environment
    FUZZ_DEBUG("Initializing fuzzing environment");
    init_fuzzing_environment();
    
    // Initialize interfaces list if empty
    if (list_empty(&interfaces)) {
        FUZZ_DEBUG("Interfaces list empty, adding mock interface");
        list_add(&mock_rif.list, &interfaces);
        FUZZ_DEBUG("Mock interface added to global interfaces list");
    }
    
    // Use first byte to determine fuzzing target
    uint8_t fuzz_type = data[0] % 4;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    FUZZ_DEBUG("Selected fuzz type: %d with %zu bytes of data", fuzz_type, fuzz_size);
    
    switch (fuzz_type) {
        case 0:
            FUZZ_DEBUG("=== Starting DHCP packet fuzzing ===");
            fuzz_dhcp_packet(fuzz_data, fuzz_size);
            break;
            
        case 1:
            FUZZ_DEBUG("=== Starting broadcast packet fuzzing ===");
            fuzz_broadcast_packet(fuzz_data, fuzz_size);
            break;
            
        case 2:
            FUZZ_DEBUG("=== Starting host refresh fuzzing ===");
            fuzz_host_refresh(fuzz_data, fuzz_size);
            break;
            
        case 3:
            FUZZ_DEBUG("=== Starting pending route fuzzing ===");
            fuzz_pending_route(fuzz_data, fuzz_size);
            break;
    }
    
    FUZZ_DEBUG("=== LLVMFuzzerTestOneInput complete ===");
    return 0;
}

