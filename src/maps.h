#ifndef __MAPS_H
#define __MAPS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MAX_FILENAME_LEN 256
#define HMAC_LEN 32
#define SCORE_THRESHOLD 75 // T >= 0.75
#define MIN_FILES_FLOOR 15

/* Operational counters per active PID */
struct proc_state {
    __u64 first_event_ns;      // Start timestamp of active window
    __u32 files_touched;       // Count of distinct inodes modified
    __u32 high_entropy_writes; // Count of writes flagged high-entropy
    __u32 renames_after_write; // Renames following high-entropy write
    __u32 deletes_after_write; // Unlinks following high-entropy write
    __u64 bytes_written;       // Total bytes modified in window
    __u8  flagged;             // Boolean flag for triggered response
};

/* Payload passed through BPF_MAP_TYPE_RINGBUF */
struct alert_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 threat_score;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
    __u64 timestamp;
    __u8 hmac_signature[HMAC_LEN]; /* Signed Payload via Kernel Crypto API */
};

#endif /* __MAPS_H */
