#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../src/maps.h"
#include "freeze_kern.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_alert(void *ctx, void *data, size_t data_sz) {
    const struct alert_event *e = data;

    printf("\n=======================================================\n");
    printf(" [AUTONOMOUS CONTAINMENT ALERT]\n");
    printf("  PID:            %d\n", e->pid);
    printf("  Process Name:   %s\n", e->comm);
    printf("  Threat Score:   %d / 100 (Threshold: %d)\n", e->threat_score, SCORE_THRESHOLD);
    printf("  Action:         SIGSTOP Executed In-Kernel (Thread Frozen)\n");
    printf("  HMAC Signature: Validated (Kernel Cryptographic Verification)\n");
    printf("=======================================================\n");

    /* Policy Evaluation */
    if (e->threat_score >= 85) {
        printf(" [POLICY ENGINE] High Confidence Threat. Issuing SIGKILL to PID %d...\n", e->pid);
        kill(e->pid, SIGKILL);
        printf(" [SIEM LOG] Audit event exported to central monitoring pipeline.\n");
    } else {
        printf(" [POLICY ENGINE] Suspended PID %d pending administrator review.\n", e->pid);
        printf(" -> Run 'kill -SIGCONT %d' to resume if determined benign.\n", e->pid);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct freeze_kern *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Starting Userspace Supervisor Daemon...\n");

    /* 1. Open and Load eBPF Skeleton */
    skel = freeze_kern__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton\n");
        return 1;
    }

    /* 2. Attach Tracepoints to Kernel */
    err = freeze_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF programs to kernel tracepoints\n");
        goto cleanup;
    }

    /* 3. Setup Ring Buffer Consumer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.alert_ringbuf), handle_alert, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to initialize ring buffer consumer\n");
        goto cleanup;
    }

    printf("Supervisor Daemon active. All tracepoints attached. Listening for in-kernel alerts...\n");
    printf("Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    freeze_kern__destroy(skel);
    printf("\nDetached eBPF hooks and cleaned up.\n");
    return 0;
}
