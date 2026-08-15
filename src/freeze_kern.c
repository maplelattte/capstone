#include  <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

// BPF map - primary state map keyed by PID

struct{
    __uint(type,BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries,10240);
    __type(key, u32);
    __type(value, struct proc_state);
} proc_state_map SEC(".maps");

// BPF map - secondary map keyed by pid,inode typle for 0-1 checks

struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,20480);
    __type(key,u64);
    __type(value,u8);
} tuple_map SEC(".maps");

// BPF map - ring buffer for tamper resistant alerts

struct{
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256 * 1024);
} alert_ringbuf SEC(".maps");

// Distinct ratio proxy 
static __always_inline u32 compute_distinct_proxy(const char *buf,u32 len){
    if(len == 0) return 0;
    u32 unique_count = 0;
    u8 seen[256] = {0};

    #pragma unroll
    for(int i=0;i<64;i++){
      if(i<len){
        u8 val = (u8)buf[i];
        if(!seen[val]){
          seen[val]=1;
          unique_count++;
      }
    }
  }
  //scaling to 0-100 range
  return(unique_count*100)/64;
}

// hook point (vfs_write)
SEC("tracepoint/syscalls/sys_enter_write")
int trace_vfs_write(struct trace_event_raw_sys_enter *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 now = bpf_ktime_get_ns();
    
    struct proc_state *state = bpf_map_lookup_elem(&proc_state_map, &pid);
    if(!state){
      struct proc_state init_state = {
        .first_event_ns=now,
        .files_touched = 1,
        .high_entropy_writes=0,
        .renames_after_write=0,
        .deletes_after_write=0,
        .bytes_written=0,
        .flagged=0
    };
    bpf_map_update_elem(&proc_state_map,&pid,&init_state, BPF_ANY);
    return 0;
  }
  if(state->flagged) return 0; // Already frozen
  state->files_touched++;

  char buffer_sample[64]={0};
  bpf_probe_read_user(buffer_sample, sizeof(buffer_sample),(void *)ctx->args[1]);

  u32 entropy_score = compute_distinct_proxy(buffer_sample, 64);
  if (entropy_score>=80){
      state->high_entropy_writes++;
  }
  // multi signal fusion scoring formula
  u32 S1 = state->files_touched;
  u32 S2 = (state->high_entropy_writes * 100)/ (state->files_touched ? state->files_touched : 1);
  u32 S3 = (state->renames_after_write * 100) / (state->files_touched ? state->files_touched : 1);
  u32 S4 = (state->deletes_after_write * 100)/(state->files_touched ? state->files_touched : 1);

  // weighted combination T 
  u32 T = (25 * S1 + 30 * S2 + 20 * S3 + 10 * S4)/100;

  if(T>=SCORE_THRESHOLD && state->files_touched >= MIN_FILES_FLOOR){
      state->flagged=1;
      // Executing autonomous process freeze using SIGSTOP (19)
      bpf_send_signal(19);

      //dispatching alert payload to ring buffer
      struct alert_event *event = bpf_ringbuf_reserve(&alert_ringbuf, sizeof(*event),0);
      if(event){
          event->pid = pid;
          event->threat_score = T;
          event->timestamp = now;
          bpf_get_current_comm(&event->comm,sizeof(event->comm));

          //populate dummy hmac signature 
          for(int i=0;i<HMAC_LEN;i++) event->hmac_signature[i]=0xAA;

          bpf_ringbuf_submit(event,0);
    }
  }
  bpf_map_update_elem(&proc_state_map, &pid, state, BPF_EXIST);
  return 0;
}

// Rename hook stuff 
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trave_vfs_rename(struct trace_event_raw_sys_enter *ctx){
      u64 pid_tgid=bpf_get_current_pid_tgid();
      u32 pid = pid_tgid >> 32;

      struct proc_state *state = bpf_map_lookup_elem(&proc_state_map, &pid);
      if(state && !state->flagged){
        state->renames_after_write++;
        bpf_map_update_elem(&proc_state_map, &pid, state, BPF_EXIST);
  }
  return 0;
}

// Delete hook stuff
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trave_vfs_unlink(struct trace_event_raw_sys_enter *ctx){
      u64 pid_tgid = bpf_get_current_pid_tgid();
      u32 pid = pid_tgid >> 32;

      struct proc_state *state = bpf_map_lookup_elem(&proc_state_map, &pid);
      if(state && !state->flagged){
        state->deletes_after_write++;
        bpf_map_update_elem(&proc_state_map, &pid, state, BPF_EXIST);
  }
  return 0;
}

