#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "GPL";



struct exec_path {
__u32 tgid;
char pathname[256];
};


struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 10240);
__type(key, __u32);
__type(value, struct exec_path);

}exec_paths SEC(".maps");

//execve entry tracer

SEC("tracepoint/syscalls/sys_enter_execve")

int event_handle (struct trace_event_raw_sys_enter *ctx){

__u64 id = bpf_get_current_pid_tgid();
__u32 tgid = id >> 32;
__u32 tid = (__u32)id;

struct exec_path entry = {0};

long ret = bpf_probe_read_user_str(entry.pathname, sizeof(entry.pathname), (const char *)ctx->args[0]);

if (ret < 0){
bpf_printk("Pathname read failed");
return 0;
}

entry.tgid = tgid;

long map_ret = bpf_map_update_elem(&exec_paths, &tid, &entry, BPF_ANY);
if (map_ret < 0){
bpf_printk("map update failed");
}

char comm[16];
long comm_ret = bpf_get_current_comm(comm, sizeof(comm));
if(comm_ret < 0){
bpf_printk("comm read failed");
}

struct task_struct *c_task = bpf_get_current_task_btf();
struct task_struct *parent = BPF_CORE_READ(c_task, real_parent);

pid_t parent_pid = BPF_CORE_READ(parent, pid);
pid_t parent_tgid = BPF_CORE_READ(parent, tgid);

char p_name[16];
BPF_CORE_READ_INTO(&p_name, parent, comm);

bpf_printk("path = %s, tid = %u, tgid = %u, comm = %s, parent_name = %s, PPid=%u, Ptgid = %u Pcomm = %s", entry.pathname, tid, tgid, comm, p_name, parent_pid, parent_tgid, p_name);


return 0;
}


//success tracepoint *need to revisit*

SEC("tracepoint/sched/sched_process_exec")

int exec_success (struct trace_event_raw_sched_process_exec *ctx){

__u32 descriptor = ctx->__data_loc_filename;
__u32 offset = descriptor & 0xFFFF;
__u32 length = descriptor >> 16;

if (offset > 1024){
return 0;
}

char *base = (char *)ctx;
char *filename = base + offset;

char data_name[128];
bpf_probe_read_kernel_str(data_name, sizeof(data_name), filename);

pid_t pid = ctx->pid;
pid_t old_pid = ctx->old_pid;

bpf_printk ("EXECVE_SUCCESS: Pname = %s, pid = %d, old_pid = %d", data_name, pid, old_pid);

return 0;
}


//failure tracepoint *might nead some correction*

SEC("tracepoint/syscalls/sys_exit_execve")

int exec_failure (struct trace_event_raw_sys_exit *ctx){

long ret = ctx->ret;

if (ret >= 0){
return 0;
}

__u64 id = bpf_get_current_pid_tgid();
__u32 tgid = id >> 32;
__u32 tid = (__u32)id;

struct exec_path *mp  = bpf_map_lookup_elem(&exec_paths, &tid);

if (!mp){
bpf_printk("map read failed");
return 0;
}

bpf_printk("execve failed: path = %s tid = %u, tgid = %u ", mp->pathname, tid, tgid);

if (ret == -2){
bpf_printk("EONENT FAILURE");
}else if (ret == -8){
bpf_printk("ENOEXEC FAILURE");
}else if (ret == -12){
bpf_printk("ENOMEM FAILURE");
}else if(ret == -13){
bpf_printk("EACCESS FAILURE");
}

bpf_map_delete_elem(&exec_paths, &tid);

return 0;
}



// EXECVAT

SEC("tracepoint/syscalls/sys_enter_execveat")

int execveat_entry(struct trace_event_raw_sys_enter *ctx){

__u64 id = bpf_get_current_pid_tgid();
__u32 tid = (__u32)id;
__u32 tgid = id >> 32;

struct exec_path entry = {0};

entry.tgid = tgid;

long ret = bpf_probe_read_user_str(entry.pathname, sizeof(entry.pathname), (const char *)ctx->args[1]);

if (ret < 0){
bpf_printk("pathname read failed");
return 0;
}

long mp_ret = bpf_map_update_elem(&exec_paths, &tid, &entry, BPF_ANY);
if (mp_ret < 0){
bpf_printk("map update failed");
}


char comm[16];
long rt = bpf_get_current_comm(comm, sizeof(comm));

if (rt < 0){
bpf_printk("comm read failed");
}

struct task_struct *c_task = bpf_get_current_task_btf();
struct task_struct *parent = BPF_CORE_READ(c_task, real_parent);

char p_name[16];
BPF_CORE_READ_INTO(&p_name, parent, comm);

pid_t p_tid = BPF_CORE_READ(parent, pid);
pid_t p_tgid =BPF_CORE_READ(parent, tgid);

bpf_printk("execveat entry: path = %s, tid = %u, tgid = %u, comm = %s, parent_name = %s, PPid=%u, Ptgid = %u Pcomm = %s", entry.pathname, tid, tgid, comm, p_name, p_tid, p_tgid, p_name);

return 0;
}


// EXECVAT exit handler

SEC("tracepoint/syscalls/sys_exit_execveat")

int execveat_exit(struct trace_event_raw_sys_exit *ctx){

long ret = ctx->ret;

if (ret >= 0){
return 0;
}

__u64 id = bpf_get_current_pid_tgid();
__u32 tid = (__u32)id;
__u32 tgid = id >> 32;

struct exec_path *mp = bpf_map_lookup_elem(&exec_paths, &tid);

if (!mp){
bpf_printk("map read failed");
return 0;
}

bpf_printk("execveat failed: path = %s, tid = %u, tgid = %u", mp->pathname, tid, mp->tgid);

if (ret == -2){
bpf_printk("EONENT FAILURE");
}else if (ret == -8){
bpf_printk("ENOEXEC FAILURE");
}else if (ret == -12){
bpf_printk("ENOMEM FAILURE");
}else if(ret == -13){
bpf_printk("EACCESS FAILURE");
}


bpf_map_delete_elem(&exec_paths, &tid);


return 0;
}


// sys enter FORK

SEC("tracepoint/syscalls/sys_enter_fork")

int fork_entry(struct trace_event_raw_sys_enter *ctx){


return 0;
}



// successful FORk


SEC("tracepoint/sched/sched_process_fork")


int fork_ok(struct trace_event_sched_process_fork *ctx){

__u32 p_comm = ctx->__data_loc_parent_comm;
__u32 offset = p_comm & 0xFFFF;
__u32 length = p_comm >> 16;

if (offset > 1024){
return 0;
}

char *base = (char *)ctx;
char *filename = base + offset;

char data_name[16];
bpf_probe_read_kernel_str(data_name, sizeof(data_name), filename);



pid_t child_pid = ctx->child_pid;
pid_t parent_pid = ctx->parent_pid;

__u32 c_comm = ctx->__data_loc_child_comm;
__u32 c_offset = c_comm & 0xFFFF;
__u32 c_length = c_comm >> 16;

if (c_offset >1024){
return 0;
}

char *c_base = (char *)ctx;
char *c_filename = c_base + c_offset;

char c_data_name[16];
bpf_probe_read_kernel_str(c_data_name, sizeof(c_data_name), c_filename);



return 0;
}
