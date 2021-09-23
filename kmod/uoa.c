


#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#include <linux/vmalloc.h>
#include <asm/pgtable_types.h>

#include <linux/err.h>
#include <linux/time.h>
#include <linux/timer.h>

#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inet.h>

#include <net/protocol.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include "uoa.h"
#include "uoa_opp.h"


// static int uoa_debug = 0;
// module_param_named(uoa_debug, uoa_debug, int, 0444);
// MODULE_PARM_DESC(uoa_debug, "enable UOA debug by setting it to 1");


//  uoa stats ------------------------------------

// const char uoa_version[] = "2.2.1";
#define UOA_VERSION "2.2.1"

enum
{
    STATS_IPV4_RCV = 0,
    STATS_IPV4_IP_OPTION,
    STATS_IPV4_IP_OPTION_V2,
    STATS_IPV4_OPTION_PROTOCOL,
    STATS_IPV4_SAVED,
    STATS_IPV6_RCV,
    STATS_IPV6_IP_OPTION,
    STATS_IPV6_IP_OPTION_V2,
    STATS_IPV6_OPTION_PROTOCOL,
    STATS_IPV6_SAVED,

    STATS_GET_V0,
    STATS_GET_V0_SUCC,
    STATS_GET_V1,
    STATS_GET_V1_SUCC,
    STATS_GET_V2,
    STATS_GET_V2_SUCC,

    STATS_MAX,
};

struct uoa_stats
{
    __u64 stats[STATS_MAX];
};

struct uoa_stats __percpu * uoa_stats_cpu;


// the uoa_cpu_stats only be added in the local cpu and can be read from other cpu
static inline void uoa_stats_inc(int index)
{
    struct uoa_stats* s = this_cpu_ptr(uoa_stats_cpu);
    s->stats[index]++;
}

static int uoa_stats_show(struct seq_file *seq, void *arg)
{
    struct uoa_stats global_stats;
    int i, j;

    seq_printf(seq, "uoa version: %s\n", UOA_VERSION);
    seq_puts(seq, "CPU     V4_RCV   V4_OPT  V4_OPT2 V4_OPT_PROTO V4_SAVED "
            "V6_RCV V6_OPT  V6_OPT2 V6_OPT_PROTO V6_SAVED "
            "GET_V0 GET_V0_OK GET_V1 GET_V1_OK GET_V2 GET_V2_OK\n");
    
    memset(&global_stats, 0, sizeof(global_stats));
    for_each_possible_cpu(i) 
    {
        struct uoa_stats *s = per_cpu_ptr(uoa_stats_cpu, i);
        __u64 tmp;

        seq_printf(seq, "%3d:  ", i);
        for (j = 0; j < STATS_MAX; j++)
        {   tmp = s->stats[j];
            global_stats.stats[j] += tmp;
            seq_printf(seq, "%8llu ", tmp);
        }
        seq_printf(seq, "\n");
    }

    seq_printf(seq, "total:");
    for (j = 0; j < STATS_MAX; j++)
        seq_printf(seq, "%8llu ", global_stats.stats[j]);
    seq_printf(seq, "\n");

    return 0;
}

static int uoa_stats_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, uoa_stats_show, NULL);
}


static const struct file_operations uoa_stats_fops = 
{
    .owner      = THIS_MODULE,
    .open       = uoa_stats_seq_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static int uoa_stats_init(void)
{
    int i;

    uoa_stats_cpu = alloc_percpu(struct uoa_stats);
    if  (!uoa_stats_cpu)
    {   pr_warn("%s: uoa_stats_cpu failed\n", __func__);
        return -ENOMEM;
    }

    for_each_possible_cpu(i)
    {
        struct uoa_stats* s = per_cpu_ptr(uoa_stats_cpu, i);
        memset(s, 0, sizeof(*s));
    }

    proc_create("uoa_stats", 0, init_net.proc_net, &uoa_stats_fops);

    return 0;
}

static void uoa_stats_exit(void)
{
    remove_proc_entry("uoa_stats", init_net.proc_net);
    free_percpu(uoa_stats_cpu);
}


// // uoa map --------------------------------------------------

enum IP_TYPE {
    IP_TYPE_V4 = 0,
    IP_TYPE_V6 = 1,
};

struct uoa_map_value {
    struct four_tuple four_tuple;
    __be32 svni;
};


struct uoa_map_bucket{
    struct hlist_head head;
    spinlock_t        lock;
};

struct uoa_map_entry{
    struct hlist_node       hlist;
    atomic_t                refcnt;
    struct timer_list       timer;

    struct four_tuple       key;
    // struct four_tuple       value;
    struct uoa_map_value value;
};


static int uoa_map_timeout = 360;
// static int uoa_map_timeout = 60;
module_param_named(uoa_map_timeout, uoa_map_timeout, int, 0444);
MODULE_PARM_DESC(uoa_map_timeout, "UOA mapping timeout in second");

#define UOA_MAP_TABLE_BITS 12
#define UOA_MAP_TABLE_SIZE (1 << UOA_MAP_TABLE_BITS)
#define UOA_MAP_TABLE_MASK (UOA_MAP_TABLE_SIZE - 1)

static struct uoa_map_bucket uoa_map_table[UOA_MAP_TABLE_SIZE] __read_mostly;
static atomic_t uoa_map_count = ATOMIC_INIT(0);

static struct kmem_cache *uoa_map_cache __read_mostly;
static unsigned int uoa_map_rand __read_mostly;



static void four_tuple_display(const char* prefix, const struct four_tuple* tuple)
{
    if  (tuple->type == IP_TYPE_V4)
    {
        pr_debug("%s %pI4:%d -> %pI4:%d\n", prefix, 
                tuple->addrs.ipv4.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv4.daddr, ntohs(tuple->dport));
    }
    else
    {
        pr_debug("%s %pI6:%d -> %pI6:%d\n", prefix, 
                tuple->addrs.ipv6.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv6.daddr, ntohs(tuple->dport));
    }
}

static void four_tuple_with_vni_display(const char* prefix,
        const struct four_tuple_with_vni* tuple)
{
    if  (tuple->type == IP_TYPE_V4)
    {
        pr_debug("%s %pI4:%d VNI %d -> %pI4:%d\n", prefix,
                tuple->addrs.ipv4.saddr, ntohs(tuple->sport),
                ntohl(tuple->svni),
                tuple->addrs.ipv4.daddr, ntohs(tuple->dport));
    }
    else
    {
        pr_debug("%s %pI6:%d VNI %d -> %pI6:%d\n", prefix,
                tuple->addrs.ipv6.saddr, ntohs(tuple->sport),
                ntohl(tuple->svni),
                tuple->addrs.ipv6.daddr, ntohs(tuple->dport));
    }
}

void uoa_map_value_display(const char* prefix, const struct uoa_map_value* value)
{
    const struct four_tuple* tuple = &value->four_tuple;

    if  (value->four_tuple.type == IP_TYPE_V4)
    {
        pr_debug("%s %pI4:%d -> %pI4:%d, svni: %u\n", prefix, 
                tuple->addrs.ipv4.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv4.daddr, ntohs(tuple->dport),
                ntohl(value->svni));
    }
    else
    {
        pr_debug("%s %pI6:%d -> %pI6:%d, svni: %u\n", prefix, 
                tuple->addrs.ipv6.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv6.daddr, ntohs(tuple->dport),
                ntohl(value->svni));
    }

    
}

static void uoa_map_entry_display(const char* prefix, const struct uoa_map_entry* entry)
{
    pr_debug("%s refcnt: %d ", prefix,  atomic_read(&entry->refcnt));
    pr_debug("uoa_map_count: %d", atomic_read(&uoa_map_count));
    four_tuple_display("key:   ", &entry->key);
    uoa_map_value_display("value: ", &entry->value);   
}


static inline unsigned int uoa_four_tuple_hash(const struct four_tuple* input)
{
    /* do not cal daddr, it could be zero for wildcard lookup */
    unsigned int saddr_fold = 0;
    if  (input->type  == IP_TYPE_V4){
        unsigned int* addr = (unsigned int*)input->addrs.ipv4.saddr;
        saddr_fold = *addr;
    }else if  (input->type == IP_TYPE_V6){
        unsigned int* addr = (unsigned int*)input->addrs.ipv6.saddr;
        saddr_fold = addr[0] ^ addr[1] ^ addr[2] ^ addr[3];
    }else
        return 0;
    
    return jhash_3words(saddr_fold, input->sport, input->dport, uoa_map_rand);
}

// A is in the hash_table, B is the get param
static inline bool uoa_two_addr_equal(enum IP_TYPE type, const union two_addr* A, const union two_addr* B)
{
    if  (type == IP_TYPE_V4)
        return (*(unsigned*)A->ipv4.saddr == *(unsigned*)B->ipv4.saddr)
                && ((*(unsigned*)A->ipv4.daddr == *(unsigned*)B->ipv4.daddr)
                        || (*(unsigned*)B->ipv4.daddr == htonl(INADDR_ANY)));
    else if  (type == IP_TYPE_V6)
    {   struct in6_addr ip6adummy = IN6ADDR_ANY_INIT;
        return memcmp(A->ipv6.saddr, B->ipv6.saddr, 16) == 0
                && (memcmp(A->ipv6.daddr, B->ipv6.daddr, 16) == 0
                        || memcmp(B->ipv6.daddr, &ip6adummy, 16) == 0);
    }
    else
        return false;
}

// A is in the hash_table, B is the get param
static inline bool uoa_four_tuple_equal(const struct four_tuple* A, const struct four_tuple* B)
{    
    return A->type == B->type
            && A->sport == B->sport
            && A->dport == B->dport
            && uoa_two_addr_equal(A->type, &A->addrs, &B->addrs); 
}


static inline bool four_tuple_equal(const struct four_tuple* A, const struct four_tuple* B)
{
    int addr_len = A->type == IP_TYPE_V4? 4 * 2 : 16 * 2;
    
    return A->type == B->type
            && A->sport == B->sport
            && A->dport == B->dport
            && (memcmp(&A->addrs, &B->addrs, addr_len) == 0); 
}


static void uoa_map_timer_expire(struct timer_list *timer);

static void uoa_map_insert(struct uoa_map_entry* entry)
{
    unsigned int index = uoa_four_tuple_hash(&entry->key) & UOA_MAP_TABLE_MASK;
    struct uoa_map_bucket* bucket = &uoa_map_table[index];
    struct hlist_head* head = &bucket->head;
    struct uoa_map_entry* cur;

    spin_lock_bh(&bucket->lock);

    hlist_for_each_entry_rcu(cur, head, hlist) 
    {
        if  (four_tuple_equal(&cur->key, &entry->key)) 
        {
            memmove(&cur->value, &entry->value, sizeof(cur->value));
            
            mod_timer(&cur->timer, jiffies + uoa_map_timeout * HZ);
            
            kmem_cache_free(uoa_map_cache, entry);
            uoa_map_entry_display("update: ", cur);

            goto found;
        }
    }

    hlist_add_head_rcu(&entry->hlist, head);
    timer_setup(&entry->timer, uoa_map_timer_expire, 0);
    mod_timer(&entry->timer, jiffies + uoa_map_timeout * HZ);
    atomic_set(&entry->refcnt, 0);
    atomic_inc(&uoa_map_count);
    uoa_map_entry_display("new: ", entry);

found:
    spin_unlock_bh(&bucket->lock);

}


static struct uoa_map_entry* uoa_map_get(const struct four_tuple* input)
{
    unsigned int index = uoa_four_tuple_hash(input) & UOA_MAP_TABLE_MASK;
    struct uoa_map_bucket* bucket = &uoa_map_table[index];
    struct hlist_head* head = &bucket->head;
    struct uoa_map_entry* cur;
    struct uoa_map_entry* result = NULL;

    

    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry_rcu(cur, head, hlist) 
    {
        if  (uoa_four_tuple_equal(&cur->key, input))
        {
            mod_timer(&cur->timer, jiffies + uoa_map_timeout * HZ);
            
            atomic_inc(&cur->refcnt);
            result = cur;
            goto found;
        }
    }

found:
    spin_unlock_bh(&bucket->lock);
    return result;
}

static void uoa_map_put(struct uoa_map_entry* entry)
{
    atomic_dec(&entry->refcnt);
}


static int uoa_map_remove(struct uoa_map_entry* entry)
{
    unsigned int index = uoa_four_tuple_hash(&entry->key) & UOA_MAP_TABLE_MASK;
    struct uoa_map_bucket* bucket = uoa_map_table + index;
    int err = -1;

    spin_lock_bh(&bucket->lock);
    if  (atomic_read(&entry->refcnt) == 0)
    {   
        hlist_del_rcu(&entry->hlist);
        atomic_dec(&uoa_map_count);
        uoa_map_entry_display("remove: ", entry);
        err = 0;
    }
    spin_unlock_bh(&bucket->lock);

    return err;
}

static void uoa_map_timer_expire__(struct uoa_map_entry* entry, struct timer_list* timer)
{
    if  (uoa_map_remove(entry) == 0)
    {
        uoa_map_entry_display("expire: ", entry);
        del_timer(timer);
        kmem_cache_free(uoa_map_cache, entry);
    }
    else
    {
        mod_timer(timer, jiffies + uoa_map_timeout * HZ);
        uoa_map_entry_display("delay: ", entry);
    }
}

static void uoa_map_timer_expire(struct timer_list *timer)
{
    struct uoa_map_entry* entry = from_timer(entry, timer, timer);

    uoa_map_timer_expire__(entry, timer);

}

static void uoa_map_flush(void)
{
    int i;
    int remaining = 0;

flush_again:
    for (i = 0; i < UOA_MAP_TABLE_SIZE; i++)
    {
        struct uoa_map_bucket* bucket = uoa_map_table + i;
        struct hlist_head* head = &bucket->head;
        struct hlist_node* node;
        struct uoa_map_entry* entry;

        spin_lock_bh(&bucket->lock);

        hlist_for_each_entry_safe(entry, node, head, hlist)
        {
            if  (timer_pending(&entry->timer))
                del_timer(&entry->timer);
            
            if  (atomic_read(&entry->refcnt) > 0)
                continue;
            
            uoa_map_entry_display("flush: ", entry);
            hlist_del_rcu(&entry->hlist);
            atomic_dec(&uoa_map_count);
            kmem_cache_free(uoa_map_cache, entry);
        }

        spin_unlock_bh(&bucket->lock);
    }

    if  ((remaining = atomic_read(&uoa_map_count)) > 0)
    {
        pr_debug("flush again, uoa_map_count: %d\n", remaining);
        schedule();
        goto flush_again;
    }

    pr_info("flush finished");
}


static int uoa_map_init(void)
{
    int i;

    for (i = 0; i < UOA_MAP_TABLE_SIZE; i++)
    {
        INIT_HLIST_HEAD(&uoa_map_table[i].head);
        spin_lock_init(&uoa_map_table[i].lock);
    }

    get_random_bytes(&uoa_map_rand, sizeof(uoa_map_rand));

    uoa_map_cache = kmem_cache_create("uoa_map",
            sizeof(struct uoa_map_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!uoa_map_cache) {
        pr_warn("fail to create uoa_map cache\n");
        return -ENOMEM;
    }

    return 0;
}

static void uoa_map_exit(void)
{
    uoa_map_flush();

    kmem_cache_destroy(uoa_map_cache);
}


// // uoa getsockopt--------------------------------------------------------------------------------------

static int v6_to_v4_enable = 0;
module_param_named(v6_to_v4_enable, v6_to_v4_enable, int, 0444);
MODULE_PARM_DESC(v6_to_v4_enable, "enable specific ipv6 addr trans to ipv4 addr, \
determined by v6_to_v4_prefix_str's first 96 bits");

static char* v6_to_v4_prefix_str = NULL;
module_param_named(v6_to_v4_prefix_str, v6_to_v4_prefix_str, charp, 0444);
MODULE_PARM_DESC(v6_to_v4_prefix_str, "the first 96 bits as prefix \
to determine wheather trans an ipv6 addr to ipv4 addr");

static char* v6_to_v4_prefix_str_default = "64:ff9b::";
static u8 v6_to_v4_prefix_addr[16]; // the first 96 bit as prefix to determine v6 to v4;



static int uoa_sockopt_set(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
    return 0;
}


static int uoa_sockopt_get_v0(void __user *user, int *len)
{
    struct uoa_param_map param;
    struct four_tuple key;
    struct uoa_map_entry* entry = NULL;
    uoa_stats_inc(STATS_GET_V0);


    if  (*len < sizeof(struct uoa_param_map))
    {   pr_debug("%s: bad param len: %d\n", __func__, *len);
        return -EINVAL;
    }

    if  (copy_from_user(&param, user, sizeof(struct uoa_param_map)) != 0)
    {   pr_debug("%s: copy failure", __func__);
        return -EFAULT;
    }

    {
        key.type = IP_TYPE_V4;
        key.sport = param.sport;
        key.dport = param.dport;
        memset(&key.addrs, 0, sizeof(key.addrs));
        *(unsigned*)key.addrs.ipv4.saddr = param.saddr;
        *(unsigned*)key.addrs.ipv4.daddr = param.daddr;
    }

    four_tuple_display("get_param_v0: ", &key);
    entry = uoa_map_get(&key);
    if  (!entry)
    {   pr_debug("%s: entry not found", __func__);
        return -ENOMEM;
    }
    uoa_map_value_display("value: ", &entry->value);

    if  (entry->value.four_tuple.type == IP_TYPE_V4)
    {   
        param.real_sport = entry->value.four_tuple.sport;
        param.real_saddr = *(unsigned*)entry->value.four_tuple.addrs.ipv4.saddr;
    }
    else
    {   pr_debug("%s: uoa_map_entry invalid\n", __func__);
    }
    uoa_map_put(entry);

    if  (copy_to_user(user, &param, sizeof(param)) != 0)
    {   pr_debug("%s: copy_to_user failed", __func__);
        return -ENOMEM;
    }
    *len = sizeof(param);

    uoa_stats_inc(STATS_GET_V0_SUCC);
    return 0;
}

static int uoa_sockopt_get_v1(void __user *user, int *len)
{
    union uoa_sockopt_param param;
    struct uoa_map_entry *entry = NULL;
    uoa_stats_inc(STATS_GET_V1);


    if  (*len < sizeof(union uoa_sockopt_param)) {
        pr_debug("%s: bad param len\n", __func__);
        return -EINVAL;
    }
    
    if  (copy_from_user(&param, user, sizeof(union uoa_sockopt_param)) != 0)
        return -EFAULT;
    four_tuple_display("get_param_v1: ", &param.input);
    
    entry = uoa_map_get(&param.input);
    if  (entry == NULL)
    {   pr_debug("uoa entry not found");
        return -ENOMEM;
    }

    if  (entry->value.four_tuple.type == IP_TYPE_V4) // v4
    {   
        param.output = entry->value.four_tuple;
    }
    else if  (entry->value.four_tuple.type == IP_TYPE_V6) // v6
    {   
        if  (unlikely(v6_to_v4_enable && entry->value.four_tuple.sport && entry->value.four_tuple.dport
                && strncmp(entry->value.four_tuple.addrs.ipv6.saddr, v6_to_v4_prefix_addr, 12) == 0
                && strncmp(entry->value.four_tuple.addrs.ipv6.daddr, v6_to_v4_prefix_addr, 12) == 0))
        {
            param.output.type = IP_TYPE_V4; // v4
            param.output.sport = entry->value.four_tuple.sport;
            param.output.dport = entry->value.four_tuple.dport;
            memset(&param.output.addrs, 0, sizeof(param.output.addrs));
            *(unsigned*)param.output.addrs.ipv4.saddr = *(unsigned*)(entry->value.four_tuple.addrs.ipv6.saddr + 12);
            *(unsigned*)param.output.addrs.ipv4.daddr = *(unsigned*)(entry->value.four_tuple.addrs.ipv6.daddr + 12);
        }
        else
        {   param.output = entry->value.four_tuple;
        }
    }
    else
    {    pr_debug("%s: uoa_map_entry invalid\n", __func__);
    }

    uoa_map_put(entry);
    four_tuple_display("value: ", &param.output);

    if  (copy_to_user(user, &param, sizeof(union uoa_sockopt_param)) != 0)
        return -EFAULT;
    *len = sizeof(union uoa_sockopt_param);

    uoa_stats_inc(STATS_GET_V1_SUCC);
    return 0;
}



static int uoa_sockopt_get_v2(void __user *user, int *len)
{
   union uoa_sockopt_param_v2 param;
   struct four_tuple map_key;
   struct uoa_map_entry *entry = NULL;
   uoa_stats_inc(STATS_GET_V2);

   if  (*len < sizeof(union uoa_sockopt_param_v2)) {
       pr_debug("%s: bad param len\n", __func__);
       return -EINVAL;
   }

   if  (copy_from_user(&param, user, sizeof(union uoa_sockopt_param_v2)) != 0)
       return -EFAULT;

   memcpy(&map_key.addrs, &param.input.addrs, sizeof(map_key.addrs));
   map_key.type = param.input.type;
   map_key.sport = htons(param.input.sport);
   map_key.dport = htons(param.input.dport);

   four_tuple_with_vni_display("get_param_v2: ", &param.input);

   entry = uoa_map_get(&map_key);
   if  (entry == NULL)
   {   // pr_debug("uoa entry not found");
       return -ENOMEM;
   }

   if  (entry->value.four_tuple.type == IP_TYPE_V4) // v4
   {
       param.output.type = IP_TYPE_V4;
       param.output.svni = ntohl(entry->value.svni);
       param.output.sport = ntohs(entry->value.four_tuple.sport);
       param.output.dport = ntohs(entry->value.four_tuple.dport);
       memcpy(param.output.addrs.ipv4.saddr, entry->value.four_tuple.addrs.ipv4.saddr,
              sizeof(param.output.addrs.ipv4.saddr));
       memcpy(param.output.addrs.ipv4.daddr, entry->value.four_tuple.addrs.ipv4.daddr,
              sizeof(param.output.addrs.ipv4.daddr));
   }
   else if  (entry->value.four_tuple.type == IP_TYPE_V6) // v6
   {
       if  (unlikely(v6_to_v4_enable && entry->value.four_tuple.sport && entry->value.four_tuple.dport
               && strncmp(entry->value.four_tuple.addrs.ipv6.saddr, v6_to_v4_prefix_addr, 12) == 0
               && strncmp(entry->value.four_tuple.addrs.ipv6.daddr, v6_to_v4_prefix_addr, 12) == 0))
       {
           param.output.type = IP_TYPE_V4; // v4
           param.output.svni = ntohl(entry->value.svni);
           param.output.sport = ntohs(entry->value.four_tuple.sport);
           param.output.dport = ntohs(entry->value.four_tuple.dport);
           memset(&param.output.addrs, 0, sizeof(param.output.addrs));
           *(unsigned*)param.output.addrs.ipv4.saddr = *(unsigned*)(entry->value.four_tuple.addrs.ipv6.saddr + 12);
           *(unsigned*)param.output.addrs.ipv4.daddr = *(unsigned*)(entry->value.four_tuple.addrs.ipv6.daddr + 12);
       }
       else
       {
           param.output.type = IP_TYPE_V6;
           param.output.svni = ntohl(entry->value.svni);
           param.output.sport = ntohs(entry->value.four_tuple.sport);
           param.output.dport = ntohs(entry->value.four_tuple.dport);
           memcpy(param.output.addrs.ipv6.saddr, entry->value.four_tuple.addrs.ipv6.saddr,
                  sizeof(param.output.addrs.ipv6.saddr));
           memcpy(param.output.addrs.ipv6.daddr, entry->value.four_tuple.addrs.ipv6.daddr,
                  sizeof(param.output.addrs.ipv6.daddr));
       }
   }
   else
   {    pr_debug("%s: uoa_map_entry invalid\n", __func__);
   }

   uoa_map_put(entry);
   four_tuple_with_vni_display("value: ", &param.output);

   if  (copy_to_user(user, &param, sizeof(union uoa_sockopt_param_v2)) != 0)
       return -EFAULT;
   *len = sizeof(union uoa_sockopt_param_v2);

    uoa_stats_inc(STATS_GET_V2_SUCC);
    return 0;
}


static int uoa_sockopt_get(struct sock *sk, int cmd, void __user *user, int *len)
{
    // pr_debug("uoa_sockopt_get: cmd: %d", cmd);

    if  (cmd == UOA_SO_GET_LOOKUP)
        return uoa_sockopt_get_v0(user, len);
    else if  (cmd == UOA_SO_GET_LOOKUP1)
        return uoa_sockopt_get_v1(user, len);
    else if  (cmd == UOA_SO_GET_LOOKUP2)
        return uoa_sockopt_get_v2(user, len);
    else
    {   pr_debug("uoa_sockopt_get bad cmd: %d", cmd);
        return -EINVAL;
    }

}

static struct nf_sockopt_ops uoa_sockopts = {
    .pf          = PF_INET,
    .owner        = THIS_MODULE,
    /* set */
    .set_optmin    = UOA_SO_BASE,
    .set_optmax    = UOA_SO_SET_MAX + 1,
    .set        = uoa_sockopt_set,
    /* get */
    .get_optmin    = UOA_SO_BASE,
    .get_optmax    = UOA_SO_GET_MAX + 1,
    .get        = uoa_sockopt_get,
};

static int uoa_sockopt_init(void)
{
    int err;
    /* socket option */
    err = nf_register_sockopt(&uoa_sockopts);
    if (err != 0) {
        pr_warn("fail to register sockopt\n");
        return -ENOMEM;
    }
    return 0;
}

static void uoa_sockopt_exit(void)
{
    nf_unregister_sockopt(&uoa_sockopts);
}


// // uoa hook ------------------------------------------------------------------------------

struct ip_option{
    union{
        struct{
            __u8 type;
            __u8 length;
            __u8 operation;
            __u8 padding;
        }ipv4;
        struct{
            __u8 nexthdr;
            __u8 hdrlen;
            __u8 option;
            __u8 optlen;
        }ipv6;
    }header;
    
    __be16 sport, dport;
    
    union two_addr addrs;
};

#define IPV4_OPTION_TYPE 31
#define IPV4_OPTION_ASYM_TYPE 30
#define IPV6_HEADER_OPTION 31
#define IPV6_HEADER_ASYM_OPTION 30


#define IP_OPTION_IPV4_LEN  16
#define IP_OPTION_IPV6_LEN  40

#define IPV6_HEADER_IPV4_LEN ((IP_OPTION_IPV4_LEN) / 8 - 1)
#define IPV6_HEADER_IPV6_LEN ((IP_OPTION_IPV6_LEN) / 8 - 1)
#define IPV6_HEADER_OPTION_IPV4_LEN (IP_OPTION_IPV4_LEN - 4)
#define IPV6_HEADER_OPTION_IPV6_LEN (IP_OPTION_IPV6_LEN - 4)


static int ip_option_to_four_tuple(enum IP_TYPE outside, struct ip_option* src, struct four_tuple* dst)
{
    int inside = -1;
    
    if  (outside == IP_TYPE_V4){
        // inside = src->header.ipv4.operation;
        if  (src->header.ipv4.operation == 0)
            inside = IP_TYPE_V4;
        else if  (src->header.ipv4.operation == 1)
            inside = IP_TYPE_V6;
    }
    else if  (outside == IP_TYPE_V6){
        if  (src->header.ipv6.optlen == IPV6_HEADER_OPTION_IPV4_LEN)
            inside = IP_TYPE_V4;
        else if  (src->header.ipv6.optlen == IPV6_HEADER_OPTION_IPV6_LEN)
            inside = IP_TYPE_V6;
    }

    if  (inside == IP_TYPE_V4){
        memset(dst, 0, sizeof(struct four_tuple));
        memcpy(dst, src, IP_OPTION_IPV4_LEN);
        dst->type = IP_TYPE_V4;

        return IP_OPTION_IPV4_LEN;
    }
    else if  (inside == IP_TYPE_V6){
        memcpy(dst, src, IP_OPTION_IPV6_LEN);
        dst->type = IP_TYPE_V6;

        return IP_OPTION_IPV6_LEN;
    }

    return -1;
}


struct ip_option_v2 {
    union{
        struct{
            __u8 type;
            __u8 length;
            __u8 operation;
            __u8 padding;
        }ipv4;
        struct{
            __u8 nexthdr;
            __u8 hdrlen;
            __u8 option;
            __u8 optlen;
        }ipv6;
    }header;

    __be32 svni;
    __be16 sport;
    __be16 _pad0;

    union {
		unsigned char saddr4[4];
		unsigned char saddr6[20]; /* extra 4 bytes padding */
    };
};


#define IPV4_OPTION_V2_TYPE 29
#define IPV6_HEADER_V2_OPTION 29

#define IP_OPTION_V2_IPV4_LEN  16
#define IP_OPTION_V2_IPV6_LEN  32

#define IPV6_HEADER_V2_IPV4_LEN ((IP_OPTION_V2_IPV4_LEN) / 8 - 1)
#define IPV6_HEADER_V2_IPV6_LEN ((IP_OPTION_V2_IPV6_LEN) / 8 - 1)
#define IPV6_HEADER_V2_OPTION_IPV4_LEN (IP_OPTION_V2_IPV4_LEN - 4)
#define IPV6_HEADER_V2_OPTION_IPV6_LEN (IP_OPTION_V2_IPV6_LEN - 4)




static int ip_option_v2_to_uoa_map_value(enum IP_TYPE outside, struct ip_option_v2* src, struct uoa_map_value* dst)
{
    int inside = -1;

    if  (outside == IP_TYPE_V4){
        // inside = src->header.ipv4.operation;
        if  (src->header.ipv4.operation == 0)
            inside = IP_TYPE_V4;
        else if  (src->header.ipv4.operation == 1)
            inside = IP_TYPE_V6;
    }
    else if  (outside == IP_TYPE_V6){
        if  (src->header.ipv6.optlen == IPV6_HEADER_V2_OPTION_IPV4_LEN)
            inside = IP_TYPE_V4;
        else if  (src->header.ipv6.optlen == IPV6_HEADER_V2_OPTION_IPV6_LEN)
            inside = IP_TYPE_V6;
    }

    if  (inside == IP_TYPE_V4){
        dst->four_tuple.type = IP_TYPE_V4;
        dst->four_tuple.sport = src->sport;
        dst->four_tuple.dport = 0;
        memcpy(&dst->four_tuple.addrs.ipv4.saddr, src->saddr4, sizeof(dst->four_tuple.addrs.ipv4.saddr));
        memset(&dst->four_tuple.addrs.ipv4.daddr, 0, sizeof(dst->four_tuple.addrs.ipv4.daddr));
        dst->svni = src->svni;

        return IP_OPTION_V2_IPV4_LEN;
    }
    else if  (inside == IP_TYPE_V6){
        dst->four_tuple.type = IP_TYPE_V6;
        
        dst->four_tuple.sport = src->sport;
        dst->four_tuple.dport = 0;
        memcpy(&dst->four_tuple.addrs.ipv6.saddr, src->saddr6, sizeof(dst->four_tuple.addrs.ipv6.saddr));
        memset(&dst->four_tuple.addrs.ipv6.daddr, 0, sizeof(dst->four_tuple.addrs.ipv6.daddr));
        dst->svni = src->svni;

        return IP_OPTION_V2_IPV6_LEN;
    }

    return -1;
}




static struct uoa_map_entry* uoa_ipv4_opt_rcv(struct iphdr* iph, struct sk_buff* skb)
{
    struct uoa_map_entry* entry;
    struct ip_option* ipopt = (struct ip_option*)(iph + 1);
    struct ip_option_v2* ipopt2 = (struct ip_option_v2*)(iph + 1);
    int ipopt_len = -1;
    struct udphdr* uh;


    entry = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
    if  (!entry)
    {   pr_debug("entry is NULL");
        return NULL;
    }    

    if (ipopt->header.ipv4.type == IPV4_OPTION_TYPE
        || ipopt->header.ipv4.type == IPV4_OPTION_ASYM_TYPE) 
    {
        uoa_stats_inc(STATS_IPV4_IP_OPTION);
        ipopt_len = ip_option_to_four_tuple(IP_TYPE_V4, ipopt, &entry->value.four_tuple);
        entry->value.svni = 0;
    } 
    else if (ipopt2->header.ipv4.type == IPV4_OPTION_V2_TYPE) 
    {
        uoa_stats_inc(STATS_IPV4_IP_OPTION_V2);
        ipopt_len = ip_option_v2_to_uoa_map_value(IP_TYPE_V4, ipopt2, &entry->value);
    }

    if  (ipopt_len < 0)
    {   pr_debug("%s: ip_option parse failed", __func__);
        kmem_cache_free(uoa_map_cache, entry);
        return NULL;
    }

    uh = (struct udphdr*)((void*)ipopt + ipopt_len);

    entry->key.type = IP_TYPE_V4;
    entry->key.sport = uh->source;
    entry->key.dport = uh->dest;
    memset(&entry->key.addrs, 0, sizeof(union two_addr));
    *((unsigned*)entry->key.addrs.ipv4.saddr) = iph->saddr;
    *((unsigned*)entry->key.addrs.ipv4.daddr) = iph->daddr;

    four_tuple_display("uoa_ipv4_opt_rcv: outside: ", &entry->key);
    uoa_map_value_display("uoa_ipv4_opt_rcv: inside:  ", &entry->value);

    return entry;
}


static struct uoa_map_entry* uoa_ipv6_opt_rcv(struct ipv6hdr* ip6h, struct sk_buff* skb)
{
    struct uoa_map_entry* entry;
    struct ip_option* ipopt = (struct ip_option*)(ip6h + 1);
    struct ip_option_v2* ipopt2 = (struct ip_option_v2*)(ip6h + 1);
    int ipopt_len = -1;
    struct udphdr* uh;


    entry = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
    if  (!entry)
    {   pr_debug("entry is NULL");
        return NULL;
    }
    
    if (ipopt->header.ipv6.option == IPV6_HEADER_OPTION
        || ipopt->header.ipv6.option == IPV6_HEADER_ASYM_OPTION) 
    {
        uoa_stats_inc(STATS_IPV6_IP_OPTION);
        ipopt_len = ip_option_to_four_tuple(IP_TYPE_V6, ipopt, &entry->value.four_tuple);
        entry->value.svni = 0;
    } 
    else if (ipopt2->header.ipv6.option == IPV6_HEADER_V2_OPTION) 
    {
        uoa_stats_inc(STATS_IPV6_IP_OPTION);
        ipopt_len = ip_option_v2_to_uoa_map_value(IP_TYPE_V6, ipopt2, &entry->value);
    }

    if  (ipopt_len < 0)
    {   pr_debug("%s: ip option parse failed", __func__);
        kmem_cache_free(uoa_map_cache, entry);
        return NULL;
    }

    uh = (struct udphdr*)((void*)ipopt + ipopt_len);

    entry->key.type = IP_TYPE_V6;
    entry->key.sport = uh->source;
    entry->key.dport = uh->dest;
    memcpy(entry->key.addrs.ipv6.saddr, &ip6h->saddr, 16);
    memcpy(entry->key.addrs.ipv6.daddr, &ip6h->daddr, 16);

    four_tuple_display("uoa_ipv6_opt_rcv: outside: ", &entry->key);
    uoa_map_value_display("uoa_ipv6_opt_rcv: inside:  ", &entry->value);

    return entry;
}



// /* get uoa info from private option protocol. */
// static struct uoa_map *uoa_opp_rcv(__be16 af, void *iph, struct sk_buff *skb)
// {
//     struct opphdr *opph;
//     struct udphdr *uh;
//     int optlen, opplen;
//     unsigned char *optptr;
//     struct uoa_map *um = NULL;
//     int iphdrlen = ((AF_INET6 == af) ? ipv6_hdrlen(skb) : ip_hdrlen(skb));

//     if (!pskb_may_pull(skb, iphdrlen + sizeof(struct opphdr)))
//       return NULL;

//     opph = iph + iphdrlen;
//     opplen = ntohs(opph->length);

//     if (unlikely(opph->protocol != IPPROTO_UDP)) {
//         pr_debug("bad opp header\n");
//         return NULL;
//     }

//     if (!pskb_may_pull(skb, iphdrlen + opplen + sizeof(*uh)))
//       return NULL;

//     uh = iph + iphdrlen + opplen;
//     optlen = opplen - sizeof(*opph);
//     optptr = (unsigned char *)(opph + 1);

//     /* try parse UOA option from ip-options */
//     um = uoa_parse_ipopt(af, optptr, optlen, iph, uh->source, uh->dest);

//     if (um && uoa_send_ack(skb) != 0) {
//         UOA_STATS_INC(uoa_ack_fail);
//         pr_debug("fail to send UOA ACK\n");
//     }

//     /*
//      * "remove" private option protocol, then adjust IP header
//      * protocol, tot_len and checksum. these could be slow ?
//      */

//     skb_set_transport_header(skb, iphdrlen + opplen);

//     /* Old kernel like 2.6.32 use "iph->ihl" rather "skb->transport_header"
//      * to get UDP header offset. The UOA private protocol data should be
//      * erased here, but this should move skb data and harm perfomance. As a
//      * compromise, we convert the private protocol data into NOP IP option
//      * data if possible.*/
//     if (AF_INET == af) {
//         if (((struct iphdr *)iph)->ihl + (opplen >> 2) < 16) {
//             ((struct iphdr *)iph)->ihl += (opplen >> 2);
//             memset(opph, opplen, IPOPT_NOOP);

//             /* need change it to parse transport layer */
//             ((struct iphdr *)iph)->protocol = opph->protocol;
//         } else {
//             pr_debug("IP header has no room to convert uoa data into option.\n");
//         }
//         /* re-calc checksum */
//         ip_send_check(iph);
//     } else {
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
//         struct ipv6hdr *ip6h = (struct ipv6hdr *)iph;
//         int payload_len = ntohs(ip6h->payload_len);
//         ip6h->payload_len = htons(payload_len - opplen);
//         ip6h->nexthdr = opph->protocol;
//         memmove(iph + iphdrlen, uh, ntohs(uh->len));
//         skb_set_transport_header(skb, iphdrlen);

//         /* disable udp checksum verification */
//         skb->ip_summed = CHECKSUM_UNNECESSARY;
// #else
//         pr_debug("ipv6 uoa is not supported in kernel version below 3.0.0.\n");
// #endif
//     }

//     return um;
// }

// ip header
// option protocol header
// uoa option in ip option format
// udp header


static int uoa_opp_parse(struct opphdr* opph, int opplen, struct uoa_map_entry* entry)
{
    struct kr_ipopt_uoa* ipopt = (struct kr_ipopt_uoa*)opph->options;

    if  (ipopt->op_len == IPOLEN_UOA_IPV4)
    {
        if  (opplen != sizeof(struct opphdr) +  IPOLEN_UOA_IPV4)
            return -1;

        entry->value.four_tuple.type = IP_TYPE_V4;
        entry->value.four_tuple.sport = ipopt->op_port;
        entry->value.four_tuple.dport = 0;
        memset(&entry->value.four_tuple.addrs, 0, sizeof(union two_addr));
        *((unsigned*)entry->value.four_tuple.addrs.ipv4.saddr) = ipopt->op_addr.in.s_addr;
    }
    else if  (ipopt->op_len == IPOLEN_UOA_IPV6)
    {
        if  (opplen != sizeof(struct opphdr) +  IPOLEN_UOA_IPV6)
            return -1;

        entry->value.four_tuple.type = IP_TYPE_V6;
        entry->value.four_tuple.sport = ipopt->op_port;
        entry->value.four_tuple.dport = 0;    
        memcpy(entry->value.four_tuple.addrs.ipv6.saddr, &ipopt->op_addr.in6, 16);
        memset(entry->value.four_tuple.addrs.ipv6.daddr, 0, 16);
    }
    else 
        return -1;

    return 0;
}

static struct uoa_map_entry* uoa_ipv4_opp_rcv(struct iphdr* iph, struct sk_buff* skb)
{
    struct opphdr *opph;
    struct udphdr *uh;
    struct uoa_map_entry* entry = NULL;
    int iphdrlen, opplen;
    

    // pr_debug("uoa_ipv4_opp_rcv: 1\n");
    iphdrlen = ip_hdrlen(skb);


    // pr_debug("uoa_ipv4_opp_rcv: 2\n");
    if  (!pskb_may_pull(skb, iphdrlen + sizeof(struct opphdr)))
    {   pr_debug("skb pull opphdr failed\n");
        return NULL;
    }
        
    // pr_debug("uoa_ipv4_opp_rcv: 3\n");
    opph = (struct opphdr*)((void*)iph + iphdrlen);
    opplen = ntohs(opph->length);
    if  (unlikely(opph->protocol != IPPROTO_UDP))
    {   pr_debug("opp carries not udp\n");
        return NULL;
    }
    

    if  (!pskb_may_pull(skb, iphdrlen + opplen + sizeof(*uh)))
    {   pr_debug("bad opp header\n");
        return NULL;
    }
    // pr_debug("uoa_ipv4_opp_rcv: 5\n");
    uh = (struct udphdr*)((void*)iph + iphdrlen + opplen);


    // at this stage, we have and entire option protocol.
    // pr_debug("uoa_ipv4_opp_rcv: 7\n");
    entry = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
    if  (!entry)
    {   pr_debug("entry is NULL");
        goto remove_opp;
    }

    if  (uoa_opp_parse(opph, opplen, entry) < 0)
    {   pr_debug("parse opp failed\n");
        kmem_cache_free(uoa_map_cache, entry);
        goto remove_opp;
    }
    entry->value.svni = 0;

    // pr_debug("uoa_ipv4_opp_rcv: 8\n");
    entry->key.type = IP_TYPE_V4;
    entry->key.sport = uh->source;
    entry->key.dport = uh->dest;
    memset(&entry->key.addrs, 0, sizeof(union two_addr));
    *((unsigned*)entry->key.addrs.ipv4.saddr) = iph->saddr;
    *((unsigned*)entry->key.addrs.ipv4.daddr) = iph->daddr;

    four_tuple_display("uoa_ipv4_opp_rcv: outside: ", &entry->key);
    uoa_map_value_display("uoa_ipv4_opp_rcv: inside:  ", &entry->value);

remove_opp:
    // pr_debug("uoa_ipv4_opp_rcv: 9\n");
    
    if  (iphdrlen + opplen <= 60)
    {   // change option protocol to ip option.
        // pr_debug("uoa_ipv4_opp_rcv: 11\n");
        iph->ihl += opplen >> 2;
        iph->protocol = opph->protocol;
        memset(opph, IPOPT_END, opplen);
        
        ip_send_check(iph);

        skb_set_transport_header(skb, iphdrlen + opplen); // this is necessary.
        // pr_debug("uoa_ipv4_opp_rcv: 12\n");
    }
    else
    {   // move udp data to directly follow ip header.
        // pr_debug("uoa_ipv4_opp_rcv: 13\n");
        iph->protocol = opph->protocol;
        iph->tot_len  = htons(ntohs(iph->tot_len) - opplen);
        memmove((void*)iph + iphdrlen, 
                (void*)iph + iphdrlen + opplen, 
                ntohs(iph->tot_len) - iphdrlen - opplen);
        skb_set_transport_header(skb, iphdrlen);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        // pr_debug("uoa_ipv4_opp_rcv: 14\n");
    }

    // pr_debug("uoa_ipv4_opp_rcv: 15\n");
    return entry;
}




static struct uoa_map_entry* uoa_ipv6_opp_rcv(struct ipv6hdr* ip6h, struct sk_buff* skb)
{
    struct opphdr *opph;
    struct udphdr *uh;
    struct uoa_map_entry* entry = NULL;
    int iphdrlen, opplen;
    // int i;

    
    // pr_debug("uoa_ipv6_opp_rcv: 1\n");
    iphdrlen = sizeof(struct ipv6hdr);


    // pr_debug("uoa_ipv6_opp_rcv: 2\n");
    if  (!pskb_may_pull(skb, iphdrlen + sizeof(struct opphdr)))
    {   pr_debug("skb pull opphdr failed\n");
        return NULL;
    }
        
    // pr_debug("uoa_ipv6_opp_rcv: 3\n");
    opph = (struct opphdr*)((void*)ip6h + iphdrlen);
    opplen = ntohs(opph->length);
    if  (unlikely(opph->protocol != IPPROTO_UDP))
    {   pr_debug("opp carries not udp\n");
        return NULL;
    }
    

    if  (!pskb_may_pull(skb, iphdrlen + opplen + sizeof(*uh)))
    {   pr_debug("bad opp header\n");
        return NULL;
    }
    // pr_debug("uoa_ipv6_opp_rcv: 5\n");
    uh = (struct udphdr*)((void*)ip6h + iphdrlen + opplen);


    // at this stage, we have and entire option protocol.
    // pr_debug("uoa_ipv6_opp_rcv: 7\n");
    entry = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
    if  (!entry)
    {   pr_debug("entry is NULL");
        goto remove_opp;
    }

    if  (uoa_opp_parse(opph, opplen, entry) < 0)
    {   pr_debug("parse opp failed\n");
        kmem_cache_free(uoa_map_cache, entry);
        goto remove_opp;
    }
    entry->value.svni = 0;

    // pr_debug("uoa_ipv6_opp_rcv: 8\n");
    entry->key.type = IP_TYPE_V6;
    entry->key.sport = uh->source;
    entry->key.dport = uh->dest;
    memcpy(entry->key.addrs.ipv6.saddr, &ip6h->saddr, 16);
    memcpy(entry->key.addrs.ipv6.daddr, &ip6h->daddr, 16);

    four_tuple_display("uoa_ipv6_opp_rcv: outside: ", &entry->key);
    uoa_map_value_display("uoa_ipv6_opp_rcv: inside:  ", &entry->value);


remove_opp:
    // pr_debug("uoa_ipv6_opp_rcv: 9\n");
    
    {   // move udp data to directly follow ip header.
        pr_debug("opp_len: %d\n", opplen);
        ip6h->nexthdr = opph->protocol;
        ip6h->payload_len  = htons(ntohs(ip6h->payload_len) - opplen);
        
        memmove((void*)ip6h + iphdrlen, 
                (void*)ip6h + iphdrlen + opplen, 
                ntohs(ip6h->payload_len));
    }
    // {
    //     // struct ipv6hdr *ip6h = (struct ipv6hdr *)iph;
    //     int payload_len = ntohs(ip6h->payload_len);
    //     ip6h->payload_len = htons(payload_len - opplen);
    //     ip6h->nexthdr = opph->protocol;
    //     memmove((void*)ip6h + iphdrlen, uh, ntohs(uh->len));
    //     // skb_set_transport_header(skb, iphdrlen);

    //     /* disable udp checksum verification */
    //     // skb->ip_summed = CHECKSUM_UNNECESSARY;
    // }
    // {
    //     unsigned char* start = (void*)opph;
    //     unsigned char nexthdr = opph->protocol;
    //     pr_debug("opph->protocol: %d", nexthdr);
    //     ip6h->nexthdr = 60;

    //     memset(opph, 0, opplen);
    //     start[0] = nexthdr;
    //     start[1] = opplen / 8 - 1;
    //     start[2] = 31;
    //     start[3] = opplen - 2;        
    // }

    // for (i = 0; i < 32; i++)
    //     pr_debug("%2d: 0x%08x ", i, htonl(((unsigned*)ip6h)[i]));

    // pr_debug("uoa_ipv6_opp_rcv: 15\n");
    return entry;

}



static unsigned int uoa_ipv4_local_in(void *priv, struct sk_buff *skb, 
        const struct nf_hook_state *state)
{
    struct iphdr* iph = ip_hdr(skb);
    uoa_stats_inc(STATS_IPV4_RCV);

    if  (unlikely(iph->ihl > 5) 
            && iph->protocol == IPPROTO_UDP 
            && (((struct ip_option*)(iph + 1))->header.ipv4.type == IPV4_OPTION_TYPE
                || ((struct ip_option*)(iph + 1))->header.ipv4.type == IPV4_OPTION_ASYM_TYPE
                || ((struct ip_option_v2*)(iph + 1))->header.ipv4.type == IPV4_OPTION_V2_TYPE)
        )
    {
        struct uoa_map_entry* entry = uoa_ipv4_opt_rcv(iph, skb);

        if  (entry) {
            uoa_map_insert(entry);
            uoa_stats_inc(STATS_IPV4_SAVED);
        }
        else
            pr_debug("uoa_ipv4_opt_rcv return NULL");
    }
    else if  (unlikely(iph->protocol == IPPROTO_OPT))
    {
        struct uoa_map_entry* entry = uoa_ipv4_opp_rcv(iph, skb);
        uoa_stats_inc(STATS_IPV4_OPTION_PROTOCOL);

        if  (entry) {
            uoa_map_insert(entry);
            uoa_stats_inc(STATS_IPV4_SAVED);
        }
        else
            pr_debug("uoa_ipv4_opp_rcv return NULL");
    }

    return NF_ACCEPT;
}


static unsigned int uoa_ipv6_local_in(void *priv, struct sk_buff *skb, 
        const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    uoa_stats_inc(STATS_IPV6_RCV);


    if  (unlikely(ip6h->nexthdr == IPPROTO_DSTOPTS)
            && ((struct ip_option*)(ip6h +1))->header.ipv6.nexthdr == IPPROTO_UDP
            && (((struct ip_option*)(ip6h +1))->header.ipv6.option == IPV6_HEADER_OPTION
                || ((struct ip_option*)(ip6h +1))->header.ipv6.option == IPV6_HEADER_ASYM_OPTION
                || ((struct ip_option*)(ip6h +1))->header.ipv6.option == IPV6_HEADER_V2_OPTION)
        )
    {
        struct uoa_map_entry* entry = uoa_ipv6_opt_rcv(ip6h, skb);

        if  (entry) {
            uoa_map_insert(entry);
            uoa_stats_inc(STATS_IPV6_SAVED);
        }
        else
            pr_debug("uoa_ipv6_opt_rcv return NULL");
    }
    else if  (ip6h->nexthdr == IPPROTO_OPT)
    {
        struct uoa_map_entry* entry = uoa_ipv6_opp_rcv(ip6h, skb);
        uoa_stats_inc(STATS_IPV6_OPTION_PROTOCOL);

        if  (entry) {
            uoa_map_insert(entry);
            uoa_stats_inc(STATS_IPV6_SAVED);
        }
        else
            pr_debug("uoa_ipv6_opp_rcv return NULL");
    }

    return NF_ACCEPT;
}

/*
 * use nf LOCAL_IN hook to get UOA option.
 */
static struct nf_hook_ops uoa_nf_hook_ops[] __read_mostly = {
    {
        .hook       = uoa_ipv4_local_in,
        .pf         = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_IN,
        .priority   = NF_IP_PRI_NAT_SRC + 1,
    },
};

static struct nf_hook_ops uoa_nf_hook_ops6[] __read_mostly = {
    {
        .hook       = uoa_ipv6_local_in,
        .pf         = NFPROTO_IPV6,
        .hooknum    = NF_INET_LOCAL_IN,
        .priority   = NF_IP_PRI_NAT_SRC + 1,
    },
};


static int uoa_nf_hook_init(void)
{
    int err = -ENOMEM;
    
    pr_debug("uoa_nf_hook_init 1");
    err = nf_register_net_hooks(&init_net, uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
    if (err < 0) {
        pr_warn("fail to register netfilter ipv4 hooks.\n");
        goto hook4_failed;
    }

    pr_debug("uoa_nf_hook_init 2");
    err = nf_register_net_hooks(&init_net, uoa_nf_hook_ops6, ARRAY_SIZE(uoa_nf_hook_ops6));
    if (err < 0) {
        pr_warn("fail to register netfilter ipv6 hooks.\n");
        goto hook6_failed;
    }

    pr_debug("uoa_nf_hook_init 3");
    return 0;

hook6_failed:
    nf_unregister_net_hooks(&init_net, uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
hook4_failed:
    return err;
}

static void uoa_nf_hook_exit(void)
{
    nf_unregister_net_hooks(&init_net, uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
    
    nf_unregister_net_hooks(&init_net, uoa_nf_hook_ops6, ARRAY_SIZE(uoa_nf_hook_ops6));
    
    pr_debug("uoa_nf_hook_exit completed");
}


// uoa init -----------------------------------------------------------------------------

static __init int uoa_init(void)
{
    int err = -ENOMEM;

    if  (v6_to_v4_prefix_str == NULL) v6_to_v4_prefix_str = v6_to_v4_prefix_str_default;
	
	if  (in6_pton(v6_to_v4_prefix_str, -1, v6_to_v4_prefix_addr, '\0', NULL) <= 0)
	{   pr_warn("bad v6_to_v4_prefix_str %s\n", v6_to_v4_prefix_str);
	    goto addr_err;
	}


    pr_info("uoa init with uoa_map_timeout = %d, v6_to_v4_enable: %d, v6_to_v4_prefix_str: %pI6\n", 
            uoa_map_timeout, v6_to_v4_enable, v6_to_v4_prefix_addr);

    // stats init
    pr_debug("uoa_init 1");    
    err = uoa_stats_init();
    if  (err != 0)
    {   pr_warn("%s: uoa_stats_init failed", __func__);
        goto stats_failed;
    }

    // map init 
    pr_debug("uoa_init 2");
    err = uoa_map_init();
    if  (err != 0)
    {   pr_warn("%s: uoa_map_init failed", __func__);
        goto map_failed;
    }   

    // sockopt init
    pr_debug("uoa_init 3");    
    err = uoa_sockopt_init();
    if  (err != 0)
    {   pr_warn("%s: uoa_sockopt_init failed", __func__);
        goto sockopt_failed;
    }
        
    // netfilter init
    pr_debug("uoa_init 4");    
    err = uoa_nf_hook_init();
    if  (err != 0)  
    {   pr_warn("%s: uoa_nf_hook_init faield\n", __func__);
        goto netfilter_failed;
    }


    pr_info("UOA module installed\n");
    return 0;

netfilter_failed:
    uoa_sockopt_exit();
sockopt_failed:
    uoa_map_exit();
map_failed:
    uoa_stats_exit();
stats_failed:
addr_err:
    return err;
}

static __exit void uoa_exit(void)
{
    uoa_nf_hook_exit();

    uoa_sockopt_exit();

    synchronize_net();

    uoa_map_exit();

    uoa_stats_exit();

    pr_info("UOA module removed\n");
    pr_debug("UOA -----------------------------\n");
}


module_init(uoa_init);
module_exit(uoa_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION(UOA_VERSION);
MODULE_AUTHOR("Qianyu Zhang <zhangianyu.sys@bytedance.com>");
