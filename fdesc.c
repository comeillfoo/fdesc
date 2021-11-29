#include <linux/module.h> /* essential for modules */
#include <linux/kernel.h> /* essential for KERNEL_INFO */

#include <linux/sched.h> /* essential for task_struct */
#include <linux/sched/signal.h> /* essential for_each_process */
#include <linux/proc_fs.h> /* essential for procfs */
#include <linux/slab.h> /* essential for kmalloc, kfree */
#include <linux/fdtable.h> /* essential for files_struct */
#include <linux/pid.h> /* essential for get_task_pid, find_get_pid */ 

MODULE_LICENSE( "Dual MIT/GPL" );

#define MOD_NAME "fdesc"
#define ROOT_PROC_NAME "fdescs"
#define MIN_KERN_BUF_CAP 16
#define MAX_PATH_LEN 4096


static size_t pid_to_str( pid_t pid, char** pid_buf );


static ssize_t proc_fdescs_pid_read( struct file *ptr_file, char __user * usr_buf, size_t length, loff_t * ptr_pos );


static const struct proc_ops  proc_fdescs_pid_ops = {
    .proc_read = proc_fdescs_pid_read
};


static struct proc_dir_entry* proc_fdescs_root;


static int __init init_fdesc( void ) {
    struct task_struct* ptr_task_itr = NULL;
    printk( KERN_INFO MOD_NAME ": init_fdesc: module loaded\n" );
    proc_fdescs_root = proc_mkdir( ROOT_PROC_NAME, NULL );
    printk( KERN_INFO MOD_NAME ": init_fdesc: created root proc entry " ROOT_PROC_NAME "\n" );
    
    for_each_process( ptr_task_itr ) {
        size_t pid_str_cnt = 0;
        char* pid_str = NULL;
        pid_str_cnt = pid_to_str( ptr_task_itr->pid, &pid_str );
        proc_create( pid_str, 0444, proc_fdescs_root, &proc_fdescs_pid_ops );
        kfree( pid_str );
        printk( KERN_INFO MOD_NAME ": init_fdesc: [ created entry for pid: %u ]", ptr_task_itr->pid );
        if ( pid_str_cnt == 0 ) return 0;
    }
    return 0;
}


static void __exit cleanup_fdesc( void ) {
    printk( KERN_INFO MOD_NAME ": cleanup_fdesc: module unloaded\n" );
    proc_remove( proc_fdescs_root );
}


module_init( init_fdesc );
module_exit( cleanup_fdesc );


static size_t __do_get_length( u64 n ) {
    if ( n == 0 )
        return 0;
    else return __do_get_length( n / 10 ) + 1;
}


static size_t get_length( u64 n ) {
    const size_t length = __do_get_length( n );
    return ( length == 0 )? 1 : length;
} 


static size_t uint32_to_str( char** dest, const char* fmt, size_t fmt_len, unsigned int num ) {
    size_t dest_sz = 0;
    size_t len = 0;

    len = get_length( num );
    
    *dest = kmalloc( sizeof( char ) * ( len + fmt_len ), GFP_KERNEL );
    if ( *dest == NULL ) {
        printk( KERN_CRIT MOD_NAME ": uint32_to_str: can't allocate memory for the buffer\n" );
        printk( KERN_CRIT MOD_NAME ": uint32_to_str: [ dest: %p, fmt: \"%s\", fmt_len: %zu, num: %u ]\n", dest, fmt, fmt_len, num );
        return 0;
    }
    
    dest_sz = sprintf( *dest, fmt, num );
    return dest_sz;
}


static size_t uint64_to_str( char** dest, const char* fmt, size_t fmt_len, u64 num ) {
    size_t dest_sz = 0;
    size_t len = 0;

    len = get_length( num );
    
    *dest = kmalloc( sizeof( char ) * ( len + fmt_len ), GFP_KERNEL );
    if ( *dest == NULL ) {
        printk( KERN_CRIT MOD_NAME ": uint64_to_str: can't allocate memory for the buffer\n" );
        printk( KERN_CRIT MOD_NAME ": uint64_to_str: [ dest: %p, fmt: \"%s\", fmt_len: %zu, num: %llu ]\n", dest, fmt, fmt_len, num );
        return 0;
    }
    
    dest_sz = sprintf( *dest, fmt, num );
    return dest_sz;
}


static size_t ptr_to_str( void const * const ptr, char** dest, const char* key, size_t key_len ) {
    const char* fmt = "\"%s\": \"%016p\",";
    size_t fmt_len = 7;
    size_t dest_sz = 0;
    size_t len = 16;

    *dest = kmalloc( sizeof( char ) * ( len + fmt_len + key_len ), GFP_KERNEL );
    if ( *dest == NULL ) {
        printk( KERN_CRIT MOD_NAME ": ptr_to_str: can't allocate memory for the buffer\n" );
        printk( KERN_CRIT MOD_NAME ": ptr_to_str: [ dest: %p, ptr: %p ]\n", dest, ptr );
        return 0;
    }
    
    dest_sz = sprintf( *dest, fmt, key, ptr );
    return dest_sz;
}

static size_t str_to_str( const char* str, char** dest, const char* key, size_t key_len ) {
    const char* fmt = "\"%s\": \"%s\",";
    size_t fmt_len = 7;
    size_t dest_sz = 0;
    size_t len = strlen( str );

    *dest = kmalloc( sizeof( char ) * ( len + fmt_len + key_len ), GFP_KERNEL );
    if ( *dest == NULL ) {
        printk( KERN_CRIT MOD_NAME ": ptr_to_str: can't allocate memory for the buffer\n" );
        printk( KERN_CRIT MOD_NAME ": ptr_to_str: [ dest: %p, str: \"%s\" ]\n", dest, str );
        return 0;
    }
    
    dest_sz = sprintf( *dest, fmt, key, str );
    return dest_sz;
}


static size_t pid_to_str( pid_t pid, char** pid_buf ) {
    return uint32_to_str( pid_buf, "%d", 0, ( unsigned int ) pid );
}


static size_t fd_to_str( unsigned int fd, char** fd_buf ) {
    return uint32_to_str( fd_buf, "\"%u\": {", 5, fd );
}


struct kstring {
    size_t capacity;
    size_t size;
    char* data;
};


static void kstring_free( struct kstring* ptr_kstr ) {
    kfree( ptr_kstr->data );
}

static size_t kstring_get_capacity( size_t old_cap ) {
    return old_cap + old_cap / 2;
}

static bool kstring_is_full( struct kstring* ptr_kstr, size_t sz ) {
    return ( ( ptr_kstr->size + sz ) >= ptr_kstr->capacity );
}

static int kstring_grow( struct kstring* ptr_kstr, size_t sz ) {
    while ( kstring_is_full( ptr_kstr, sz ) )
        ptr_kstr->capacity = kstring_get_capacity( ptr_kstr->capacity );
    ptr_kstr->data = ( char* ) krealloc( ptr_kstr->data, ptr_kstr->capacity, GFP_KERNEL );
    if ( ptr_kstr->data == NULL ) {
        printk( KERN_CRIT MOD_NAME ": kstring_grow: can't reallocate kernel string\n" );
        printk( KERN_CRIT MOD_NAME ": kstring_grow: [ ptr_kstr: %p, capacity: %zu, old size: %zu ]\n",
            ptr_kstr, ptr_kstr->capacity, ptr_kstr->size );
        return -1;   
    }
    return 0;
}


static size_t kstring_write( struct kstring* ptr_kstr, const char* src ) {
    size_t src_sz = strlen( src );
    printk( KERN_INFO MOD_NAME ": kstring_write: starting write from { %s } to %p ]\n", src, ptr_kstr );

    if ( kstring_is_full( ptr_kstr, src_sz ) )
        if ( kstring_grow( ptr_kstr, src_sz ) == -1 )
            return ptr_kstr->size = 0;

    ptr_kstr->size += sprintf( ptr_kstr->data + ptr_kstr->size, src );
    printk( KERN_INFO MOD_NAME ": kstring_write: [ count: %zu, capacity: %zu ]\n", ptr_kstr->size, ptr_kstr->capacity );
    return ptr_kstr->size;
}

static size_t kstring_write_file( struct kstring* ptr_kstr, struct file* ptr_file ) {
    size_t cnt = 0;
    char* ptr = NULL;

    char* full_path = kmalloc( sizeof( char ) * MAX_PATH_LEN, GFP_KERNEL );
    str_to_str( dentry_path_raw( ptr_file->f_path.dentry, full_path, MAX_PATH_LEN ), &ptr, "f_path.dentry", 13 );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    kfree( full_path );
    if ( !cnt ) return 0;

    ptr = NULL;
    ptr_to_str( ptr_file->f_inode, &ptr, "f_inode", 7 );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    ptr_to_str( ptr_file->f_op, &ptr, "f_op", 4 );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint32_to_str( &ptr, "\"f_mode\": \"%x\",", 13, ptr_file->f_mode );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint32_to_str( &ptr, "\"f_flags\": \"%x\",", 14, ptr_file->f_flags );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint64_to_str( &ptr, "\"f_pos\": %llu,", 10, ptr_file->f_pos );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint64_to_str( &ptr, "\"f_version\": %llu,", 14, ptr_file->f_version );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint32_to_str( &ptr, "\"f_wb_err\": %u,", 13, ptr_file->f_wb_err );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    ptr = NULL;
    uint32_to_str( &ptr, "\"f_sb_err\": %u", 12, ptr_file->f_sb_err );
    cnt += kstring_write( ptr_kstr, ptr );
    kfree( ptr );
    if ( !cnt ) return 0;

    return cnt;
}

static int fd_itr_callback_fn( const void * ptr, struct file* ptr_file, unsigned int fd ) {
    struct kstring* ptr_kern_buf = ( struct kstring* ) ptr;
    size_t kstr_written_cnt = 0;

    // read start
    char* fd_str = NULL;
    fd_to_str( fd, &fd_str );
    kstr_written_cnt = kstring_write( ptr_kern_buf, fd_str );
    kfree( fd_str );
    if ( !kstr_written_cnt ) return ~0;
    // read finish

    // read start
    if ( !kstring_write_file( ptr_kern_buf, ptr_file ) ) return ~0;
    // read finish

    // read start
    if ( !kstring_write( ptr_kern_buf, "}," ) ) return ~0;
    // read finish

    return 0;
}


static void fill_the_entry( int pid, struct kstring* ptr_kern_buf ) {
    struct task_struct* ptr_task_itr = get_pid_task( find_get_pid( pid ), PIDTYPE_PID );
    ptr_kern_buf->data = kmalloc( sizeof( char ) * MIN_KERN_BUF_CAP, GFP_KERNEL );
    ptr_kern_buf->capacity = MIN_KERN_BUF_CAP;
    ptr_kern_buf->size = 0;
    printk( KERN_INFO MOD_NAME ": fill_the_entry: pid=%u\n", pid );

    if ( ptr_task_itr == NULL ) return;
    
    // read start
    if ( !kstring_write( ptr_kern_buf, "{" ) ) return;
    // read finish

    iterate_fd( ptr_task_itr->files, 0, fd_itr_callback_fn, ptr_kern_buf );

    // read start
    if ( !kstring_write( ptr_kern_buf, "}\n\0" ) ) return;
    // read finish
}

static int get_pid_from_file( struct file* ptr_file ) {
    char* d_iname = ptr_file->f_path.dentry->d_iname;
    int result = -1;
    printk( KERN_INFO MOD_NAME ": get_pid_from_file: d_iname=%s\n", d_iname );
    return !kstrtoint( d_iname, 10, &result )? result : -1;
}

static ssize_t proc_fdescs_pid_read( struct file* ptr_file, char __user * usr_buf, size_t length, loff_t* ptr_pos ) {
    struct kstring kern_buf;
    unsigned int pid = 1;
    printk( KERN_INFO MOD_NAME ": proc_fdesc_pid_read: [ ptr_file: %p ], [ usr_buf: %p ], [ length: %zu ], [ ptr_pos: %p ]\n", ptr_file, usr_buf, length, ptr_pos );

    if ( *ptr_pos > 0 ) return 0;

    pid = get_pid_from_file( ptr_file );
    fill_the_entry( pid, &kern_buf );

    if ( !copy_to_user( usr_buf, kern_buf.data, kern_buf.size ) )
        *ptr_pos += kern_buf.size;
    else {
        printk( KERN_CRIT MOD_NAME ": proc_fdesc_pid_read: can't copy to user buffer\n" );
        if ( kern_buf.data != NULL ) kstring_free( &kern_buf );
        return 0;
    }

    if ( kern_buf.data == NULL ) {
        printk( KERN_CRIT MOD_NAME ": proc_fdesc_pid_read: can't free the kernel buffer 'cause of corrupted pointer\n" );
        return 0;
    } else kstring_free( &kern_buf );

    return kern_buf.size;
}