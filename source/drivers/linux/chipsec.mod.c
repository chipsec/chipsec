#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x830e547b, "ioremap_prot" },
	{ 0x799c50a, "param_set_ulong" },
	{ 0x7edc1537, "device_destroy" },
	{ 0xfa0d49c7, "__register_chrdev" },
	{ 0x3758301, "mutex_unlock" },
	{ 0x9629486a, "per_cpu__cpu_number" },
	{ 0xde0bdcff, "memset" },
	{ 0xf10de535, "ioread8" },
	{ 0xea147363, "printk" },
	{ 0x85f8a266, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0xfee8a795, "mutex_lock" },
	{ 0x2d2cf7d, "device_create" },
	{ 0x7dceceac, "capable" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0x727c4f3, "iowrite8" },
	{ 0x91766c09, "param_get_ulong" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x8c183cbe, "iowrite16" },
	{ 0x37a0cba, "kfree" },
	{ 0xedc03953, "iounmap" },
	{ 0xe06bb002, "class_destroy" },
	{ 0xc5534d64, "ioread16" },
	{ 0xabcb345a, "directly_mappable_cdev_bdi" },
	{ 0x436c2179, "iowrite32" },
	{ 0xa2654165, "__class_create" },
	{ 0x3302b500, "copy_from_user" },
	{ 0xd6a78d08, "smp_call_function_single" },
	{ 0xe484e35f, "ioread32" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 8,
	.rhel_release = 641,
};
