// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2001-2004 Aurelien Jarno <aurelien@aurel32.net>
 * Ported to Linux 2.6 by Aurelien Jarno <aurelien@aurel32.net> with
 * the help of Jean Delvare <jdelvare@suse.de>
 * Ported to Linux 5.10.16  by Vijay Panchal
 * Modified and maintained by Vijay Panchal <vijayp.work@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/hwmon.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define PCF8591_NUM_CHANNELS 4

/* Insmod parameters */

static int input_mode;
module_param(input_mode, int, 0);
MODULE_PARM_DESC(input_mode,
	"Analog input mode:\n"
	" 0 = four single ended inputs\n"
	" 1 = three differential inputs\n"
	" 2 = single ended and differential mixed\n"
	" 3 = two differential inputs\n");

/*
 * The PCF8591 control byte
 *      7    6    5    4    3    2    1    0
 *   |  0 |AOEF|   AIP   |  0 |AINC|  AICH   |
 */

/* Analog Output Enable Flag (analog output active if 1) */
#define PCF8591_CONTROL_AOEF		0x40

/*
 * Analog Input Programming
 * 0x00 = four single ended inputs
 * 0x10 = three differential inputs
 * 0x20 = single ended and differential mixed
 * 0x30 = two differential inputs
 */
#define PCF8591_CONTROL_AIP_MASK	0x30

/* Autoincrement Flag (switch on if 1) */
#define PCF8591_CONTROL_AINC		0x04

/*
 * Channel selection
 * 0x00 = channel 0
 * 0x01 = channel 1
 * 0x02 = channel 2
 * 0x03 = channel 3
 */
#define PCF8591_CONTROL_AICH_MASK	0x03

/* Initial values */
#define PCF8591_INIT_CONTROL	((input_mode << 4) | PCF8591_CONTROL_AOEF)
#define PCF8591_INIT_AOUT	0	/* DAC out = 0 */

/* Conversions */
#define REG_TO_SIGNED(reg)	(((reg) & 0x80) ? ((reg) - 256) : (reg))

struct pcf8591_data {
    struct i2c_client *client; // <-- Add this line
    struct device *hwmon_dev;
    struct mutex update_lock;
    u8 control;
    u8 aout;

    struct cdev cdev[PCF8591_NUM_CHANNELS];
    dev_t devt_base;
    struct class *class;
};

static void pcf8591_init_client(struct i2c_client *client);
static int pcf8591_read_channel(struct pcf8591_data *data, int channel);

/* following are the sysfs callback functions */
#define show_in_channel(channel)					\
static ssize_t show_in##channel##_input(struct device *dev,		\
                    struct device_attribute *attr,	\
                    char *buf)			\
{								\
    struct i2c_client *client = to_i2c_client(dev);		\
    struct pcf8591_data *data = i2c_get_clientdata(client);	\
    pr_info("show_input:%d called\n", channel);		\
    return sprintf(buf, "%d\n", pcf8591_read_channel(data, channel));\
}									\
static DEVICE_ATTR(in##channel##_input, S_IRUGO,			\
		   show_in##channel##_input, NULL);

show_in_channel(0);
show_in_channel(1);
show_in_channel(2);
show_in_channel(3);

static ssize_t out0_output_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct pcf8591_data *data = i2c_get_clientdata(to_i2c_client(dev));
	return sprintf(buf, "%d\n", data->aout * 10);
}

static ssize_t out0_output_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	unsigned long val;
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8591_data *data = i2c_get_clientdata(client);
	int err;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	val /= 10;
	if (val > 255)
		return -EINVAL;

	data->aout = val;
	i2c_smbus_write_byte_data(client, data->control, data->aout);
	return count;
}

static DEVICE_ATTR_RW(out0_output);

static ssize_t out0_enable_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct pcf8591_data *data = i2c_get_clientdata(to_i2c_client(dev));
	return sprintf(buf, "%u\n", !(!(data->control & PCF8591_CONTROL_AOEF)));
}

static ssize_t out0_enable_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8591_data *data = i2c_get_clientdata(client);
	unsigned long val;
	int err;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	mutex_lock(&data->update_lock);
	if (val)
		data->control |= PCF8591_CONTROL_AOEF;
	else
		data->control &= ~PCF8591_CONTROL_AOEF;
	i2c_smbus_write_byte(client, data->control);
	mutex_unlock(&data->update_lock);
	return count;
}

static DEVICE_ATTR_RW(out0_enable);

static struct attribute *pcf8591_attributes[] = {
	&dev_attr_out0_enable.attr,
	&dev_attr_out0_output.attr,
	&dev_attr_in0_input.attr,
	&dev_attr_in1_input.attr,
	NULL
};

static const struct attribute_group pcf8591_attr_group = {
	.attrs = pcf8591_attributes,
};

static struct attribute *pcf8591_attributes_opt[] = {
	&dev_attr_in2_input.attr,
	&dev_attr_in3_input.attr,
	NULL
};

static const struct attribute_group pcf8591_attr_group_opt = {
	.attrs = pcf8591_attributes_opt,
};

/*
 * Real code
 */
static ssize_t pcf8591_ch_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct pcf8591_data *data = file->private_data;
    int channel = iminor(file_inode(file)) & 0x3;
    int value;
    char tmp[16];
    int len;

    value = pcf8591_read_channel(data, channel);
    len = snprintf(tmp, sizeof(tmp), "%d\n", value);

    return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static int pcf8591_ch_open(struct inode *inode, struct file *file)
{
    struct pcf8591_data *data = container_of(inode->i_cdev, struct pcf8591_data, cdev[iminor(inode) & 0x3]);
    file->private_data = data;
    return 0;
}

static const struct file_operations pcf8591_fops = {
    .owner = THIS_MODULE,
    .open = pcf8591_ch_open,
    .read = pcf8591_ch_read,
};

static int pcf8591_probe(struct i2c_client *client)
{
    struct pcf8591_data *data;
    int err;
    int i;

    pr_info("pcf8591_probe: called for device at 0x%02x\n", client->addr);

    data = devm_kzalloc(&client->dev, sizeof(struct pcf8591_data),
                GFP_KERNEL);
    if (!data) {
        pr_err("pcf8591_probe: memory allocation failed\n");
        return -ENOMEM;
    }
    data->client = client; // <-- add this line
    i2c_set_clientdata(client, data);
    mutex_init(&data->update_lock);

    pr_info("pcf8591_probe: initializing client\n");
    pcf8591_init_client(client);

    pr_info("pcf8591_probe: creating sysfs group\n");
    err = sysfs_create_group(&client->dev.kobj, &pcf8591_attr_group);
    if (err) {
        pr_err("pcf8591_probe: sysfs_create_group failed: %d\n", err);
        return err;
    }

    if (input_mode != 3) {
        pr_info("pcf8591_probe: creating in2_input sysfs file\n");
        err = device_create_file(&client->dev, &dev_attr_in2_input);
        if (err) {
            pr_err("pcf8591_probe: device_create_file in2_input failed: %d\n", err);
            goto exit_sysfs_remove;
        }
    }

    if (input_mode == 0) {
        pr_info("pcf8591_probe: creating in3_input sysfs file\n");
        err = device_create_file(&client->dev, &dev_attr_in3_input);
        if (err) {
            pr_err("pcf8591_probe: device_create_file in3_input failed: %d\n", err);
            goto exit_sysfs_remove;
        }
    }

    pr_info("pcf8591_probe: registering hwmon device\n");
    data->hwmon_dev = hwmon_device_register(&client->dev);
    if (IS_ERR(data->hwmon_dev)) {
        err = PTR_ERR(data->hwmon_dev);
        pr_err("pcf8591_probe: hwmon_device_register failed: %d\n", err);
        goto exit_sysfs_remove;
    }

    // Allocate device numbers
    pr_info("pcf8591_probe: allocating character device numbers\n");
    err = alloc_chrdev_region(&data->devt_base, 0, PCF8591_NUM_CHANNELS, "pcf8591");
    if (err)
        goto exit_sysfs_remove;

    data->class = class_create(THIS_MODULE, "pcf8591");
    if (IS_ERR(data->class)) {
        err = PTR_ERR(data->class);
        goto unregister_chrdev;
    }

    for (i = 0; i < PCF8591_NUM_CHANNELS; i++) {
        cdev_init(&data->cdev[i], &pcf8591_fops);
        data->cdev[i].owner = THIS_MODULE;
        err = cdev_add(&data->cdev[i], data->devt_base + i, 1);
        if (err)
            goto destroy_devices;
        pr_info("pcf8591_probe: creating device for channel pcf8591_ch%d\n", i);
        // Create device nodes for each channel
        device_create(data->class, &client->dev, data->devt_base + i, data, "pcf8591_ch%d", i);
    }

    pr_info("pcf8591_probe: probe successful\n");
    return 0;

destroy_devices:
    pr_err("pcf8591_probe: error occurred, cleaning up devices\n");
    for (i = 0; i < PCF8591_NUM_CHANNELS; i++) {
        device_destroy(data->class, data->devt_base + i);
        cdev_del(&data->cdev[i]);
    }
    class_destroy(data->class);
unregister_chrdev:
    pr_err("pcf8591_probe: error occurred, cleaning up character device numbers\n");
    unregister_chrdev_region(data->devt_base, PCF8591_NUM_CHANNELS);
exit_sysfs_remove:
    pr_err("pcf8591_probe: error occurred, cleaning up sysfs\n");
    sysfs_remove_group(&client->dev.kobj, &pcf8591_attr_group_opt);
    sysfs_remove_group(&client->dev.kobj, &pcf8591_attr_group);
    return err;
}

static int pcf8591_remove(struct i2c_client *client)
{
    struct pcf8591_data *data = i2c_get_clientdata(client);
    int i;
    pr_info("pcf8591_remove: called for device at 0x%02x\n", client->addr);

    hwmon_device_unregister(data->hwmon_dev);
    sysfs_remove_group(&client->dev.kobj, &pcf8591_attr_group_opt);
    sysfs_remove_group(&client->dev.kobj, &pcf8591_attr_group);
    for (i = 0; i < PCF8591_NUM_CHANNELS; i++) {
        device_destroy(data->class, data->devt_base + i);
        cdev_del(&data->cdev[i]);
    }
    class_destroy(data->class);
    unregister_chrdev_region(data->devt_base, PCF8591_NUM_CHANNELS);
    return 0;
}

static void pcf8591_init_client(struct i2c_client *client)
{
    struct pcf8591_data *data = i2c_get_clientdata(client);
    pr_info("pcf8591_init_client: initializing device at 0x%02x\n", client->addr);

    data->control = PCF8591_INIT_CONTROL;
    data->aout = PCF8591_INIT_AOUT;

    pr_info("pcf8591_init_client: writing control=0x%02x, aout=0x%02x\n", data->control, data->aout);
    i2c_smbus_write_byte_data(client, data->control, data->aout);

    pr_info("pcf8591_init_client: flushing first read\n");
    i2c_smbus_read_byte(client);
}

static int pcf8591_read_channel(struct pcf8591_data *data, int channel)
{
    u8 value;
    struct i2c_client *client = data->client;

    pr_debug("pcf8591_read_channel: reading channel %d\n", channel);

    mutex_lock(&data->update_lock);

    if ((data->control & PCF8591_CONTROL_AICH_MASK) != channel) {
        pr_debug("pcf8591_read_channel: switching to channel %d\n", channel);
        data->control = (data->control & ~PCF8591_CONTROL_AICH_MASK)
                  | channel;
        i2c_smbus_write_byte(client, data->control);

        pr_debug("pcf8591_read_channel: flushing after channel switch\n");
        i2c_smbus_read_byte(client);
    }
    value = i2c_smbus_read_byte(client);

    mutex_unlock(&data->update_lock);

    pr_debug("pcf8591_read_channel: raw value = %u\n", value);

    if ((channel == 2 && input_mode == 2) ||
        (channel != 3 && (input_mode == 1 || input_mode == 3))) {
        int signed_val = 10 * REG_TO_SIGNED(value);
        pr_debug("pcf8591_read_channel: signed value = %d\n", signed_val);
        return signed_val;
    } else {
        int unsigned_val = 10 * value;
        pr_debug("pcf8591_read_channel: unsigned value = %d\n", unsigned_val);
        return unsigned_val;
    }
}
// ...existing code...
// Dummy callback implementations with info print
static int pcf8591_dummy_detect(struct i2c_client *client, struct i2c_board_info *info) {
    pr_info("pcf8591_dummy_detect: called for device at 0x%02x\n", client->addr);
    return 0;
}


static const struct i2c_device_id pcf8591_id[] = {
	{ "pcf8591", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pcf8591_id);


static struct i2c_driver pcf8591_driver = {
	.driver = {
		.name	= "pcf8591",
	},
	.probe_new	= pcf8591_probe,
    .remove		= pcf8591_remove,
    .detect     = pcf8591_dummy_detect,
	.id_table	= pcf8591_id,
};

static int __init pcf8591_init(void)
{
    pr_info("pcf8591_init: called, input_mode=%d\n", input_mode);
    if (input_mode < 0 || input_mode > 3) {
        pr_warn("invalid input_mode (%d)\n", input_mode);
        input_mode = 0;
    }
    return i2c_add_driver(&pcf8591_driver);
}

static void __exit pcf8591_exit(void)
{
    pr_info("pcf8591_exit: called\n");
    i2c_del_driver(&pcf8591_driver);
}

MODULE_AUTHOR("Vijay <vijayp.work@gmail.com>");
MODULE_DESCRIPTION("PCF8591 driver");
MODULE_LICENSE("GPL");

module_init(pcf8591_init);
module_exit(pcf8591_exit);
