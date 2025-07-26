#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DRIVER_NAME "pcf8591"       // Driver name
#define ADC_DEVICES 4               // Number of ADC channels
#define DAC_MINOR ADC_DEVICES       // Minor number for DAC device

// Macro for debug logging (can be enabled via Makefile)
#define DEBUG
#ifdef DEBUG
#define pcf_debug(dev, fmt, ...) dev_dbg(dev, "DEBUG: " fmt, ##__VA_ARGS__)
#else
#define pcf_debug(dev, fmt, ...)
#endif

// Driver private data structure
struct pcf8591_data {
    struct i2c_client *client;      // I2C client structure
    struct cdev adc_cdev[ADC_DEVICES]; // Character devices for ADC channels
    struct cdev dac_cdev;           // Character device for DAC
    dev_t devt;                     // Device number
    struct class *class;            // Device class
};

/* ADC read operation
 * Reads the specified ADC channel and returns the value to userspace
 */
static int pcf8591_adc_read(struct file *file, char __user *buf, 
                           size_t count, loff_t *ppos)
{
    struct pcf8591_data *data = file->private_data;
    struct i2c_client *client = data->client;
    u8 channel = iminor(file_inode(file)); // Get channel from minor number
    u8 txbuf = 0x40 | (channel & 0x03);   // Control byte: Enable DAC + channel
    u8 rxbuf[2];                 // Receive buffer (dummy + actual value)
    struct i2c_msg msgs[2] = {   // I2C transaction messages
        {                        // Write message: control byte
            .addr = client->addr,
            .flags = 0,
            .len = 1,
            .buf = &txbuf,
        },
        {                        // Read message: 2 bytes (dummy + actual)
            .addr = client->addr,
            .flags = I2C_M_RD,
            .len = 2,
            .buf = rxbuf,
        }
    };
    int ret;

    pcf_debug(&client->dev, "Reading ADC channel %d\n", channel);

    // Perform I2C transfer
    ret = i2c_transfer(client->adapter, msgs, 2);
    if (ret < 0) {
        dev_err(&client->dev, "I2C transfer failed: %d\n", ret);
        return ret;
    }
    if (ret != 2) {
        dev_err(&client->dev, "Incomplete I2C transfer: %d/2\n", ret);
        return -EIO;
    }

    pcf_debug(&client->dev, "ADC%d raw value: 0x%02x\n", channel, rxbuf[1]);

    // Copy result to userspace
    if (copy_to_user(buf, &rxbuf[1], 1)) {
        dev_err(&client->dev, "Failed to copy to userspace\n");
        return -EFAULT;
    }

    return 1; // Return 1 byte read
}

/* ADC device open operation
 * Associates private data with file instance
 */
static int pcf8591_adc_open(struct inode *inode, struct file *file)
{
    struct pcf8591_data *data = container_of(inode->i_cdev, 
                                           struct pcf8591_data, 
                                           adc_cdev[iminor(inode)]);
    file->private_data = data;
    pcf_debug(&data->client->dev, "ADC channel %d opened\n", iminor(inode));
    return 0;
}

// File operations for ADC devices
static const struct file_operations adc_fops = {
    .owner = THIS_MODULE,
    .open = pcf8591_adc_open,
    .read = pcf8591_adc_read,
};

/* DAC write operation
 * Writes a value to the DAC output
 */
static ssize_t pcf8591_dac_write(struct file *file, const char __user *buf, 
                                size_t count, loff_t *ppos)
{
    struct pcf8591_data *data = file->private_data;
    u8 val;                      // Value to write (0-255)
    u8 txbuf[2] = {0x40, 0};     // Control byte + DAC value

    // Get value from userspace
    if (copy_from_user(&val, buf, 1)) {
        dev_err(&data->client->dev, "Failed to copy from userspace\n");
        return -EFAULT;
    }

    txbuf[1] = val;
    pcf_debug(&data->client->dev, "Setting DAC output: 0x%02x\n", val);

    // Send to I2C device
    if (i2c_master_send(data->client, txbuf, 2) != 2) {
        dev_err(&data->client->dev, "DAC write failed\n");
        return -EIO;
    }

    return 1; // Return 1 byte written
}

/* DAC device open operation
 * Associates private data with file instance
 */
static int pcf8591_dac_open(struct inode *inode, struct file *file)
{
    struct pcf8591_data *data = container_of(inode->i_cdev, 
                                           struct pcf8591_data, 
                                           dac_cdev);
    file->private_data = data;
    pcf_debug(&data->client->dev, "DAC device opened\n");
    return 0;
}

// File operations for DAC device
static const struct file_operations dac_fops = {
    .owner = THIS_MODULE,
    .open = pcf8591_dac_open,
    .write = pcf8591_dac_write,
};

/* Driver probe function
 * Initializes the driver when device is detected
 */
static int pcf8591_probe(struct i2c_client *client, 
                        const struct i2c_device_id *id)
{
    struct pcf8591_data *data;
    int i, ret;
    u8 init_data[2] = {0x40, 0x00};
    dev_info(&client->dev, "Probing PCF8591 at address 0x%02x\n", client->addr);

    // Allocate driver private data
    data = devm_kzalloc(&client->dev, sizeof(*data), GFP_KERNEL);
    if (!data) {
        dev_err(&client->dev, "Failed to allocate memory\n");
        return -ENOMEM;
    }

    data->client = client;
    i2c_set_clientdata(client, data);

    // Allocate device numbers (1 major + 5 minors: 4 ADC + 1 DAC)
    ret = alloc_chrdev_region(&data->devt, 0, ADC_DEVICES + 1, DRIVER_NAME);
    if (ret < 0) {
        dev_err(&client->dev, "Failed to allocate char device region\n");
        return ret;
    }
    dev_info(&client->dev, "Allocated major %d\n", MAJOR(data->devt));

    // Create device class
    data->class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(data->class)) {
        ret = PTR_ERR(data->class);
        dev_err(&client->dev, "Failed to create device class\n");
        goto err_class;
    }

    // Initialize and register ADC channel devices
    for (i = 0; i < ADC_DEVICES; i++) {
        cdev_init(&data->adc_cdev[i], &adc_fops);
        data->adc_cdev[i].owner = THIS_MODULE;
        
        ret = cdev_add(&data->adc_cdev[i], data->devt + i, 1);
        if (ret) {
            dev_err(&client->dev, "Failed to add ADC%d cdev\n", i);
            goto err_cdev;
        }
        
        device_create(data->class, NULL, data->devt + i, NULL, "pcf8591_adc%d", i);
        pcf_debug(&client->dev, "Created device node for ADC%d\n", i);
    }

    // Initialize and register DAC device
    cdev_init(&data->dac_cdev, &dac_fops);
    data->dac_cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&data->dac_cdev, data->devt + DAC_MINOR, 1);
    if (ret) {
        dev_err(&client->dev, "Failed to add DAC cdev\n");
        goto err_cdev;
    }
    
    device_create(data->class, NULL, data->devt + DAC_MINOR, NULL, "pcf8591_dac");
    pcf_debug(&client->dev, "Created device node for DAC\n");

    // Initialize DAC to 0V (mid-range)
    //u8 init_data[2] = {0x40, 0x00};
    if (i2c_master_send(client, init_data, 2) != 2) {
        dev_warn(&client->dev, "DAC initialization failed\n");
    } else {
        dev_info(&client->dev, "DAC initialized to 0V\n");
    }

    dev_info(&client->dev, "PCF8591 driver loaded successfully\n");
    return 0;

// Error handling
err_cdev:
    for (i = 0; i < ADC_DEVICES; i++) {
        if (data->adc_cdev[i].ops) {
            device_destroy(data->class, data->devt + i);
            cdev_del(&data->adc_cdev[i]);
        }
    }
    class_destroy(data->class);
err_class:
    unregister_chrdev_region(data->devt, ADC_DEVICES + 1);
    return ret;
}

/* Driver remove function
 * Cleanup resources when device is removed
 */
static int pcf8591_remove(struct i2c_client *client)
{
    struct pcf8591_data *data = i2c_get_clientdata(client);
    int i;

    dev_info(&client->dev, "Removing PCF8591 driver\n");

    // Cleanup ADC devices
    for (i = 0; i < ADC_DEVICES; i++) {
        device_destroy(data->class, data->devt + i);
        cdev_del(&data->adc_cdev[i]);
        pcf_debug(&client->dev, "Removed ADC%d device\n", i);
    }

    // Cleanup DAC device
    device_destroy(data->class, data->devt + DAC_MINOR);
    cdev_del(&data->dac_cdev);
    pcf_debug(&client->dev, "Removed DAC device\n");

    // Destroy class and unregister device numbers
    class_destroy(data->class);
    unregister_chrdev_region(data->devt, ADC_DEVICES + 1);
    return 0;
}

/* I2C device ID table */
static const struct i2c_device_id pcf8591_id[] = {
    { "pcf8591", 0 },  // Compatible with devices named "pcf8591"
    { }
};
MODULE_DEVICE_TABLE(i2c, pcf8591_id);

/* Device tree match table */
static const struct of_device_id pcf8591_of_match[] = {
    { .compatible = "nxp,pcf8591" },  // Compatible with device tree nodes
    { }
};
MODULE_DEVICE_TABLE(of, pcf8591_of_match);

/* I2C driver structure */
static struct i2c_driver pcf8591_driver = {
    .driver = {
        .name = DRIVER_NAME,
        .of_match_table = pcf8591_of_match,
    },
    .probe = pcf8591_probe,
    .remove = pcf8591_remove,
    .id_table = pcf8591_id,
};

module_i2c_driver(pcf8591_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Enhanced PCF8591 ADC/DAC Driver with Logging");
MODULE_VERSION("1.1");
