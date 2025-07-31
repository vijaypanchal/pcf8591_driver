// pcf8591_read_all.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define NUM_CHANNELS 4

int main(int argc, char *argv[])
{
    int delay_ms = 1000; // default 1000ms
    if (argc > 1)
        delay_ms = atoi(argv[1]);

    char devname[32];
    int fds[NUM_CHANNELS] = {-1,};
    int i;

    printf("Reading all channels every %d ms. Press Ctrl+C to stop.\n", delay_ms);

    while (1) {
        for (i = 0; i < NUM_CHANNELS; i++) {
            snprintf(devname, sizeof(devname), "/dev/pcf8591_ch%d", i);
            fds[i] = open(devname, O_RDONLY);
            if (fds[i] < 0) {
                printf("Error opening device %s:%d", devname, errno);
                continue;
            }
            char buf[32];
            memset(buf, 0, sizeof(buf));
            int n = read(fds[i], buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("Channel %d: %s", i, buf);
            } else {
                printf("Channel %s: read error %d\n", devname, errno);
            }
            close(fds[i]);
            fds[i] = -1; // Reset file descriptor
        }
        printf("----\n");
        usleep(delay_ms * 1000);
    }       

    return 0;
}
