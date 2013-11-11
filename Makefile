
# 
# compile tool
# compile param
# link    param
# exe file
# *.o file
# compile command 
# link command
#

#CC = mips64-octeon-linux-gnu-gcc
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpcap #-lpthread 
TARGET1 = packet_chk
TARGET2 = packet_mdf
OBJS1 = chk_pckt.o #pcap.o
OBJS2 = packet_mdf.o pcap.o
COMPILE  = $(CC) $(CFLAGS) -MD -c -o $@ $<
LINK = $(CC) $^ $(LDFLAGS) -o $@

ALL:$(TARGET1) $(TARGET2)

$(TARGET1):$(OBJS1)
	$(LINK)

$(TARGET2):$(OBJS2)
	$(LINK)

%.o:%.c
	$(COMPILE)

-include $(OBJS:.o=.d)

clean:
	rm -f $(OBJS) *~ *.d *.o $(TARGET1) $(TARGET2)
