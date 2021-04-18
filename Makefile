#   Building Open Source Network Security Tools
#   Sift Makefile - Vulnerability Scanning Technique sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

#CONFIGURE_ARGS+=        --disable-pcap
SFLAG= -w
CC		= gcc -g
CFLAGS		= -O2 -Wall
#LDFLAGS        = -L/path/to/libpcap/and/libnet/library/if/needed
OBJECTS         = sift.o
#INCS           = -I/path/to/libpcap/and/libnet/headers/if/needed
LIBS		= -lpcap -lnet

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: sift

sift: $(OBJECTS)
	$(CC) $(SFLAG) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* sift

# EOF
