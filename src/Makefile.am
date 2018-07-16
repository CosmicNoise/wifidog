#
# $Id$
#

bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-DSYSCONFDIR='"$(sysconfdir)"' 
wifidog_LDADD = 

wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw.c \
	gateway.c \
	centralserver.c \
	auth.c \
	client_list.c \
	util.c \
	wdctl_thread.c \
	safe.c  \
	queue.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw.h \
	gateway.h \
	centralserver.h \
	auth.h \
	client_list.h \
	util.h \
	wdctl_thread.h \
	wdctl.h \
	safe.h \
	queue.h

wdctl_SOURCES = wdctl.c
