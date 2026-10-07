# SPDX-License-Identifier: GPL-2.0
OUTPUT ?= $(CURDIR)/build/
override OUTPUT := $(abspath $(OUTPUT))/
$(shell mkdir -p $(OUTPUT))

include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

TOOLSDIR := $(abspath ../../..)
BPFDIR := $(TOOLSDIR)/lib/bpf
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSDIR)/include/uapi
INCLUDE_DIR := $(OUTPUT)include
BPFOBJ := $(OUTPUT)libbpf/libbpf.a
DEFAULT_BPFTOOL := $(OUTPUT)sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)
CLANG ?= clang
msg = $(if $(Q),@printf '  %-8s %s\n' "$(1)" "$(3)";)

prefix ?= /usr/local
sbindir ?= $(prefix)/sbin
INSTALL ?= install

CFLAGS += -g -O2 -Wall -I$(INCLUDE_DIR) -I$(OUTPUT)
LDLIBS += -lelf -lz
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(SRCARCH) \
	      -I$(INCLUDE_DIR) -I$(APIDIR) -Wall

all: $(OUTPUT)svc-classify

$(OUTPUT)libbpf $(OUTPUT)bpftool:
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) | $(OUTPUT)libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(OUTPUT)libbpf/ \
		    DESTDIR=$(OUTPUT) prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(BPFOBJ) | $(OUTPUT)bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR) OUTPUT=$(OUTPUT)bpftool/ \
		    LIBBPF_OUTPUT=$(OUTPUT)libbpf/ LIBBPF_DESTDIR=$(OUTPUT) \
		    prefix= DESTDIR=$(OUTPUT) install-bin

$(OUTPUT)svc_classify.bpf.o: svc_classify.bpf.c $(BPFOBJ)
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)svc_classify.skel.h: $(OUTPUT)svc_classify.bpf.o $(BPFTOOL)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< name svc_classify > $@

$(OUTPUT)svc-classify: svc-classify.c $(OUTPUT)svc_classify.skel.h $(BPFOBJ)
	$(call msg,CC,,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) -o $@ $< $(BPFOBJ) $(LDLIBS)

install: $(OUTPUT)svc-classify
	$(Q)$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(Q)$(INSTALL) -m 755 $(OUTPUT)svc-classify $(DESTDIR)$(sbindir)/

clean:
	$(Q)rm -rf $(OUTPUT)

.PHONY: all install clean
.DELETE_ON_ERROR:
