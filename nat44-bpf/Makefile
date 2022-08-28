# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := nat44
BPF_TARGETS    := nat44_kern
BPF_SKEL_OBJ := nat44_kern.o

#LDLIBS     += -pthread
USER_LIBS = -lmnl
EXTRA_DEPS += nat44.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
