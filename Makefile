CC:=gcc
CFLAGS:=-Wall -Wextra -Wformat=2 -Wundef -Wpointer-arith -Wcast-align\
	    -Wstrict-prototypes -Wwrite-strings -Wswitch-default -Werror\
		-pedantic -std=c11 -g
DEPFLAGS:=-MMD -MP

SRC_DIRS:=test set1
SRC:=$(foreach dir, $(SRC_DIRS), $(wildcard $(dir)/*.c))

BDIR:=build
OBJ:=$(patsubst %.c, $(BDIR)/%.o, $(notdir $(SRC)))
DEP:=$(patsubst $(BDIR)/%.o, $(BDIR)/%.d, $(OBJ))

INCDIR:=include
INC:=$(wildcard $(INCDIR)/*.h)
INCFLAG:=-I$(INCDIR)

PROG=crypto

.PHONY: all
all: $(PROG)
$(PROG): $(OBJ)
	$(CC) $^ -o $(PROG)

.PHONY: clean
clean:
	rm $(BDIR)/*

# Maps all source files to object files
$(BDIR)/%.o: */%.c
	$(CC) -c $(INCFLAG) $(DEPFLAGS) $(CFLAGS) $< -o $@

# Prevents errors when changing header names
$(INC):

-include $(DEP)
