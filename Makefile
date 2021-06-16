CC ?= gcc

SRCDIR ?= src
GENDIR ?= gen
OBJDIR ?= obj

LIBS = -lm
INCS = -Isrc/ -Igen/ -I.

CFG = -std=gnu11 -fms-extensions -flto

CFLAGS ?= -O3 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall

SOURCES = $(shell find $(SRCDIR) -name "*.c")
DEPS_C = $(OBJS_C:%.o=%.d)
OBJS_C = $(SOURCES:%.c=$(OBJDIR)/%.o)

FFGEN_SOURCES = $(wildcard ffgen/*.c)
FFGEN_DEPS_C = $(FFGEN_OBJS_C:%.o=%.d)
FFGEN_OBJS_C = $(FFGEN_SOURCES:%.c=$(OBJDIR)/%.o)

.DEFAULT_GOAL := opz

print-%  : ; @echo $* = $($*)

src/.clang_complete: Makefile
	@(for i in $(filter-out -O% -DNDEBUG, $(CFG) $(CPPFLAGS) $(CFLAGS) $(INCS)); do echo "$$i"; done) > $@

opz: $(OBJS_C)
	$(CC) $(CFG) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS_C) $(LIBS)

$(OBJDIR)/ffgen/ffgen: $(FFGEN_OBJS_C)
	$(CC) $(CFG) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o $@ $^

$(GENDIR)/ffgen/opz.h: $(SRCDIR)/opz.ff $(OBJDIR)/ffgen/ffgen
	@mkdir -p $(dir $@)
	$(OBJDIR)/ffgen/ffgen <$< >$@

-include $(DEPS_C) $(FFGEN_DEPS_C)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFG) $(CPPFLAGS) $(CFLAGS) $(INCS) -MMD -o $@ -c $<

clean:
	@rm -rf $(OBJDIR)
	@rm -f opz .clang_complete

.PHONY: version
version:
	@echo "$(COMPTON_VERSION)"
