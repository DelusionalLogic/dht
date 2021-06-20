CC ?= gcc

SRCDIR ?= src
TSTDIR ?= test
GENDIR ?= gen
OBJDIR ?= obj

LIBS = -lm
INCS = -Isrc/ -Igen/ -I.

CFLAGS ?= -O3 -D_FORTIFY_SOURCE=2 -Wall
# add all the required Cflags
CFLAGS += -std=gnu11 -fms-extensions -flto

APP_MAIN_SOURCES = src/main.c
APP_SOURCES = $(filter-out $(APP_MAIN_SOURCES),$(shell find $(SRCDIR) -name "*.c"))
APP_OBJS = $(APP_SOURCES:%.c=$(OBJDIR)/%.o)
APP_MAIN_OBJS = $(APP_MAIN_SOURCES:%.c=$(OBJDIR)/%.o)
APP_DEPS = $(APP_OBJS:%.o=%.d)
APP_MAIN_DEPS = $(APP_MAIN_OBJS:%.o=%.d)

TEST_LIB_SOURCES = thirdparty/Unity/src/unity.c
TEST_LIB_OBJS = $(TEST_LIB_SOURCES:%.c=$(OBJDIR)/%.o)
TEST_LIB_DEPS = $(TEST_LIB_SOURCES:%.c=%.d)
TEST_LIB_INCS = -Ithirdparty/Unity/src

TEST_SOURCES = $(shell find $(TSTDIR) -name "*.c")
TEST_EXES = $(TEST_SOURCES:%.c=$(OBJDIR)/%)
TEST_DEPS = $(TEST_SOURCES:%.c=%.d)

print-%  : ; @echo $* = $($*)

-include $(APP_DEPS) $(TEST_LIB_DEPS) $(TEST_DEPS)

# We don't really need to run the tests for bear to record them
compile_commands.json: clean Makefile $(APP_SOURCES) $(TEST_LIB_SOURCES) $(TEST_SOURCES)
	@rm -f "$@"
	bear -- make $(TEST_EXES) dht

dht: $(APP_MAIN_OBJS) $(APP_OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(APP_MAIN_OBJS) $(APP_OBJS) $(LIBS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCS) -MMD -o $@ -c $<

clean:
	@rm -rf $(OBJDIR)
	@rm -f dht

.PHONY: version
version:
	@echo "$(COMPTON_VERSION)"

# Unit tests!

# Run all tests
.PHONY: test
test: $(TEST_EXES)
	$(foreach test,$(TEST_EXES),./$(test);)

$(OBJDIR)/test/%: $(APP_OBJS) $(TEST_LIB_OBJS) $(OBJDIR)/test/%.o $(OBJDIR)/test/%.runner.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/test/%.runner.c: test/%.c
	@mkdir -p $(dir $@)
	ruby thirdparty/Unity/auto/generate_test_runner.rb $< $@

# Test code needs test includes
$(OBJDIR)/test/%.o: test/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_LIB_INCS) $(INCS) -MMD -o $@ -c $<

# Generated test sources are located under obj 
$(OBJDIR)/test/%.o: $(OBJDIR)/test/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_LIB_INCS) $(INCS) -MMD -o $@ -c $<

.DEFAULT_GOAL := all
all: test dht
