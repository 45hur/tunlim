tunlim_CFLAGS := -fvisibility=hidden -fPIC 
tunlim_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
tunlim_SOURCES := \
	modules/tunlim/cache_domains.c \
	modules/tunlim/tunlim.c \
	modules/tunlim/log.c \
	modules/tunlim/program.c
tunlim_DEPEND := $(libkres)
tunlim_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) 
$(call make_c_module,tunlim)
