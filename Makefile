DESCRIPTION = X Tables Configurator
URL = https://github.com/ikle/xt

LIBNAME	= ikle-xt
LIBVER	= 0
LIBREV	= 0.1

DEPENDS	= ikle-data

LDFLAGS	+= -Wl,--as-needed

include make-core.mk
