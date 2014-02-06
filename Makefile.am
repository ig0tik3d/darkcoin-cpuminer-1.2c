
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  x2/sha2.c x2/sha2-arm.S x2/sha2-x86.S x2/sha2-x64.S \
		  x2/scrypt.c x2/scrypt-arm.S x2/scrypt-x86.S x2/scrypt-x64.S \
		  x5/aes_helper.c x5/luffa_for_sse2.c x5/shavite.c x5/cubehash_sse2.c x5/vect128/nist.c x5/vect128/vector.c x5/echo.c \
		  xcoin.c
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

