ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = jae 
                               jae_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       jae_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               jae_SOURCES = jae.c \
						       credits.c \
						       help.c \
                                                       util.c \
						       util-time.c \
						       util-hash.c \
						       util-base64.c \
						       util-strlcpy.c \
						       util-strlcat.c \
						       util-tcpip.c \
						       util-file.c \
						       lockfile.c \
						       signal-handler.c \
						       batch.c \
						       processor.c \
                                                       config-yaml.c \
						       classifications.c \
						       rules.c \
						       output.c \
						       after.c \
						       json-output-builder.c \
					               parsers/json.c \
						       parsers/search.c \
						       parsers/pcre.c \
						       parsers/ip.c \
						       parsers/normalize.c \
                                                       parsers/strstr-asm/strstr-hook.c \
                                                       parsers/strstr-asm/strstr_sse2.S \
                                                       parsers/strstr-asm/strstr_sse4_2.S \
						       input-plugins/named-pipe.c \
						       output-plugins/file.c \
						       processors/engine.c \
						       processors/bluedot.c

                                                       install-data-local:

