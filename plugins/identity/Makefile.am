plugin_name = identity

plugin_LTLIBRARIES = \
	libidentity.la

libidentity_la_SOURCES = \
	gsd-identity-plugin.h            \
	gsd-identity-plugin.c            \
	gsd-alarm.h                      \
	gsd-alarm.c                      \
	gsd-identity.h                   \
	gsd-identity.c                   \
	gsd-kerberos-identity.c          \
	gsd-identity-manager.h           \
	gsd-identity-manager-private.h   \
	gsd-identity-manager.c           \
	gsd-kerberos-identity-manager.h  \
	gsd-kerberos-identity-manager.c

libidentity_la_CPPFLAGS = \
	-I$(top_srcdir)/gnome-settings-daemon \
	-DGNOME_SETTINGS_LOCALEDIR=\""$(datadir)/locale"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DGSD_SMARTCARD_MANAGER_NSS_DB=\""$(NSS_DATABASE)"\" \
	$(AM_CPPFLAGS)

libidentity_la_CFLAGS = \
	$(PLUGIN_CFLAGS)	\
	$(SETTINGS_PLUGIN_CFLAGS) \
	$(GNOME_CFLAGS)	\
	$(KRB5_CFLAGS)	\
	$(AM_CFLAGS)

libidentity_la_LDFLAGS = \
	$(GSD_PLUGIN_LDFLAGS)

libidentity_la_LIBADD = \
	$(SETTINGS_PLUGIN_LIBS)	\
	$(KRB5_LIBS)

noinst_PROGRAMS =				\
	test-identity

test_identity_SOURCES =			\
	gsd-alarm.h                      \
	gsd-alarm.c                      \
	gsd-identity.h                   \
	gsd-identity.c                   \
	gsd-kerberos-identity.c          \
	gsd-identity-manager.h           \
	gsd-identity-manager-private.h   \
	gsd-identity-manager.c           \
	gsd-kerberos-identity-manager.h  \
	gsd-kerberos-identity-manager.c  \
	test-identity.c			 \
	$(NULL)

test_identity_CPPFLAGS = \
	-I$(top_srcdir)/data/					\
	-I$(top_srcdir)/gnome-settings-daemon			\
	-I$(top_srcdir)/plugins/common				\
	-I$(top_srcdir)/plugins/media-keys/cut-n-paste		\
	-DBINDIR=\"$(bindir)\"					\
	-DPIXMAPDIR=\""$(pkgdatadir)"\"				\
	-DGTKBUILDERDIR=\""$(pkgdatadir)"\"			\
	-DGNOME_SETTINGS_LOCALEDIR=\""$(datadir)/locale"\"	\
	$(AM_CPPFLAGS)

test_identity_CFLAGS = \
	$(PLUGIN_CFLAGS)	\
	$(SETTINGS_PLUGIN_CFLAGS) \
	$(GNOME_CFLAGS)	\
	$(KRB5_CFLAGS)	\
	$(AM_CFLAGS)

test_identity_LDFLAGS = \
	$(GSD_PLUGIN_LDFLAGS)

test_identity_LDADD = \
	$(top_builddir)/gnome-settings-daemon/libgsd.la		\
	$(top_builddir)/plugins/common/libcommon.la			\
	$(top_builddir)/plugins/media-keys/cut-n-paste/libgvc.la	\
	$(SETTINGS_DAEMON_LIBS)			\
	$(SETTINGS_PLUGIN_LIBS)	\
	$(KRB5_LIBS)

@GSD_INTLTOOL_PLUGIN_RULE@

plugin_in_files = \
	identity.gnome-settings-plugin.in

plugin_DATA = $(plugin_in_files:.gnome-settings-plugin.in=.gnome-settings-plugin)

EXTRA_DIST = \
	$(plugin_in_files)

CLEANFILES = \
	$(plugin_DATA)

DISTCLEANFILES = \
	$(plugin_DATA)
