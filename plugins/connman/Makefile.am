plugin_name = connman

dbus_built_sources =	manager.c manager.h	\
			service.c service.h

manager.c: manager.h
manager.h: Makefile.am manager-interface.xml
	gdbus-codegen					\
		--interface-prefix net.connman.		\
		--generate-c-code manager		\
		$(srcdir)/manager-interface.xml

service.c: service.h
service.h: Makefile.am service-interface.xml
	gdbus-codegen					\
		--interface-prefix net.connman.		\
		--generate-c-code service		\
		$(srcdir)/service-interface.xml

plugin_LTLIBRARIES = \
	libconnman.la

libconnman_la_SOURCES =			\
	$(dbus_built_sources)		\
	gsd-connman-manager.c		\
	gsd-connman-manager.h		\
	gsd-connman-plugin.c

libconnman_la_CPPFLAGS = \
	-I$(top_srcdir)/gnome-settings-daemon		\
	-DGNOME_SETTINGS_LOCALEDIR=\""$(datadir)/locale"\" \
	$(AM_CPPFLAGS)

libconnman_la_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	$(SETTINGS_PLUGIN_CFLAGS) \
	$(AM_CFLAGS)

libconnman_la_LDFLAGS = \
	$(GSD_PLUGIN_LDFLAGS)

libconnman_la_LIBADD = \
	$(SETTINGS_PLUGIN_LIBS)

plugin_in_files = \
	connman.gnome-settings-plugin.in

plugin_DATA = $(plugin_in_files:.gnome-settings-plugin.in=.gnome-settings-plugin)

EXTRA_DIST = \
	$(plugin_in_files)	\
	manager-interface.xml	\
	service-interface.xml

CLEANFILES = \
	$(plugin_DATA)  \
	$(dbus_built_sources)

DISTCLEANFILES = \
	$(plugin_DATA)

@GSD_INTLTOOL_PLUGIN_RULE@

