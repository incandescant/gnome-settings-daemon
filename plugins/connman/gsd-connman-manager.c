/*
 * Copyright (C) 2013 Intel, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Author: Joshua Lock <joshua.lock@intel.com>
 *
 */

#include "config.h"

#include <glib.h>
#include <gio/gio.h>

#include "gnome-settings-plugin.h"
#include "gsd-connman-manager.h"

#include "manager.h"
#include "service.h"

#define CONNMAN_DBUS_NAME               "net.connman"
#define CONNMAN_DBUS_PATH_MANAGER       "/"

#define SCHEMA_PROXY                    "org.gnome.system.proxy"
#define KEY_AUTO_URL                    "autoconfig-url"
#define KEY_MODE                        "mode"
#define KEY_HTTP                        "http"
#define KEY_HTTPS                       "https"
#define KEY_FTP                         "ftp"
#define KEY_SOCKS                       "socks"
#define KEY_HOST                        "host"
#define KEY_PORT                        "port"
#define KEY_IGNORE                      "ignore-hosts"

#define GSD_CONNMAN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GSD_TYPE_CONNMAN_MANAGER, GsdConnmanManagerPrivate))

struct GsdConnmanManagerPrivate {
        Manager         *manager_proxy;
        Service         *active_service;
        GSettings       *proxy_settings;
        gchar           **current_servers;
};

static void     gsd_connman_manager_class_init  (GsdConnmanManagerClass *klass);
static void     gsd_connman_manager_init        (GsdConnmanManager *connman_manager);

G_DEFINE_TYPE (GsdConnmanManager, gsd_connman_manager, G_TYPE_OBJECT)

static gpointer manager_object = NULL;

static void
connman_manager_clear_proxy_settings (GsdConnmanManager *manager)
{
        GSettings       *child;

        g_debug ("Resetting org.gnome.system.proxy and its children");

        g_settings_reset (manager->priv->proxy_settings, KEY_AUTO_URL);
        g_settings_reset (manager->priv->proxy_settings, KEY_MODE);
        g_settings_reset (manager->priv->proxy_settings, KEY_IGNORE);

        child = g_settings_get_child (manager->priv->proxy_settings, KEY_HTTP);
        g_settings_reset (child, KEY_HOST);
        g_settings_reset (child, KEY_PORT);
        g_object_unref (child);

        child = g_settings_get_child (manager->priv->proxy_settings, KEY_HTTPS);
        g_settings_reset (child, KEY_HOST);
        g_settings_reset (child, KEY_PORT);
        g_object_unref (child);

        child = g_settings_get_child (manager->priv->proxy_settings, KEY_FTP);
        g_settings_reset (child, KEY_HOST);
        g_settings_reset (child, KEY_PORT);
        g_object_unref (child);

        child = g_settings_get_child (manager->priv->proxy_settings, KEY_SOCKS);
        g_settings_reset (child, KEY_HOST);
        g_settings_reset (child, KEY_PORT);
        g_object_unref (child);
}

static void
gsd_connman_manager_set_auto_proxy (GsdConnmanManager   *manager,
                                    GVariant            *proxy_values)
{
        GVariant                *val;
        const gchar             *auto_url;

        val = g_variant_lookup_value (proxy_values, "URL",
                                      G_VARIANT_TYPE_STRING);
        auto_url = g_variant_get_string (val, 0);

        g_debug ("Setting proxy to auto: %s", auto_url);
        g_settings_set_string (manager->priv->proxy_settings,
                               KEY_MODE, "auto");
        g_settings_set_string (manager->priv->proxy_settings,
                               KEY_AUTO_URL, auto_url);

        g_variant_unref (val);
}

static void
parse_server_entry (const gchar *server_entry,
                    gchar       **protocol,
                    gchar       **server,
                    gint        *port)
{
        gchar   **host, **url;
        guint   host_part = 0;

        if (!server_entry)
                return;

        /* proto://server.example.com:911 */
        host = g_strsplit (server_entry, "://", -1);
        if (g_strv_length (host) < 1) {
                g_warning ("Invalid value set for manual proxy - ignoring.");
                goto host;
        } else if (g_strv_length (host) > 1 && host[1]) {
                /* Got protocol and domain[:port] */
                (*protocol) = g_strdup (host[0]);
                host_part = 1;
        } else {
                /* Got domain[:port]
                 *
                 * According to the GSettings schema for org.gnome.system.proxy
                 * SOCKS is used by default where a proxy for a specific
                 * protocol is not set, so default to settings socks when we
                 * get an entry from connman without a protocol set.
                 */
                (*protocol) = g_strdup ("socks");
        }

        url = g_strsplit (host[host_part], ":", -1);
        if (g_strv_length (url) > 1 && url[1]) {
                (*port) = g_ascii_strtoull (url[1], NULL, 0);
        } else {
                (*port) = 0;
        }
        (*server) = g_strdup (url[0]);

        g_strfreev (url);
host:
        g_strfreev (host);
}

static void
gsd_connman_manager_set_manual_proxy (GsdConnmanManager *manager,
                                      GVariant          *proxy_values)
{
        GVariant        *val;
        GSettings       *child_settings = NULL;
        const gchar     **servers;
        guint           i;
        gsize           num_servers;

        g_debug ("Setting proxy to manual");

        val = g_variant_lookup_value (proxy_values, "Servers",
                                      G_VARIANT_TYPE_STRING_ARRAY);
        if (val) {
                servers = g_variant_get_strv (val, &num_servers);

                for (i = 0; i < num_servers; i++) {
                        gchar   *protocol = NULL;
                        gchar   *server = NULL;
                        gint    port;

                        parse_server_entry (servers[i], &protocol, &server, &port);
                        if (!server)
                                continue;

                        if (g_strcmp0 (protocol, "http") == 0) {
                                child_settings = g_settings_get_child
                                        (manager->priv->proxy_settings,
                                         KEY_HTTP);
                        } else if (g_strcmp0 (protocol, "https") == 0) {
                                child_settings = g_settings_get_child
                                        (manager->priv->proxy_settings,
                                         KEY_HTTPS);
                        } else if (g_strcmp0 (protocol, "ftp") == 0) {
                                child_settings = g_settings_get_child
                                        (manager->priv->proxy_settings,
                                         KEY_FTP);
                        } else if (g_strcmp0 (protocol, "socks") == 0 ||
                                   g_strcmp0 (protocol, "socks4") == 0 ||
                                   g_strcmp0 (protocol, "socks5") == 0) {
                                child_settings = g_settings_get_child
                                        (manager->priv->proxy_settings,
                                         KEY_SOCKS);
                        }

                        if (port > 0 && child_settings) {
                                g_settings_set_string (child_settings, KEY_HOST,
                                                       server);
                                g_settings_set_int (child_settings, KEY_PORT,
                                                    port);
                        }

                        g_object_unref (child_settings);
                        g_free (protocol);
                        g_free (server);
                }

                g_clear_pointer (&manager->priv->current_servers, g_strfreev);
                manager->priv->current_servers = g_strdupv ((gchar **) servers);

                g_free (servers);
                g_variant_unref (val);
        }

        val = g_variant_lookup_value (proxy_values, "Excludes",
                                      G_VARIANT_TYPE_STRING_ARRAY);
        if (val) {
                /* The Excludes property of a ConnMan Service is of type as
                 * and the ignore-hosts GSetting expects an as .:. we can just
                 * set the exact values we retrieved.
                 */
                g_settings_set_value (manager->priv->proxy_settings,
                                      KEY_IGNORE, val);

                g_variant_unref (val);
        }

        g_settings_set_string (manager->priv->proxy_settings,
                               KEY_MODE, "manual");
}

static gboolean
gsd_connman_manager_settings_changed (GsdConnmanManager *manager,
                                      const gchar       *method,
                                      GVariant          *proxy_values)
{
        gboolean        has_changed = FALSE;
        gchar           *current_method;
        gchar           **current_excludes;
        const gchar     *new_method;

        current_method = g_settings_get_string (manager->priv->proxy_settings,
                                                KEY_MODE);

        /* GNOME uses 'none' where ConnMan uses 'direct' */
        if (g_strcmp0 (method, "direct") == 0)
                new_method = "none";
        else
                new_method = method;

        /* If the methods are different, settings have changed */
        if (g_strcmp0 (new_method, current_method) != 0) {
                g_debug ("Proxy method changed from %s to %s",
                         current_method, method);
                has_changed = TRUE;
        } else {
                GVariant        *val;

                /* Method was direct and is still direct = not changed */
                if (g_strcmp0 (method, "direct") == 0) {
                        /*g_debug ("Proxy method unchanged - direct");*/
                        has_changed = FALSE;
                /* Method is auto and URL different = changed */
                } else if (g_strcmp0 (method, "auto") == 0) {
                        const gchar     *auto_url;
                        gchar           *current_auto_url;

                        val = g_variant_lookup_value (proxy_values, "URL",
                                                      G_VARIANT_TYPE_STRING);
                        auto_url = g_variant_get_string (val, 0);
                        current_auto_url = g_settings_get_string (manager->priv->proxy_settings,
                                                                  KEY_AUTO_URL);

                        if (g_strcmp0 (auto_url, current_auto_url) != 0) {
                                g_debug ("Proxy auto url changed from %s to %s",
                                         current_auto_url, auto_url);
                                has_changed = TRUE;
                        }

                        g_variant_unref (val);

                /* Method is manual and any of the servers or excludes are different
                 * = changed
                 */
                } else if (g_strcmp0 (method, "manual") == 0) {
                        /* Compare Servers, as soon as mismatch return TRUE
                         */
                        val = g_variant_lookup_value (proxy_values, "Servers",
                                      G_VARIANT_TYPE_STRING_ARRAY);
                        if (val) {
                                const gchar **servers;
                                gsize num_servers;
                                gint i;

                                servers = g_variant_get_strv (val, &num_servers);

                                if (g_strv_length ((gchar **) servers) != g_strv_length (manager->priv->current_servers)) {
                                        g_debug ("Number of configured proxy servers has changed");
                                        has_changed = TRUE;
                                        goto servers_done;
                                }

                                for (i = 0; i < num_servers; i++) {
                                        if (g_strcmp0 (servers[i], manager->priv->current_servers[i]) != 0) {
                                                g_debug ("Configured servers have changed");
                                                has_changed = TRUE;
                                                break;
                                        }
                                }

                        servers_done:
                                g_free (servers);
                                g_variant_unref (val);
                        }

                        /* Compare Excludes, as soon as mismatch return TRUE
                         */
                        val = g_variant_lookup_value (proxy_values, "Excludes",
                                                      G_VARIANT_TYPE_STRING_ARRAY);
                        current_excludes = g_settings_get_strv (manager->priv->proxy_settings, KEY_IGNORE);
                        if (val) {
                                const gchar     **excludes;
                                gsize           num_excludes;
                                gint            i;

                                excludes = g_variant_get_strv (val, &num_excludes);

                                if (g_strv_length (current_excludes) != g_strv_length ((gchar **) excludes)) {
                                        g_debug ("Number of excludes has changed");
                                        has_changed = TRUE;
                                        goto excludes_done;
                                }

                                for (i = 0; i < num_excludes; i++) {
                                        if (g_strcmp0 (excludes[i], current_excludes[i]) != 0) {
                                                g_debug ("Configured excludes have changed");
                                                has_changed = TRUE;
                                                break;
                                        }
                                }
                        excludes_done:
                                g_strfreev (current_excludes);
                                g_free (excludes);
                                g_variant_unref (val);
                        }
                }
        }

        /*g_debug ("Proxy configuration has%s changed", has_changed ? "" : " not");*/

        g_free (current_method);

        return has_changed;
}

static void
gsd_connman_manager_set_proxy_values (GsdConnmanManager *manager,
                                      GVariant          *proxy_values)
{
        GVariant                *val;
        const gchar             *method;

        val = g_variant_lookup_value (proxy_values, "Method",
                                      G_VARIANT_TYPE_STRING);

        if (val) {
                method = g_variant_get_string (val, 0);

                if (!gsd_connman_manager_settings_changed (manager, method, proxy_values))
                        goto done;

                connman_manager_clear_proxy_settings (manager);

                if (method == NULL || g_strcmp0 (method, "direct") == 0) {
                        g_debug ("Setting proxy to direct");
                } else if (g_strcmp0 (method, "auto") == 0) {
                        gsd_connman_manager_set_auto_proxy (manager,
                                                            proxy_values);
                } else if (g_strcmp0 (method, "manual") == 0) {
                        gsd_connman_manager_set_manual_proxy (manager,
                                                              proxy_values);
                }
        done:
                g_variant_unref (val);
        }
}

static void
service_property_changed_cb (Service            *service,
                             const gchar        *property,
                             GVariant           *value,
                             gpointer           user_data)
{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);

        if (g_strcmp0 (property, "Proxy") == 0) {
                gsd_connman_manager_set_proxy_values (manager,
                                                      g_variant_get_variant (value));
        }
}

static void
service_proxy_ready_cb (GObject         *source_object,
                        GAsyncResult    *result,
                        gpointer        user_data)

{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);
        GError                  *error = NULL;

        manager->priv->active_service =
                service_proxy_new_for_bus_finish (result, &error);

        if (!manager->priv->active_service) {
                g_warning ("Could not get proxy for service: %s",
                           error->message);
                g_clear_error (&error);
                return;
        }

        g_signal_connect (manager->priv->active_service, "property-changed",
                          G_CALLBACK (service_property_changed_cb),
                          manager);
}

static void
handle_service (const gchar      *path,
                GVariant         *properties,
                gpointer         user_data)
{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);
        GVariant                *proxy;


        if (manager->priv->active_service) {
                g_signal_handlers_disconnect_by_func (manager->priv->active_service,
                                                      service_property_changed_cb,
                                                      manager);
                g_clear_object (&manager->priv->active_service);
        }

        /*
         * We maybe shouldn't pay attention to a Service which isn't connected,
         * i.e. doesn't have a State property of "online", but as we are arguably
         * overzealous about unsetting the we should be OK to set proxy settings
         * even if the service isn't connected and save ourselves some work.
         */
        service_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
                                   G_DBUS_PROXY_FLAGS_NONE,
                                   CONNMAN_DBUS_NAME,
                                   path,
                                   NULL,
                                   service_proxy_ready_cb,
                                   manager);

        proxy = g_variant_lookup_value (properties, "Proxy",
                                        G_VARIANT_TYPE_DICTIONARY);

        if (proxy)
                gsd_connman_manager_set_proxy_values (manager, proxy);

        g_variant_unref (proxy);
}

static void
manager_get_services_cb (GObject        *source,
                         GAsyncResult   *result,
                         gpointer       user_data)
{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);
        GVariant                *ret, *val, *obj_val, *props;
        GError                  *error = NULL;
        GVariantIter            obj_iter;
        const gchar             *path = NULL;
        gsize                   num_services;
        gboolean                service_found = FALSE;

        if (!manager_call_get_services_finish (manager->priv->manager_proxy,
                                               &ret, result, &error)) {
                g_warning ("manager_call_get_services () failed: %s",
                           error->message);
                g_clear_error (&error);
                return;
        }

        /* GetServices() returns (a(oa{sv})) */
        if (ret && g_variant_n_children (ret) > 0) {
                val = g_variant_get_child_value (ret, 0);
                if (!val) {
                        g_debug ("ConnMan didn't return any services");
                }
                // The first child is the first, service
                num_services = g_variant_iter_init (&obj_iter, val);
                if (num_services < 1) {
                        g_debug ("ConnMan didn't return any services");
                        goto out;
                }

                // object path
                obj_val = g_variant_iter_next_value (&obj_iter);
                if (!obj_val) {
                        g_warning ("The first Service returned by ConnMan is empty");
                        goto out;
                }
                path = g_variant_get_string (obj_val, NULL);

                // properties
                props = g_variant_iter_next_value (&obj_iter);
                if (props && path) {
                        handle_service (path, props, manager);
                        g_variant_unref (props);
                        service_found = TRUE;
                }

                g_variant_unref (obj_val);
        out:
                /* Clear proxy settings and saved state when there aren't any
                 * available services.
                 */
                if (!service_found) {
                        g_debug ("No service found, clearing proxy settings");
                        connman_manager_clear_proxy_settings (manager);
                }
                g_variant_unref (val);
        }
}

static void
manager_services_changed_cb (Manager            *manager_proxy,
                             GVariant           *changed,
                             const gchar *const *removed,
                             gpointer           user_data)
{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);

        /* We have to call the GetServices () method to ensure all properties
         * are populated and up-to-date.
         */
        manager_call_get_services (manager->priv->manager_proxy, NULL,
                                   manager_get_services_cb, manager);
}

static void
manager_proxy_ready_cb (GObject         *source_object,
                        GAsyncResult    *result,
                        gpointer        user_data)
{
        GsdConnmanManager       *manager = GSD_CONNMAN_MANAGER (user_data);
        GError                  *error = NULL;

        manager->priv->manager_proxy = manager_proxy_new_for_bus_finish (result,
                                                                         &error);
        if (manager->priv->manager_proxy == NULL) {
                g_warning ("Could not connect to ConnMan: %s",
                           error->message);
                g_clear_error (&error);
                return;
        }

        manager_call_get_services (manager->priv->manager_proxy, NULL,
                                   manager_get_services_cb, manager);

        g_signal_connect (manager->priv->manager_proxy,
                          "services-changed",
                          G_CALLBACK (manager_services_changed_cb),
                          manager);
}

gboolean
gsd_connman_manager_start (GsdConnmanManager *manager,
                           GError            **error)
{
        g_debug ("Starting connman manager");

        manager_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
                                   G_DBUS_PROXY_FLAGS_NONE,
                                   CONNMAN_DBUS_NAME,
                                   CONNMAN_DBUS_PATH_MANAGER,
                                   NULL,
                                   manager_proxy_ready_cb,
                                   manager);

        return TRUE;
}

void
gsd_connman_manager_stop (GsdConnmanManager *manager)
{
        g_debug ("Stopping connman manager");

        connman_manager_clear_proxy_settings (manager);

        g_clear_object (&manager->priv->manager_proxy);
        g_clear_object (&manager->priv->active_service);
        g_clear_pointer (&manager->priv->current_servers, g_strfreev);
}

static void
gsd_connman_manager_finalize (GObject *object)
{
        GsdConnmanManager *manager;

        g_return_if_fail (object != NULL);
        g_return_if_fail (GSD_IS_CONNMAN_MANAGER (object));

        manager = GSD_CONNMAN_MANAGER (object);

        g_return_if_fail (manager->priv != NULL);

        g_clear_object (&manager->priv->proxy_settings);

        G_OBJECT_CLASS (gsd_connman_manager_parent_class)->finalize (object);
}

static void
gsd_connman_manager_class_init (GsdConnmanManagerClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = gsd_connman_manager_finalize;

        g_type_class_add_private (klass, sizeof (GsdConnmanManagerPrivate));
}

static void
gsd_connman_manager_init (GsdConnmanManager *manager)
{
        manager->priv = GSD_CONNMAN_MANAGER_GET_PRIVATE (manager);

        manager->priv->active_service = NULL;
        manager->priv->proxy_settings = g_settings_new (SCHEMA_PROXY);
        manager->priv->current_servers = NULL;
}

GsdConnmanManager *
gsd_connman_manager_new (void)
{
        if (manager_object != NULL) {
                g_object_ref (manager_object);
        } else {
                manager_object = g_object_new (GSD_TYPE_CONNMAN_MANAGER, NULL);
                g_object_add_weak_pointer (manager_object,
                                           (gpointer *) &manager_object);
        }

        return GSD_CONNMAN_MANAGER (manager_object);
}

