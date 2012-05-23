/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 */

#include "config.h"

#include <glib/gi18n-lib.h>
#include <gmodule.h>

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "gnome-settings-plugin.h"
#include "gsd-identity-plugin.h"
#include "gsd-identity-manager.h"
#include "gsd-kerberos-identity-manager.h"

struct GsdIdentityPluginPrivate {
        GsdIdentityManager *identity_manager;

        guint32             is_active : 1;
};

#define GSD_IDENTITY_PLUGIN_GET_PRIVATE(object) (G_TYPE_INSTANCE_GET_PRIVATE ((object), GSD_TYPE_IDENTITY_PLUGIN, GsdIdentityPluginPrivate))

GNOME_SETTINGS_PLUGIN_REGISTER (GsdIdentityPlugin, gsd_identity_plugin);

static void
gsd_identity_plugin_init (GsdIdentityPlugin *self)
{
        self->priv = GSD_IDENTITY_PLUGIN_GET_PRIVATE (self);

        g_debug ("GsdIdentityPlugin initializing");

        self->priv->identity_manager = gsd_kerberos_identity_manager_new ();
}

static void
gsd_identity_plugin_finalize (GObject *object)
{
        GsdIdentityPlugin *self;

        g_return_if_fail (object != NULL);
        g_return_if_fail (GSD_IS_IDENTITY_PLUGIN (object));

        g_debug ("GsdIdentityPlugin finalizing");

        self = GSD_IDENTITY_PLUGIN (object);

        g_return_if_fail (self->priv != NULL);

        if (self->priv->identity_manager != NULL) {
                g_object_unref (self->priv->identity_manager);
        }

        G_OBJECT_CLASS (gsd_identity_plugin_parent_class)->finalize (object);
}

static void
on_identity_added (GsdIdentityManager *manager,
                   GsdIdentity        *identity,
                   GsdIdentityPlugin  *self)
{
}

static void
on_identity_renewed (GsdIdentityManager *manager,
                     GsdIdentity        *identity,
                     GsdIdentityPlugin  *self)
{
}

static void
on_identity_removed (GsdIdentityManager *manager,
                     GsdIdentity        *identity,
                     GsdIdentityPlugin  *self)
{
}

static void
on_identity_expired (GsdIdentityManager *manager,
                     GsdIdentity        *identity,
                     GsdIdentityPlugin  *self)
{
}

static void
on_identity_renamed (GsdIdentityManager *manager,
                     GsdIdentity        *identity,
                     GsdIdentityPlugin  *self)
{
}

static void
on_identities_listed (GsdIdentityManager *manager,
                      GAsyncResult       *result,
                      GsdIdentityPlugin  *self)
{
        GList *identities, *node;
        GError *error;

        g_signal_connect (manager,
                          "identity-added",
                          G_CALLBACK (on_identity_added),
                          self);

        g_signal_connect (manager,
                          "identity-removed",
                          G_CALLBACK (on_identity_removed),
                          self);

        g_signal_connect (manager,
                          "identity-expired",
                          G_CALLBACK (on_identity_expired),
                          self);

        g_signal_connect (manager,
                          "identity-renewed",
                          G_CALLBACK (on_identity_renewed),
                          self);
        g_signal_connect (manager,
                          "identity-renamed",
                          G_CALLBACK (on_identity_renamed),
                          self);

        error = NULL;
        identities = gsd_identity_manager_list_identities_finish (manager,
                                                                  result,
                                                                  &error);

        if (identities == NULL) {
                if (error != NULL) {
                        g_warning ("GsdUserPanel: Could not list identities: %s",
                                   error->message);
                        g_error_free (error);
                }

                return;
        }

        node = identities;
        while (node != NULL) {
                GsdIdentity *identity = GSD_IDENTITY (node->data);

                if (gsd_identity_is_signed_in (identity)) {
                }

                node = node->next;
        }
}

static void
impl_activate (GnomeSettingsPlugin *plugin)
{
        GsdIdentityPlugin *self = GSD_IDENTITY_PLUGIN (plugin);

        if (self->priv->is_active) {
                g_debug ("GsdIdentityPlugin Not activating identity plugin, because it's "
                         "already active");
                return;
        }

        g_debug ("GsdIdentityPlugin Activating identity plugin");

        gsd_identity_manager_list_identities (self->priv->identity_manager,
                                              NULL,
                                              (GAsyncReadyCallback)
                                              on_identities_listed,
                                              self);

        self->priv->is_active = TRUE;
}

static void
impl_deactivate (GnomeSettingsPlugin *plugin)
{
        GsdIdentityPlugin *self = GSD_IDENTITY_PLUGIN (plugin);

        if (!self->priv->is_active) {
                g_debug ("GsdIdentityPlugin Not deactivating identity plugin, "
                         "because it's already inactive");
                return;
        }

        g_debug ("GsdIdentityPlugin Deactivating identity plugin");

        self->priv->is_active = FALSE;
}

static void
gsd_identity_plugin_class_init (GsdIdentityPluginClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);
        GnomeSettingsPluginClass *plugin_class = GNOME_SETTINGS_PLUGIN_CLASS (klass);

        object_class->finalize = gsd_identity_plugin_finalize;

        plugin_class->activate = impl_activate;
        plugin_class->deactivate = impl_deactivate;

        g_type_class_add_private (klass, sizeof (GsdIdentityPluginPrivate));
}

static void
gsd_identity_plugin_class_finalize (GsdIdentityPluginClass *klass)
{
}
