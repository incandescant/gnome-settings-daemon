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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Ray Strode
 */

#include "config.h"

#include "gsd-identity.h"
#include "gsd-kerberos-identity.h"
#include "gsd-alarm.h"

#include <string.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

struct _GsdKerberosIdentityPrivate
{
        krb5_context    kerberos_context;
        krb5_ccache     credentials_cache;

        char           *identifier;
        char           *cached_principal_name;
        char           *cached_realm_name;
        GsdAlarm       *expiration_alarm;
        GCancellable   *expiration_alarm_cancellable;
        krb5_timestamp  expiration_time;

        GsdAlarm       *renewal_alarm;
        GCancellable   *renewal_alarm_cancellable;

        GRecMutex       updates_lock;
};

typedef enum
{
        VERIFICATION_LEVEL_UNVERIFIED,
        VERIFICATION_LEVEL_ERROR,
        VERIFICATION_LEVEL_EXISTS,
        VERIFICATION_LEVEL_SIGNED_IN
} VerificationLevel;

enum {
        EXPIRED,
        UNEXPIRED,
        NEEDS_RENEWAL,
        NEEDS_REFRESH,
        NUMBER_OF_SIGNALS,
};

static guint signals[NUMBER_OF_SIGNALS] = { 0 };

static void identity_interface_init (GsdIdentityInterface *interface);
static void initable_interface_init (GInitableIface *interface);
static void set_expiration_and_renewal_alarms (GsdKerberosIdentity *self);

G_DEFINE_TYPE_WITH_CODE (GsdKerberosIdentity,
                         gsd_kerberos_identity,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GSD_TYPE_IDENTITY,
                                                identity_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                initable_interface_init));

static void
gsd_kerberos_identity_dispose (GObject *object)
{
        GsdKerberosIdentity *self = GSD_KERBEROS_IDENTITY (object);

        if (self->priv->renewal_alarm_cancellable != NULL) {
                if (!g_cancellable_is_cancelled (self->priv->renewal_alarm_cancellable)) {
                        g_cancellable_cancel (self->priv->renewal_alarm_cancellable);
                }
                g_object_unref (self->priv->renewal_alarm_cancellable);
                self->priv->renewal_alarm_cancellable = NULL;
        }

        if (self->priv->renewal_alarm != NULL) {
                g_object_unref (self->priv->renewal_alarm);
                self->priv->renewal_alarm = NULL;
        }

        if (self->priv->expiration_alarm_cancellable != NULL) {
                if (!g_cancellable_is_cancelled (self->priv->expiration_alarm_cancellable)) {
                        g_cancellable_cancel (self->priv->expiration_alarm_cancellable);
                }
                g_object_unref (self->priv->expiration_alarm_cancellable);
                self->priv->expiration_alarm_cancellable = NULL;
        }

        if (self->priv->expiration_alarm != NULL) {
                g_object_unref (self->priv->expiration_alarm);
                self->priv->expiration_alarm = NULL;
        }
}

static void
gsd_kerberos_identity_finalize (GObject *object)
{
        GsdKerberosIdentity *self = GSD_KERBEROS_IDENTITY (object);

        g_free (self->priv->identifier);
        self->priv->identifier = NULL;

        if (self->priv->credentials_cache != NULL) {
                krb5_cc_close (self->priv->kerberos_context, self->priv->credentials_cache);
        }

        G_OBJECT_CLASS (gsd_kerberos_identity_parent_class)->finalize (object);
}

static void
gsd_kerberos_identity_class_init (GsdKerberosIdentityClass *klass)
{
        GObjectClass *object_class;

        object_class = G_OBJECT_CLASS (klass);

        object_class->dispose = gsd_kerberos_identity_dispose;
        object_class->finalize = gsd_kerberos_identity_finalize;

        g_type_class_add_private (klass, sizeof (GsdKerberosIdentityPrivate));

        signals[EXPIRED] = g_signal_new ("expired",
                                         G_TYPE_FROM_CLASS (klass),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL, NULL, NULL,
                                         G_TYPE_NONE, 0);
        signals[UNEXPIRED] = g_signal_new ("unexpired",
                                           G_TYPE_FROM_CLASS (klass),
                                           G_SIGNAL_RUN_LAST,
                                           0,
                                           NULL, NULL, NULL,
                                           G_TYPE_NONE, 0);
        signals[NEEDS_RENEWAL] = g_signal_new ("needs-renewal",
                                               G_TYPE_FROM_CLASS (klass),
                                               G_SIGNAL_RUN_LAST,
                                               0,
                                               NULL, NULL, NULL,
                                               G_TYPE_NONE, 0);
        signals[NEEDS_REFRESH] = g_signal_new ("needs-refresh",
                                               G_TYPE_FROM_CLASS (klass),
                                               G_SIGNAL_RUN_LAST,
                                               0,
                                               NULL, NULL, NULL,
                                               G_TYPE_NONE, 0);
}

static void
gsd_kerberos_identity_init (GsdKerberosIdentity *self)
{
        self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                                  GSD_TYPE_KERBEROS_IDENTITY,
                                                  GsdKerberosIdentityPrivate);
        self->priv->expiration_alarm = gsd_alarm_new ();
        self->priv->renewal_alarm = gsd_alarm_new ();

        g_rec_mutex_init (&self->priv->updates_lock);
}

static char *
get_principal_name (GsdKerberosIdentity *self,
                    gboolean            for_display)
{
        krb5_principal principal;
        krb5_error_code error_code;
        char *unparsed_name;
        char *principal_name;
        int flags;

        if (self->priv->credentials_cache == NULL) {
                return NULL;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("GsdKerberosIdentity: Error looking up principal identity in credential cache: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return NULL;
        }

        if (for_display) {
                flags = KRB5_PRINCIPAL_UNPARSE_DISPLAY;
        } else {
                flags = 0;
        }

        error_code = krb5_unparse_name_flags (self->priv->kerberos_context,
                                              principal,
                                              flags,
                                              &unparsed_name);

        if (error_code != 0) {
                const char *error_message;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("GsdKerberosIdentity: Error parsing principal identity name: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return NULL;
        }

        principal_name = g_strdup (unparsed_name);
        krb5_free_unparsed_name (self->priv->kerberos_context, unparsed_name);

        return principal_name;
}

char *
gsd_kerberos_identity_get_principal_name (GsdKerberosIdentity *self)
{
        char *principal_name;

        if (self->priv->cached_principal_name == NULL) {
                self->priv->cached_principal_name = get_principal_name (self, TRUE);
        }
        principal_name = g_strdup (self->priv->cached_principal_name);

        return principal_name;
}

static char *
get_realm_name (GsdKerberosIdentity *self)
{
        krb5_principal principal;
        krb5_error_code error_code;
        krb5_data *realm;
        char *realm_name;

        if (self->priv->credentials_cache == NULL) {
                return NULL;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("GsdKerberosIdentity: Error looking up principal identity in credential cache: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return NULL;
        }

        realm = krb5_princ_realm (self->priv->kerberos_context,
                                  principal);
        realm_name = g_strndup (realm->data, realm->length);
        krb5_free_principal (self->priv->kerberos_context, principal);

        return realm_name;
}

char *
gsd_kerberos_identity_get_realm_name (GsdKerberosIdentity *self)
{
        char *realm_name;

        if (self->priv->cached_realm_name == NULL) {
                self->priv->cached_realm_name = get_realm_name (self);
        }
        realm_name = g_strdup (self->priv->cached_realm_name);

        return realm_name;
}

static const char *
gsd_kerberos_identity_get_identifier (GsdIdentity *identity)
{
        GsdKerberosIdentity *self = GSD_KERBEROS_IDENTITY (identity);

        if (self->priv->identifier == NULL) {
                self->priv->identifier = get_principal_name (self, FALSE);
        }

        return self->priv->identifier;
}

static gboolean
credentials_validate_existence (GsdKerberosIdentity *self,
                                krb5_principal      principal,
                                krb5_creds         *credentials)
{
        /* Checks if default principal associated with the cache has a valid
         * ticket granting ticket in the passed in credentials
         */

        if (krb5_is_config_principal (self->priv->kerberos_context,
                                      credentials->server)) {
                return FALSE;
        }

        /* looking for the krbtgt / REALM pair, so it should be exactly 2 items */
        if (krb5_princ_size (self->priv->kerberos_context,
                             credentials->server) != 2) {
                return FALSE;
        }

        if (!krb5_realm_compare (self->priv->kerberos_context,
                                 credentials->server,
                                 principal)) {
                /* credentials are from some other realm */
                return FALSE;
        }

        if (strncmp (credentials->server->data[0].data,
                     KRB5_TGS_NAME,
                     credentials->server->data[0].length) != 0) {
                /* credentials aren't for ticket granting */
                return FALSE;
        }

        if (credentials->server->data[1].length != principal->realm.length ||
            memcmp (credentials->server->data[1].data,
                    principal->realm.data,
                    principal->realm.length) != 0) {
                /* credentials are for some other realm */
                return FALSE;
        }

        return TRUE;
}

static krb5_timestamp
get_current_time (GsdKerberosIdentity *self)
{
        krb5_timestamp  current_time;
        krb5_error_code error_code;

        error_code = krb5_timeofday (self->priv->kerberos_context,
                                     &current_time);

        if (error_code != 0) {
                const char *error_message;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("GsdKerberosIdentity: Error getting current time: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return 0;
        }

        return current_time;
}

static gboolean
credentials_are_expired (GsdKerberosIdentity *self,
                         krb5_creds          *credentials)
{
        krb5_timestamp  current_time;

        current_time = get_current_time (self);

        self->priv->expiration_time = MAX (credentials->times.endtime,
                                           self->priv->expiration_time);

        if (credentials->times.endtime <= current_time) {
                return TRUE;
        }

        return FALSE;
}

static VerificationLevel
verify_identity (GsdKerberosIdentity  *self,
                 GError             **error)
{
        krb5_principal principal;
        const char *error_message;
        krb5_cc_cursor cursor;
        krb5_creds credentials;
        krb5_error_code error_code;
        VerificationLevel verification_level;

        if (self->priv->credentials_cache == NULL) {
                return VERIFICATION_LEVEL_UNVERIFIED;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                if (error_code == KRB5_CC_END) {
                        return VERIFICATION_LEVEL_UNVERIFIED;
                }

                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_VERIFYING,
                             _("Could not find identity in credential cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);

                return VERIFICATION_LEVEL_ERROR;
        }

        error_code = krb5_cc_start_seq_get (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &cursor);
        if (error_code != 0) {
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_VERIFYING,
                             _("Could not find identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);

                verification_level = VERIFICATION_LEVEL_ERROR;
                goto out;
        }

        verification_level = VERIFICATION_LEVEL_UNVERIFIED;

        error_code = krb5_cc_next_cred (self->priv->kerberos_context,
                                        self->priv->credentials_cache,
                                        &cursor,
                                        &credentials);

        while (error_code == 0) {
                if (credentials_validate_existence (self, principal, &credentials)) {
                        if (!credentials_are_expired (self, &credentials)) {
                                verification_level = VERIFICATION_LEVEL_SIGNED_IN;
                                g_debug ("GsdKerberosIdentity: credentials good");
                        } else {
                                verification_level = VERIFICATION_LEVEL_EXISTS;
                                g_debug ("GsdKerberosIdentity: credentials expired");
                        }
                }

                error_code = krb5_cc_next_cred (self->priv->kerberos_context,
                                                self->priv->credentials_cache,
                                                &cursor,
                                                &credentials);
        }

        if (error_code != KRB5_CC_END) {
                verification_level = VERIFICATION_LEVEL_ERROR;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_VERIFYING,
                             _("Could not sift through identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                goto out;
        }

        error_code = krb5_cc_end_seq_get (self->priv->kerberos_context,
                                          self->priv->credentials_cache,
                                          &cursor);

        if (error_code != 0) {
                verification_level = VERIFICATION_LEVEL_ERROR;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_VERIFYING,
                             _("Could not finish up sifting through identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                goto out;
        }
out:
        krb5_free_principal (self->priv->kerberos_context, principal);
        return verification_level;
}

static gboolean
gsd_kerberos_identity_is_signed_in (GsdIdentity *identity)
{
        GsdKerberosIdentity *self = GSD_KERBEROS_IDENTITY (identity);
        VerificationLevel verification_level;

        verification_level = verify_identity (self, NULL);

        return verification_level == VERIFICATION_LEVEL_SIGNED_IN;
}

static void
identity_interface_init (GsdIdentityInterface *interface)
{
        interface->get_identifier = gsd_kerberos_identity_get_identifier;
        interface->is_signed_in = gsd_kerberos_identity_is_signed_in;
}

static void
on_expiration_alarm_fired (GsdAlarm            *alarm,
                           GsdKerberosIdentity *self)
{
        VerificationLevel verification_level;

        g_return_if_fail (GSD_IS_ALARM (alarm));
        g_return_if_fail (GSD_IS_KERBEROS_IDENTITY (self));

        g_signal_emit (G_OBJECT (self), signals[NEEDS_REFRESH], 0);
#if 0
        verification_level = verify_identity (self, NULL);

        if (verification_level != VERIFICATION_LEVEL_SIGNED_IN) {
                g_signal_emit (G_OBJECT (self), signals[EXPIRED], 0);
        }

        if (verification_level != VERIFICATION_LEVEL_SIGNED_IN) {
                set_expiration_and_renewal_alarms (self);
        }
#endif

}

static void
on_expiration_alarm_rearmed (GsdAlarm            *alarm,
                             GsdKerberosIdentity *self)
{
        VerificationLevel verification_level;

        g_return_if_fail (GSD_IS_ALARM (alarm));
        g_return_if_fail (GSD_IS_KERBEROS_IDENTITY (self));

        g_signal_emit (G_OBJECT (self), signals[NEEDS_REFRESH], 0);
#if 0
        verification_level = verify_identity (self, NULL);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                g_signal_emit (G_OBJECT (self), signals[UNEXPIRED], 0);
        }

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                set_expiration_and_renewal_alarms (self);
        }
#endif
}

static void
on_renewal_alarm_fired (GsdAlarm            *alarm,
                        GsdKerberosIdentity *self)
{
        VerificationLevel verification_level;

        g_return_if_fail (GSD_IS_ALARM (alarm));
        g_return_if_fail (GSD_IS_KERBEROS_IDENTITY (self));

        if (self->priv->renewal_alarm_cancellable != NULL) {
                g_object_unref (self->priv->renewal_alarm_cancellable);
                self->priv->renewal_alarm_cancellable = NULL;
        }

        g_debug ("GsdKerberosIdentity: renewal alarm fired");
        g_signal_emit (G_OBJECT (self), signals[NEEDS_RENEWAL], 0);
#if 0
        verification_level = verify_identity (self, NULL);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                g_signal_emit (G_OBJECT (self), signals[NEEDS_RENEWAL], 0);
        } else {
                g_debug ("GsdKerberosIdentity: not signed in so not renewing");
        }

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                set_expiration_and_renewal_alarms (self);
        }
#endif
}

static void
on_renewal_alarm_rearmed (GsdAlarm            *alarm,
                          GsdKerberosIdentity *self)
{
        VerificationLevel verification_level;

        g_return_if_fail (GSD_IS_ALARM (alarm));
        g_return_if_fail (GSD_IS_KERBEROS_IDENTITY (self));

#if 0
        G_LOCK (gsd_kerberos_identity_updates_lock);
        verification_level = verify_identity (self, NULL);
        G_UNLOCK (gsd_kerberos_identity_updates_lock);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                set_expiration_and_renewal_alarms (self);
        }
#endif
}

static void
set_expiration_and_renewal_alarms (GsdKerberosIdentity *self)
{
        GDateTime *now;
        GDateTime *expiration_time;
        GDateTime *renewal_time;
        GTimeSpan  time_span_until_expiration;

        now = g_date_time_new_now_local ();
        expiration_time = g_date_time_new_from_unix_local (self->priv->expiration_time);
        time_span_until_expiration = g_date_time_difference (expiration_time, now);
        renewal_time = g_date_time_add (expiration_time,
                                        - (time_span_until_expiration / 2));

        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->expiration_alarm),
                                              G_CALLBACK (on_expiration_alarm_fired),
                                              self);
        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->renewal_alarm),
                                              G_CALLBACK (on_renewal_alarm_fired),
                                              self);
        g_signal_connect (G_OBJECT (self->priv->expiration_alarm),
                          "fired",
                          G_CALLBACK (on_expiration_alarm_fired),
                          self);
        g_signal_connect (G_OBJECT (self->priv->renewal_alarm),
                          "fired",
                          G_CALLBACK (on_renewal_alarm_fired),
                          self);
        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->expiration_alarm),
                                              G_CALLBACK (on_expiration_alarm_rearmed),
                                              self);
        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->renewal_alarm),
                                              G_CALLBACK (on_renewal_alarm_rearmed),
                                              self);
        g_signal_connect (G_OBJECT (self->priv->expiration_alarm),
                          "rearmed",
                          G_CALLBACK (on_expiration_alarm_rearmed),
                          self);
        g_signal_connect (G_OBJECT (self->priv->renewal_alarm),
                          "rearmed",
                          G_CALLBACK (on_renewal_alarm_rearmed),
                          self);

        if (self->priv->expiration_alarm_cancellable != NULL) {
                g_object_unref (self->priv->expiration_alarm_cancellable);
                self->priv->expiration_alarm_cancellable = NULL;
        }

        if (self->priv->renewal_alarm_cancellable != NULL) {
                g_object_unref (self->priv->renewal_alarm_cancellable);
                self->priv->renewal_alarm_cancellable = NULL;
        }

        self->priv->expiration_alarm_cancellable = g_cancellable_new ();
        gsd_alarm_set (self->priv->expiration_alarm,
                       expiration_time,
                       self->priv->expiration_alarm_cancellable);
        g_date_time_unref (expiration_time);

        self->priv->renewal_alarm_cancellable = g_cancellable_new ();
        gsd_alarm_set (self->priv->renewal_alarm,
                       renewal_time,
                       self->priv->renewal_alarm_cancellable);
        g_date_time_unref (renewal_time);
}

static gboolean
gsd_kerberos_identity_initable_init (GInitable      *initable,
                                     GCancellable   *cancellable,
                                     GError        **error)
{
        GsdKerberosIdentity *self = GSD_KERBEROS_IDENTITY (initable);
        GError *verification_error;
        VerificationLevel verification_level;

        if (g_cancellable_set_error_if_cancelled (cancellable, error)) {
                return FALSE;
        }

        verification_error = NULL;
        verification_level = verify_identity (self, &verification_error);

        switch (verification_level) {
                case VERIFICATION_LEVEL_EXISTS:
                    set_expiration_and_renewal_alarms (self);
                    return TRUE;

                case VERIFICATION_LEVEL_SIGNED_IN:
                    set_expiration_and_renewal_alarms (self);
                    return TRUE;

                case VERIFICATION_LEVEL_ERROR:
                    g_propagate_error (error, verification_error);
                    return FALSE;

                case VERIFICATION_LEVEL_UNVERIFIED:
                default:
                {
                        const char *name;

                        name = krb5_cc_get_name (self->priv->kerberos_context,
                                                 self->priv->credentials_cache);
                        g_set_error (error,
                                     GSD_IDENTITY_ERROR,
                                     GSD_IDENTITY_ERROR_VERIFYING,
                                     _("No associated identification found%s%s"),
                                     name != NULL? " for credentials cache " : "",
                                     name != NULL? name : "");
                    return FALSE;
                 }
        }
}

static void
initable_interface_init (GInitableIface *interface)
{
        interface->init = gsd_kerberos_identity_initable_init;
}

void
gsd_kerberos_identity_update (GsdKerberosIdentity *self,
                              GsdKerberosIdentity *new_identity)
{
        char *new_principal_name;
        VerificationLevel verification_level;

        if (self->priv->credentials_cache != NULL) {
                krb5_cc_close (self->priv->kerberos_context, self->priv->credentials_cache);
        }
        krb5_cc_dup (new_identity->priv->kerberos_context,
                     new_identity->priv->credentials_cache,
                     &self->priv->credentials_cache);

        if (!g_cancellable_is_cancelled (self->priv->renewal_alarm_cancellable)) {
                g_cancellable_cancel (self->priv->renewal_alarm_cancellable);
        }

        if (!g_cancellable_is_cancelled (self->priv->expiration_alarm_cancellable)) {
                g_cancellable_cancel (self->priv->expiration_alarm_cancellable);
        }

        new_principal_name = get_principal_name (self, FALSE);
        if (g_strcmp0 (self->priv->identifier, new_principal_name) != 0) {
                g_free (self->priv->identifier);
                self->priv->identifier = new_principal_name;
        } else {
                g_free (new_principal_name);
        }

        g_free (self->priv->cached_realm_name);
        self->priv->cached_realm_name = get_realm_name (self);

        g_free (self->priv->cached_principal_name);
        self->priv->cached_principal_name = get_principal_name (self, TRUE);

        verification_level = verify_identity (self, NULL);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN ||
            verification_level == VERIFICATION_LEVEL_EXISTS) {
                set_expiration_and_renewal_alarms (self);
        }
}

gboolean
gsd_kerberos_identity_renew (GsdKerberosIdentity  *self,
                             GError              **error)
{
        krb5_error_code error_code = 0;
        krb5_principal principal;
        krb5_creds new_credentials;
        gboolean renewed = FALSE;
        char *name = NULL;

        if (self->priv->credentials_cache == NULL) {
                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_RENEWING,
                             _("Could not renew identitys: Not signed in"));
                goto out;
        }


        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                if (error_code == 22)
                    raise(SIGABRT);
                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_RENEWING,
                             _("Could not renew identity: %s"), error_message);

                krb5_free_error_message (self->priv->kerberos_context, error_message);
                goto out;
        }

        name = gsd_kerberos_identity_get_principal_name (self);

        error_code = krb5_get_renewed_creds (self->priv->kerberos_context,
                                             &new_credentials,
                                             principal,
                                             self->priv->credentials_cache,
                                             NULL);
        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_RENEWING,
                             _("Could not get new credentials to renew identity %s: %s"),
                             name,
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                krb5_free_principal (self->priv->kerberos_context, principal);
                goto out;
        }

        error_code = krb5_cc_initialize (self->priv->kerberos_context,
                                         self->priv->credentials_cache,
                                         principal);
        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_RENEWING,
                             _("Could not reinitialize credentials cache to renew identity %s: %s"),
                             name,
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                krb5_free_principal (self->priv->kerberos_context, principal);
                krb5_free_cred_contents (self->priv->kerberos_context, &new_credentials);
                goto out;
        }

        krb5_free_principal (self->priv->kerberos_context, principal);

        error_code = krb5_cc_store_cred (self->priv->kerberos_context,
                                         self->priv->credentials_cache,
                                         &new_credentials);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_RENEWING,
                             _("Could not store new credentials in credentials cache to renew identity %s: %s"),
                             name,
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                krb5_free_cred_contents (self->priv->kerberos_context, &new_credentials);
                goto out;
        }
        krb5_free_cred_contents (self->priv->kerberos_context, &new_credentials);

        g_debug ("GsdKerberosIdentity: identity %s renewed\n", name);
        renewed = TRUE;
out:
        g_free (name);

        return renewed;
}

gboolean
gsd_kerberos_identity_erase  (GsdKerberosIdentity  *self,
                              GError              **error)
{
        krb5_error_code error_code = 0;

        if (self->priv->credentials_cache != NULL) {
                error_code = krb5_cc_destroy (self->priv->kerberos_context,
                                              self->priv->credentials_cache);
                self->priv->credentials_cache = NULL;
        }

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                g_set_error (error,
                             GSD_IDENTITY_ERROR,
                             GSD_IDENTITY_ERROR_ERASING,
                             _("Could not erase identity: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return FALSE;
        }

        return TRUE;
}

GsdIdentity *
gsd_kerberos_identity_new (krb5_context context,
                           krb5_ccache  cache)
{
        GsdKerberosIdentity *self;
        GError *error;

        self = GSD_KERBEROS_IDENTITY (g_object_new (GSD_TYPE_KERBEROS_IDENTITY, NULL));

        krb5_cc_dup (context,
                     cache,
                     &self->priv->credentials_cache);
        self->priv->kerberos_context = context;

        error = NULL;
        if (!g_initable_init (G_INITABLE (self), NULL, &error)) {
                const char *name;

                name = krb5_cc_get_name (context,
                                         cache);
                g_debug ("Could not build identity%s%s: %s",
                         name != NULL? " from credentials cache " : "",
                         name != NULL? name : "",
                         error->message);
                g_error_free (error);
                g_object_unref (self);
                return NULL;
        }

        return GSD_IDENTITY (self);
}
