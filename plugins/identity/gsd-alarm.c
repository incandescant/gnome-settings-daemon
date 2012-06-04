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
 * Based on work by Colin Walters
 */

#include "config.h"

#include "gsd-alarm.h"

#define  TFD_TIMER_CANCEL_ON_SET  (1 << 1)
#define HAVE_TIMERFD

#ifdef HAVE_TIMERFD
#include <sys/timerfd.h>
#endif

#include <unistd.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>

typedef struct {
        GSource      *source;
        GInputStream *stream;
} Timer;

typedef struct {
        GSource *source;
} Timeout;

#define MAX_TIMEOUT_INTERVAL (10 * 1000)

typedef enum {
    GSD_ALARM_TYPE_UNSCHEDULED,
    GSD_ALARM_TYPE_TIMER,
    GSD_ALARM_TYPE_TIMEOUT,
} GsdAlarmType;

struct _GsdAlarmPrivate
{
        GCancellable *cancellable;
        GDateTime    *time;
        GDateTime    *previous_wakeup_time;
        GMainContext *context;
        GSource      *immediate_wakeup_source;

        GsdAlarmType type;
        union {
                Timer   timer;
                Timeout timeout;
        };
};

enum {
        FIRED,
        REARMED,
        NGSDBER_OF_SIGNALS,
};

static void schedule_wakeups (GsdAlarm *self);
static void schedule_wakeups_with_timeout_source (GsdAlarm *self);
static guint signals[NGSDBER_OF_SIGNALS] = { 0 };

G_DEFINE_TYPE (GsdAlarm, gsd_alarm, G_TYPE_OBJECT);

static void
clear_scheduled_immediate_wakeup (GsdAlarm *self)
{
        if (self->priv->immediate_wakeup_source != NULL) {
                g_source_destroy (self->priv->immediate_wakeup_source);
                g_source_unref (self->priv->immediate_wakeup_source);
                self->priv->immediate_wakeup_source = NULL;
        }
}

static void
clear_scheduled_timer_wakeups (GsdAlarm *self)
{
#ifdef HAVE_TIMERFD
        GError *error;
        gboolean is_closed;

        if (self->priv->timer.stream == NULL) {
                return;
        }

        g_source_destroy (self->priv->timer.source);
        g_source_unref (self->priv->timer.source);
        self->priv->timer.source = NULL;

        error = NULL;
        is_closed = g_input_stream_close (self->priv->timer.stream,
                                          NULL,
                                          &error);

        if (!is_closed) {
                g_warning ("GsdAlarm: could not close timer stream: %s",
                           error->message);
                g_error_free (error);
        }

        g_object_unref (self->priv->timer.stream);
        self->priv->timer.stream = NULL;

#endif
}

static void
clear_scheduled_timeout_wakeups (GsdAlarm *self)
{
        if (self->priv->timeout.source != NULL) {
                g_source_destroy (self->priv->timeout.source);
                g_source_unref (self->priv->timeout.source);
                self->priv->timeout.source = NULL;
        }
}

static void
clear_scheduled_wakeups (GsdAlarm *self)
{
        clear_scheduled_immediate_wakeup (self);

        switch (self->priv->type) {
                case GSD_ALARM_TYPE_TIMER:
                        clear_scheduled_timer_wakeups (self);
                        break;

                case GSD_ALARM_TYPE_TIMEOUT:
                        clear_scheduled_timeout_wakeups (self);
                        break;

                default:
                        break;
        }

        if (self->priv->cancellable != NULL) {
                if (!g_cancellable_is_cancelled (self->priv->cancellable)) {
                        g_cancellable_cancel (self->priv->cancellable);
                }

                g_object_unref (self->priv->cancellable);
                self->priv->cancellable = NULL;
        }

        if (self->priv->context != NULL) {
                g_main_context_unref (self->priv->context);
                self->priv->context = NULL;
        }

        if (self->priv->previous_wakeup_time != NULL) {
                g_date_time_unref (self->priv->previous_wakeup_time);
                self->priv->previous_wakeup_time = NULL;
        }

        self->priv->type = GSD_ALARM_TYPE_UNSCHEDULED;
}

static void
gsd_alarm_finalize (GObject *object)
{
        GsdAlarm *self = GSD_ALARM (object);

        if (self->priv->cancellable != NULL &&
            !g_cancellable_is_cancelled (self->priv->cancellable)) {
                g_cancellable_cancel (self->priv->cancellable);
        }

        clear_scheduled_wakeups (self);

        if (self->priv->time != NULL) {
                g_date_time_unref (self->priv->time);
        }

        if (self->priv->previous_wakeup_time != NULL) {
                g_date_time_unref (self->priv->previous_wakeup_time);
        }

        G_OBJECT_CLASS (gsd_alarm_parent_class)->finalize (object);
}

static void
gsd_alarm_class_init (GsdAlarmClass *klass)
{
        GObjectClass *object_class;

        object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = gsd_alarm_finalize;

        g_type_class_add_private (klass, sizeof (GsdAlarmPrivate));

        signals[FIRED] = g_signal_new ("fired",
                                       G_TYPE_FROM_CLASS (klass),
                                       G_SIGNAL_RUN_LAST,
                                       0,
                                       NULL, NULL, NULL,
                                       G_TYPE_NONE, 0);

        signals[REARMED] = g_signal_new ("rearmed",
                                         G_TYPE_FROM_CLASS (klass),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL, NULL, NULL,
                                         G_TYPE_NONE, 0);
}

static void
gsd_alarm_init (GsdAlarm *self)
{
        self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                                  GSD_TYPE_ALARM,
                                                  GsdAlarmPrivate);
        self->priv->type = GSD_ALARM_TYPE_UNSCHEDULED;
}

static void
on_cancelled (GCancellable *cancellable,
              gpointer      user_data)
{
        GsdAlarm *self = GSD_ALARM (user_data);

        clear_scheduled_wakeups (self);
}

static void
fire_alarm (GsdAlarm *self)
{
        g_signal_emit (G_OBJECT (self), signals[FIRED], 0);
}

static void
rearm_alarm (GsdAlarm *self)
{
        g_signal_emit (G_OBJECT (self), signals[REARMED], 0);
}

static void
fire_or_rearm_alarm (GsdAlarm *self)
{
        GTimeSpan  time_until_fire;
        GTimeSpan  previous_time_until_fire;
        GDateTime *now;

        now = g_date_time_new_now_local ();
        time_until_fire = g_date_time_difference (self->priv->time, now);

        if (self->priv->previous_wakeup_time == NULL) {
                self->priv->previous_wakeup_time = now;

                /* If, according to the time, we're past when we should have fired,
                 * then fire the alarm.
                 */
                if (time_until_fire <= 0) {
                        fire_alarm (self);
                }
        } else {
                previous_time_until_fire = g_date_time_difference (self->priv->time,
                                                                   self->priv->previous_wakeup_time);

                g_date_time_unref (self->priv->previous_wakeup_time);
                self->priv->previous_wakeup_time = now;

                /* If, according to the time, we're past when we should have fired,
                 * and this is the first wakeup where that's been true then fire
                 * the alarm. The first check makes sure we don't fire prematurely,
                 * and the second check makes sure we don't fire more than once
                 */
                if (time_until_fire <= 0 && previous_time_until_fire > 0) {
                        fire_alarm (self);

                /* If, according to the time, we're before when we should fire,
                 * and we previously fired the alarm, then we've jumped back in
                 * time and need to rearm the alarm.
                 */
                } else if (time_until_fire > 0 && previous_time_until_fire <= 0) {
                        rearm_alarm (self);
                }
        }
}

static gboolean
on_immediate_wakeup_source_ready (GsdAlarm *self)
{
        g_return_val_if_fail (self->priv->type != GSD_ALARM_TYPE_UNSCHEDULED, FALSE);

        if (g_cancellable_is_cancelled (self->priv->cancellable)) {
                return FALSE;
        }

        fire_or_rearm_alarm (self);

        return FALSE;
}

#ifdef HAVE_TIMERFD
static gboolean
on_timer_source_ready (GObject  *stream,
                       GsdAlarm *self)
{
        gint64 number_of_fires;
        gssize bytes_read;

        g_return_val_if_fail (GSD_IS_ALARM (self), FALSE);
        g_return_val_if_fail (self->priv->type == GSD_ALARM_TYPE_TIMER, FALSE);

        if (g_cancellable_is_cancelled (self->priv->cancellable)) {
                return FALSE;
        }

        bytes_read = g_pollable_input_stream_read_nonblocking (G_POLLABLE_INPUT_STREAM (stream),
                                                               &number_of_fires,
                                                               sizeof (gint64),
                                                               NULL,
                                                               NULL);

        if (bytes_read == sizeof (gint64)) {
                if (number_of_fires < 0 || number_of_fires > 1) {
                        g_warning ("GsdAlarm: expected timerfd to report firing once,"
                                   "but it reported firing %ld times\n",
                                   (long) number_of_fires);
                }
        }

        fire_or_rearm_alarm (self);
        return TRUE;
}
#endif

static gboolean
schedule_wakeups_with_timerfd (GsdAlarm *self)
{
#ifdef HAVE_TIMERFD
        struct itimerspec timer_spec;
        int fd;
        int result;
        static gboolean seen_before = FALSE;

        if (!seen_before) {
                g_debug ("GsdAlarm: trying to use kernel timer");
                seen_before = TRUE;
        }

        fd = timerfd_create (CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);

        if (fd < 0) {
                g_debug ("GsdAlarm: could not create timer fd: %m");
                return FALSE;
        }

        memset (&timer_spec, 0, sizeof (timer_spec));
        timer_spec.it_value.tv_sec = g_date_time_to_unix (self->priv->time) + 1;

        result = timerfd_settime (fd,
                                  TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                                  &timer_spec,
                                  NULL);

        if (result < 0) {
                g_debug ("GsdAlarm: could not set timer: %m");
                return FALSE;
        }

        self->priv->type = GSD_ALARM_TYPE_TIMER;
        self->priv->timer.stream = g_unix_input_stream_new (fd, TRUE);

        self->priv->timer.source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (self->priv->timer.stream),
                                                                          self->priv->cancellable);
        g_source_set_callback (self->priv->timer.source,
                               (GSourceFunc)
                               on_timer_source_ready,
                               g_object_ref (self),
                               (GDestroyNotify)
                               g_object_unref);
        g_source_attach (self->priv->timer.source,
                         self->priv->context);

        return TRUE;

#endif /* HAVE_TIMERFD */

    return FALSE;
}

static gboolean
on_timeout_source_ready (GsdAlarm *self)
{
        g_return_val_if_fail (GSD_IS_ALARM (self), FALSE);
        g_return_val_if_fail (self->priv->type != GSD_ALARM_TYPE_UNSCHEDULED, FALSE);
        g_return_val_if_fail (self->priv->type == GSD_ALARM_TYPE_TIMEOUT, FALSE);

        if (g_cancellable_is_cancelled (self->priv->cancellable)) {
                return FALSE;
        }

        fire_or_rearm_alarm (self);

        if (g_cancellable_is_cancelled (self->priv->cancellable)) {
                return FALSE;
        }

        schedule_wakeups_with_timeout_source (self);

        return FALSE;
}

static void
schedule_wakeups_with_timeout_source (GsdAlarm *self)
{
        GDateTime *now;
        GTimeSpan time_span;
        guint interval;

        self->priv->type = GSD_ALARM_TYPE_TIMEOUT;

        now = g_date_time_new_now_local ();
        time_span = g_date_time_difference (self->priv->time, now);
        g_date_time_unref (now);

        time_span = CLAMP (time_span, 1000 * G_TIME_SPAN_MILLISECOND, G_MAXUINT * G_TIME_SPAN_MILLISECOND);
        interval = time_span / G_TIME_SPAN_MILLISECOND;

        /* We poll every 10 seconds or so because we want to catch time skew
         */
        interval = MIN (interval, MAX_TIMEOUT_INTERVAL);

        self->priv->timeout.source = g_timeout_source_new (interval);
        g_source_set_callback (self->priv->timeout.source,
                               (GSourceFunc)
                               on_timeout_source_ready,
                               g_object_ref (self),
                               (GDestroyNotify)
                               g_object_unref);

        g_source_attach (self->priv->timeout.source,
                         self->priv->context);
}

static void
schedule_wakeups (GsdAlarm *self)
{
        gboolean wakeup_scheduled;

        wakeup_scheduled = schedule_wakeups_with_timerfd (self);

        if (!wakeup_scheduled) {
                static gboolean seen_before = FALSE;

                if (!seen_before) {
                        g_debug ("GsdAlarm: falling back to polling timeout\n");
                        seen_before = TRUE;
                }
                schedule_wakeups_with_timeout_source (self);
        }
}

static void
schedule_immediate_wakeup (GsdAlarm *self)
{
        self->priv->immediate_wakeup_source = g_idle_source_new ();

        g_source_set_callback (self->priv->immediate_wakeup_source,
                               (GSourceFunc)
                               on_immediate_wakeup_source_ready,
                               g_object_ref (self),
                               (GDestroyNotify)
                               g_object_unref);
        g_source_attach (self->priv->immediate_wakeup_source,
                         self->priv->context);
}

void
gsd_alarm_set (GsdAlarm     *self,
               GDateTime    *time,
               GCancellable *cancellable)
{
        if (g_cancellable_is_cancelled (cancellable)) {
                return;
        }

        if (self->priv->cancellable != NULL) {
                if (!g_cancellable_is_cancelled (self->priv->cancellable)) {
                        g_cancellable_cancel (cancellable);
                }

                g_object_unref (self->priv->cancellable);
                self->priv->cancellable = NULL;
        }

        if (cancellable == NULL) {
                self->priv->cancellable = g_cancellable_new ();
        } else {
                self->priv->cancellable = g_object_ref (cancellable);
        }

        g_cancellable_connect (self->priv->cancellable,
                               G_CALLBACK (on_cancelled),
                               self,
                               NULL);
        self->priv->time = g_date_time_ref (time);
        self->priv->context = g_main_context_ref (g_main_context_default ());

        schedule_wakeups (self);

        /* Wake up right away, in case it's already expired leaving the gate */
        schedule_immediate_wakeup (self);
}

GsdAlarm *
gsd_alarm_new (void)
{
        GsdAlarm *self;

        self = GSD_ALARM (g_object_new (GSD_TYPE_ALARM, NULL));

        return GSD_ALARM (self);
}
