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

#ifndef __GSD_CONNMAN_MANAGER_H
#define __GSD_CONNMAN_MANAGER_H

#include <glib-object.h>

G_BEGIN_DECLS

#define GSD_TYPE_CONNMAN_MANAGER	(gsd_connman_manager_get_type ())
#define GSD_CONNMAN_MANAGER(o)		(G_TYPE_CHECK_INSTANCE_CAST ((o), GSD_TYPE_CONNMAN_MANAGER, GsdConnmanManager))
#define GSD_CONNMAN_MANAGER_CLASS(k)	(G_TYPE_CHECK_CLASS_CAST((k), GSD_TYPE_CONNMAN_MANAGER, GsdConnmanManagerClass))
#define GSD_IS_CONNMAN_MANAGER(o)	(G_TYPE_CHECK_INSTANCE_TYPE ((o), GSD_TYPE_CONNMAN_MANAGER))
#define GSD_IS_CONNMAN_MANAGER_CLASS(k)	(G_TYPE_CHECK_CLASS_TYPE ((k), GSD_TYPE_CONNMAN_MANAGER))
#define GSD_CONNMAN_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GSD_CONNMAN_MANAGER, GsdConnmanManagerClass))

typedef struct GsdConnmanManagerPrivate GsdConnmanManagerPrivate;

typedef struct
{
	GObject			 parent;
	GsdConnmanManagerPrivate *priv;
} GsdConnmanManager;

typedef struct
{
	GObjectClass parent_class;
} GsdConnmanManagerClass;

GType			gsd_connman_manager_get_type	(void);

GsdConnmanManager *	gsd_connman_manager_new		(void);
gboolean		gsd_connman_manager_start	(GsdConnmanManager *manager,
							 GError 	  **error);
void			gsd_connman_manager_stop	(GsdConnmanManager *manager);

G_END_DECLS

#endif /* __GSD_CONNMAN_MANAGER_H */
