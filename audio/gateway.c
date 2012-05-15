/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2008-2009  Leonid Movshovich <event.riga@gmail.org>
 *  Copyright (C) 2010  ProFUSION embedded systems
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "sdp-client.h"
#include "device.h"
#include "gateway.h"
#include "telephony.h"
#include "log.h"
#include "error.h"
#include "btio.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

struct connect_cb {
	unsigned int id;
	gateway_stream_cb_t cb;
	void *cb_data;
};

struct gateway {
	gateway_state_t state;
	GIOChannel *rfcomm;
	GIOChannel *sco;
	const char *connecting_uuid;
	const char *connecting_path;
	GSList *callbacks;
	DBusMessage *msg;
	gateway_lock_t lock;
	void *slc;
};

struct gateway_state_callback {
	gateway_state_cb cb;
	void *user_data;
	unsigned int id;
};

static GSList *gateway_callbacks = NULL;

int gateway_close(struct audio_device *device);

GQuark gateway_error_quark(void)
{
	return g_quark_from_static_string("gateway-error-quark");
}

static const char *state2str(gateway_state_t state)
{
	switch (state) {
	case GATEWAY_STATE_DISCONNECTED:
		return "disconnected";
	case GATEWAY_STATE_CONNECTING:
		return "connecting";
	case GATEWAY_STATE_CONNECTED:
		return "connected";
	case GATEWAY_STATE_PLAYING:
		return "playing";
	default:
		return "";
	}
}

static void change_state(struct audio_device *dev, gateway_state_t new_state)
{
	struct gateway *gw = dev->gateway;
	const char *val;
	GSList *l;
	gateway_state_t old_state;

	if (gw->state == new_state)
		return;

	val = state2str(new_state);
	old_state = gw->state;
	gw->state = new_state;

	emit_property_changed(dev->conn, dev->path,
			AUDIO_GATEWAY_INTERFACE, "State",
			DBUS_TYPE_STRING, &val);

	for (l = gateway_callbacks; l != NULL; l = l->next) {
		struct gateway_state_callback *cb = l->data;
		cb->cb(dev, old_state, new_state, cb->user_data);
	}
}

void gateway_set_state(struct audio_device *dev, gateway_state_t new_state)
{
	struct gateway *gw = dev->gateway;

	switch (new_state) {
	case GATEWAY_STATE_DISCONNECTED:
		if (gw->msg) {
			DBusMessage *reply;

			reply = btd_error_failed(gw->msg, "Connect failed");
			g_dbus_send_message(dev->conn, reply);
			dbus_message_unref(gw->msg);
			gw->msg = NULL;
		}

		gateway_close(dev);
		break;
	case GATEWAY_STATE_CONNECTING:
	case GATEWAY_STATE_CONNECTED:
	case GATEWAY_STATE_PLAYING:
		break;
	}
}

static unsigned int connect_cb_new(struct gateway *gw,
					gateway_stream_cb_t func,
					void *user_data)
{
	struct connect_cb *cb;
	static unsigned int free_cb_id = 1;

	if (!func)
		return 0;

	cb = g_new(struct connect_cb, 1);

	cb->cb = func;
	cb->cb_data = user_data;
	cb->id = free_cb_id++;

	gw->callbacks = g_slist_append(gw->callbacks, cb);

	return cb->id;
}

static void run_connect_cb(struct audio_device *dev, GError *err)
{
	struct gateway *gw = dev->gateway;
	GSList *l;

	for (l = gw->callbacks; l != NULL; l = l->next) {
		struct connect_cb *cb = l->data;
		cb->cb(dev, err, cb->cb_data);
	}

	g_slist_free_full(gw->callbacks, g_free);
	gw->callbacks = NULL;
}

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (cond & G_IO_NVAL)
		return FALSE;

	DBG("sco connection is released");
	g_io_channel_shutdown(gw->sco, TRUE, NULL);
	g_io_channel_unref(gw->sco);
	gw->sco = NULL;
	change_state(dev, GATEWAY_STATE_CONNECTED);

	return FALSE;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = (struct audio_device *) user_data;
	struct gateway *gw = dev->gateway;

	DBG("at the begin of sco_connect_cb() in gateway.c");

	gw->sco = g_io_channel_ref(chan);

	if (err) {
		error("sco_connect_cb(): %s", err->message);
		gateway_suspend_stream(dev);
		return;
	}

	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) sco_io_cb, dev);

	change_state(dev, GATEWAY_STATE_PLAYING);
	run_connect_cb(dev, NULL);
}

void gateway_slc_complete(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;
	DBusMessage *reply;

	DBG("Service Level Connection established");

	change_state(dev, GATEWAY_STATE_CONNECTED);

	if (!gw->msg)
		return;

	reply = dbus_message_new_method_return(gw->msg);
	g_dbus_send_message(dev->conn, reply);
	dbus_message_unref(gw->msg);
	gw->msg = NULL;
}

void gateway_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	char hs_address[18];
	void *agent;

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	ba2str(&dev->dst, hs_address);

	if (gw->rfcomm == NULL)
		gw->rfcomm = g_io_channel_ref(chan);

	agent = telephony_agent_by_uuid(device_get_adapter(dev->btd_dev),
						gw->connecting_uuid);
	gw->slc = telephony_device_connecting(chan, dev, agent);
	gw->connecting_uuid = NULL;
	telephony_set_media_transport_path(gw->slc, gw->connecting_path);
	gw->connecting_path = NULL;

	DBG("%s: Connected to %s", dev->path, hs_address);

	return;

failed:
	gateway_set_state(dev, GATEWAY_STATE_DISCONNECTED);
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	int ch;
	sdp_list_t *protos, *classes;
	uuid_t uuid;
	GIOChannel *io;
	GError *gerr = NULL;

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
					-err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No records found");
		err = -EIO;
		goto fail;
	}

	if (sdp_get_service_classes(recs->data, &classes) < 0) {
		error("Unable to get service classes from record");
		err = -EINVAL;
		goto fail;
	}

	if (sdp_get_access_protos(recs->data, &protos) < 0) {
		error("Unable to get access protocols from record");
		err = -ENODATA;
		goto fail;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));
	sdp_list_free(classes, free);

	if (!sdp_uuid128_to_uuid(&uuid) || uuid.type != SDP_UUID16 ||
			uuid.value.uuid16 != HANDSFREE_AGW_SVCLASS_ID) {
		sdp_list_free(protos, NULL);
		error("Invalid service record or not HFP");
		err = -EIO;
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (ch <= 0) {
		error("Unable to extract RFCOMM channel from service record");
		err = -EIO;
		goto fail;
	}

	io = bt_io_connect(BT_IO_RFCOMM, gateway_connect_cb, dev, NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_CHANNEL, ch,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Unable to connect: %s", gerr->message);
		goto fail;
	}

	g_io_channel_unref(io);
	return;

fail:
	if (gw->msg) {
		DBusMessage *reply = btd_error_failed(gw->msg,
					gerr ? gerr->message : strerror(-err));
		g_dbus_send_message(dev->conn, reply);
		dbus_message_unref(gw->msg);
		gw->msg = NULL;
	}

	gateway_close(dev);

	if (gerr)
		g_error_free(gerr);
}

static int get_records(struct audio_device *device)
{
	uuid_t uuid;

	change_state(device, GATEWAY_STATE_CONNECTING);
	sdp_uuid16_create(&uuid, HANDSFREE_AGW_SVCLASS_ID);
	return bt_search_service(&device->src, &device->dst, &uuid,
				get_record_cb, device, NULL);
}

static DBusMessage *ag_connect(DBusConnection *conn, DBusMessage *msg,
				void *data)
{
	struct audio_device *au_dev = (struct audio_device *) data;
	struct gateway *gw = au_dev->gateway;
	int err;

	if (gw->state == GATEWAY_STATE_CONNECTING)
		return btd_error_in_progress(msg);
	else if (gw->state > GATEWAY_STATE_CONNECTING)
		return btd_error_already_connected(msg);

	if (telephony_agent_by_uuid(device_get_adapter(au_dev->btd_dev),
						HFP_HS_UUID) == NULL)
		return btd_error_agent_not_available(msg);

	gw->connecting_uuid = HFP_HS_UUID;

	err = get_records(au_dev);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	gw->msg = dbus_message_ref(msg);

	return NULL;
}

int gateway_close(struct audio_device *device)
{
	GError *gerr = NULL;
	struct gateway *gw = device->gateway;
	int sock;

	if (gw->rfcomm) {
		sock = g_io_channel_unix_get_fd(gw->rfcomm);
		shutdown(sock, SHUT_RDWR);

		g_io_channel_shutdown(gw->rfcomm, TRUE, NULL);
		g_io_channel_unref(gw->rfcomm);
		gw->rfcomm = NULL;
	}

	if (gw->sco) {
		g_io_channel_shutdown(gw->sco, TRUE, NULL);
		g_io_channel_unref(gw->sco);
		gw->sco = NULL;
	}

	change_state(device, GATEWAY_STATE_DISCONNECTED);
	g_set_error(&gerr, GATEWAY_ERROR,
			GATEWAY_ERROR_DISCONNECTED, "Disconnected");
	run_connect_cb(device, gerr);
	g_error_free(gerr);

	return 0;
}

static DBusMessage *ag_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	DBusMessage *reply = NULL;
	char gw_addr[18];

	if (!device->conn)
		return NULL;

	if (!gw->rfcomm)
		return btd_error_not_connected(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	gateway_close(device);
	ba2str(&device->dst, gw_addr);
	DBG("Disconnected from %s, %s", gw_addr, device->path);

	return reply;
}

static DBusMessage *ag_get_properties(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *value;


	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	value = state2str(gw->state);
	dict_append_entry(&dict, "State",
			DBUS_TYPE_STRING, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable gateway_methods[] = {
	{ "Connect", "", "", ag_connect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect", "", "", ag_disconnect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetProperties", "", "a{sv}", ag_get_properties },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable gateway_signals[] = {
	{ "PropertyChanged", "sv" },
	{ NULL, NULL }
};

static void path_unregister(void *data)
{
	struct audio_device *dev = data;

	DBG("Unregistered interface %s on path %s",
		AUDIO_GATEWAY_INTERFACE, dev->path);

	gateway_close(dev);

	g_free(dev->gateway);
	dev->gateway = NULL;
}

void gateway_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
						AUDIO_GATEWAY_INTERFACE);
}

struct gateway *gateway_init(struct audio_device *dev)
{
	if (DBUS_TYPE_UNIX_FD < 0)
		return NULL;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_GATEWAY_INTERFACE,
					gateway_methods, gateway_signals,
					NULL, dev, path_unregister))
		return NULL;

	return g_new0(struct gateway, 1);
}

gboolean gateway_is_connected(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (gw->state == GATEWAY_STATE_CONNECTED)
		return TRUE;

	return FALSE;
}

gboolean gateway_is_active(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (gw->state != GATEWAY_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

int gateway_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	if (!io)
		return -EINVAL;

	dev->gateway->rfcomm = g_io_channel_ref(io);

	change_state(dev, GATEWAY_STATE_CONNECTING);

	return 0;
}

GIOChannel *gateway_get_rfcomm(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	return gw->rfcomm;
}

void gateway_set_connecting_uuid(struct audio_device *dev, const char *uuid)
{
	struct gateway *gw = dev->gateway;

	gw->connecting_uuid = uuid;
}

void gateway_set_media_transport_path(struct audio_device *dev,
							const char *path)
{
	struct gateway *gw = dev->gateway;

	DBG("MediaTransport path: %s", path);

	if (gw->slc == NULL) {
		gw->connecting_path = path;
		return;
	}

	telephony_set_media_transport_path(gw->slc, path);
}

const char *gateway_get_telephony_agent_name(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (gw == NULL || gw->slc == NULL)
		return NULL;

	return telephony_get_agent_name(gw->slc);
}

int gateway_connect_sco(struct audio_device *dev, GIOChannel *io)
{
	struct gateway *gw = dev->gateway;

	if (gw->sco)
		return -EISCONN;

	gw->sco = g_io_channel_ref(io);

	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) sco_io_cb, dev);

	change_state(dev, GATEWAY_STATE_PLAYING);

	return 0;
}

static gboolean request_stream_cb(gpointer data)
{
	run_connect_cb(data, NULL);
	return FALSE;
}

/* These are functions to be called from unix.c for audio system
 * ifaces (alsa, gstreamer, etc.) */
unsigned int gateway_request_stream(struct audio_device *dev,
				gateway_stream_cb_t cb, void *user_data)
{
	struct gateway *gw = dev->gateway;
	GError *err = NULL;
	GIOChannel *io;

	if (!gw->rfcomm)
		get_records(dev);
	else if (!gw->sco) {
		io = bt_io_connect(BT_IO_SCO, sco_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_INVALID);
		if (!io) {
			error("%s", err->message);
			g_error_free(err);
			return 0;
		}
	} else
		g_idle_add(request_stream_cb, dev);

	return connect_cb_new(gw, cb, user_data);
}

int gateway_config_stream(struct audio_device *dev, gateway_stream_cb_t cb,
				void *user_data)
{
	struct gateway *gw = dev->gateway;
	unsigned int id;

	id = connect_cb_new(gw, cb, user_data);

	if (!gw->rfcomm)
		get_records(dev);
	else if (cb)
		g_idle_add(request_stream_cb, dev);

	return id;
}

gboolean gateway_cancel_stream(struct audio_device *dev, unsigned int id)
{
	struct gateway *gw = dev->gateway;
	GSList *l;
	struct connect_cb *cb = NULL;

	for (l = gw->callbacks; l != NULL; l = l->next) {
		struct connect_cb *tmp = l->data;

		if (tmp->id == id) {
			cb = tmp;
			break;
		}
	}

	if (!cb)
		return FALSE;

	gw->callbacks = g_slist_remove(gw->callbacks, cb);
	g_free(cb);

	gateway_suspend_stream(dev);

	return TRUE;
}

int gateway_get_sco_fd(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (!gw || !gw->sco)
		return -1;

	return g_io_channel_unix_get_fd(gw->sco);
}

void gateway_suspend_stream(struct audio_device *dev)
{
	GError *gerr = NULL;
	struct gateway *gw = dev->gateway;

	if (!gw || !gw->sco)
		return;

	g_io_channel_shutdown(gw->sco, TRUE, NULL);
	g_io_channel_unref(gw->sco);
	gw->sco = NULL;
	g_set_error(&gerr, GATEWAY_ERROR, GATEWAY_ERROR_SUSPENDED, "Suspended");
	run_connect_cb(dev, gerr);
	g_error_free(gerr);
	change_state(dev, GATEWAY_STATE_CONNECTED);
}

unsigned int gateway_add_state_cb(gateway_state_cb cb, void *user_data)
{
	struct gateway_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct gateway_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	gateway_callbacks = g_slist_append(gateway_callbacks, state_cb);

	return state_cb->id;
}

gboolean gateway_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = gateway_callbacks; l != NULL; l = l->next) {
		struct gateway_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			gateway_callbacks = g_slist_remove(gateway_callbacks,
									cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

gateway_lock_t gateway_get_lock(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	return gw->lock;
}

gboolean gateway_lock(struct audio_device *dev, gateway_lock_t lock)
{
	struct gateway *gw = dev->gateway;

	if (gw->lock & lock)
		return FALSE;

	gw->lock |= lock;

	return TRUE;
}

gboolean gateway_unlock(struct audio_device *dev, gateway_lock_t lock)
{
	struct gateway *gw = dev->gateway;

	if (!(gw->lock & lock))
		return FALSE;

	gw->lock &= ~lock;

	if (gw->lock)
		return TRUE;

	if (gw->state == GATEWAY_STATE_PLAYING)
		gateway_suspend_stream(dev);

	return TRUE;
}
