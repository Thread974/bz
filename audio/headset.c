/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "device.h"
#include "manager.h"
#include "error.h"
#include "telephony.h"
#include "headset.h"
#include "sdp-client.h"
#include "btio.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"

#define DC_TIMEOUT 3

static gboolean sco_hci = TRUE;

static char *str_state[] = {
	"HEADSET_STATE_DISCONNECTED",
	"HEADSET_STATE_CONNECTING",
	"HEADSET_STATE_CONNECTED",
	"HEADSET_STATE_PLAY_IN_PROGRESS",
	"HEADSET_STATE_PLAYING",
};

struct headset_state_callback {
	headset_state_cb cb;
	void *user_data;
	unsigned int id;
};

struct headset_nrec_callback {
	unsigned int id;
	headset_nrec_cb cb;
	void *user_data;
};

struct connect_cb {
	unsigned int id;
	headset_stream_cb_t cb;
	void *cb_data;
};

struct pending_connect {
	DBusMessage *msg;
	DBusPendingCall *call;
	GIOChannel *io;
	int err;
	headset_state_t target_state;
	GSList *callbacks;
	uint16_t svclass;
};

struct headset {
	uint32_t hsp_handle;
	uint32_t hfp_handle;

	int rfcomm_ch;

	GIOChannel *rfcomm;
	GIOChannel *tmp_rfcomm;
	const char *connecting_uuid;
	GIOChannel *sco;
	guint sco_id;

	gboolean auto_dc;

	guint dc_timer;

	gboolean hfp_active;
	gboolean search_hfp;
	gboolean rfcomm_initiator;

	headset_state_t state;
	struct pending_connect *pending;

	headset_lock_t lock;
	void *slc;
	GSList *nrec_cbs;
};

static GSList *headset_callbacks = NULL;

static void error_connect_failed(DBusConnection *conn, DBusMessage *msg,
								int err)
{
	DBusMessage *reply = btd_error_failed(msg,
			err < 0 ? strerror(-err) : "Connect failed");
	g_dbus_send_message(conn, reply);
}

static int rfcomm_connect(struct audio_device *device, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id);
static int get_records(struct audio_device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id);

static const char *state2str(headset_state_t state)
{
	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		return "disconnected";
	case HEADSET_STATE_CONNECTING:
		return "connecting";
	case HEADSET_STATE_CONNECTED:
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		return "connected";
	case HEADSET_STATE_PLAYING:
		return "playing";
	}

	return NULL;
}

static void pending_connect_complete(struct connect_cb *cb, struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->pending->err < 0)
		cb->cb(NULL, cb->cb_data);
	else
		cb->cb(dev, cb->cb_data);
}

static void pending_connect_finalize(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	if (p == NULL)
		return;

	if (p->svclass)
		bt_cancel_discovery(&dev->src, &dev->dst);

	g_slist_foreach(p->callbacks, (GFunc) pending_connect_complete, dev);

	g_slist_free_full(p->callbacks, g_free);

	if (p->io) {
		g_io_channel_shutdown(p->io, TRUE, NULL);
		g_io_channel_unref(p->io);
	}

	if (p->msg)
		dbus_message_unref(p->msg);

	if (p->call) {
		dbus_pending_call_cancel(p->call);
		dbus_pending_call_unref(p->call);
	}

	g_free(p);

	hs->pending = NULL;
}

static void pending_connect_init(struct headset *hs, headset_state_t target_state)
{
	if (hs->pending) {
		if (hs->pending->target_state < target_state)
			hs->pending->target_state = target_state;
		return;
	}

	hs->pending = g_new0(struct pending_connect, 1);
	hs->pending->target_state = target_state;
}

static unsigned int connect_cb_new(struct headset *hs,
					headset_state_t target_state,
					headset_stream_cb_t func,
					void *user_data)
{
	struct connect_cb *cb;
	static unsigned int free_cb_id = 1;

	pending_connect_init(hs, target_state);

	if (!func)
		return 0;

	cb = g_new(struct connect_cb, 1);

	cb->cb = func;
	cb->cb_data = user_data;
	cb->id = free_cb_id++;

	hs->pending->callbacks = g_slist_append(hs->pending->callbacks,
						cb);

	return cb->id;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	int sk;
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	if (err) {
		error("%s", err->message);

		if (p != NULL) {
			p->err = -errno;
			if (p->msg)
				error_connect_failed(dev->conn, p->msg, p->err);
			pending_connect_finalize(dev);
		}

		if (hs->rfcomm)
			headset_set_state(dev, HEADSET_STATE_CONNECTED);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

		return;
	}

	DBG("SCO socket opened for headset %s", dev->path);

	sk = g_io_channel_unix_get_fd(chan);

	DBG("SCO fd=%d", sk);

	if (p) {
		p->io = NULL;
		if (p->msg) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(p->msg);
			g_dbus_send_message(dev->conn, reply);
		}

		pending_connect_finalize(dev);
	}

	fcntl(sk, F_SETFL, 0);

	headset_set_state(dev, HEADSET_STATE_PLAYING);
}

static int sco_connect(struct audio_device *dev, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	GError *err = NULL;
	GIOChannel *io;

	if (hs->state != HEADSET_STATE_CONNECTED)
		return -EINVAL;

	io = bt_io_connect(BT_IO_SCO, sco_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return -EIO;
	}

	hs->sco = io;

	headset_set_state(dev, HEADSET_STATE_PLAY_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_PLAYING);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_PLAYING,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

void headset_slc_complete(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	DBG("Service Level Connection established");

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p == NULL)
		return;

	if (p->target_state == HEADSET_STATE_CONNECTED) {
		if (p->msg) {
			DBusMessage *reply = dbus_message_new_method_return(p->msg);
			g_dbus_send_message(dev->conn, reply);
		}
		pending_connect_finalize(dev);
		return;
	}

	p->err = sco_connect(dev, NULL, NULL, NULL);
	if (p->err < 0) {
		if (p->msg)
			error_connect_failed(dev->conn, p->msg, p->err);
		pending_connect_finalize(dev);
	}
}

static void close_sco(struct audio_device *device)
{
	struct headset *hs = device->headset;

	if (hs->sco) {
		int sock = g_io_channel_unix_get_fd(hs->sco);
		shutdown(sock, SHUT_RDWR);
		g_io_channel_shutdown(hs->sco, TRUE, NULL);
		g_io_channel_unref(hs->sco);
		hs->sco = NULL;
	}

	if (hs->sco_id) {
		g_source_remove(hs->sco_id);
		hs->sco_id = 0;
	}
}

static gboolean sco_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *device)
{
	if (cond & G_IO_NVAL)
		return FALSE;

	error("Audio connection got disconnected");

	pending_connect_finalize(device);
	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return FALSE;
}

void headset_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct btd_adapter *adapter;
	struct pending_connect *p = hs->pending;
	char hs_address[18];
	void *agent;

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	adapter = device_get_adapter(dev->btd_dev);

	/* For HFP telephony isn't ready just disconnect */
	if (hs->hfp_active && !telephony_get_ready_state(adapter)) {
		error("Unable to accept HFP connection since the telephony "
				"subsystem isn't initialized");
		goto failed;
	}

	hs->rfcomm = hs->tmp_rfcomm;
	hs->tmp_rfcomm = NULL;

	ba2str(&dev->dst, hs_address);

	if (p)
		p->io = NULL;
	else
		hs->auto_dc = FALSE;

	agent = telephony_agent_by_uuid(device_get_adapter(dev->btd_dev),
						hs->connecting_uuid);
	hs->slc = telephony_device_connecting(chan, dev, agent);
	hs->connecting_uuid = NULL;

	DBG("%s: Connected to %s", dev->path, hs_address);

	return;

failed:
	if (p && p->msg)
		error_connect_failed(dev->conn, p->msg, p->err);
	pending_connect_finalize(dev);

	if (hs->rfcomm)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int headset_set_channel(struct headset *headset,
				const sdp_record_t *record, uint16_t svc)
{
	int ch;
	sdp_list_t *protos;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get access protos from headset record");
		return -1;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);

	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch <= 0) {
		error("Unable to get RFCOMM channel from Headset record");
		return -1;
	}

	headset->rfcomm_ch = ch;

	if (svc == HANDSFREE_SVCLASS_ID) {
		headset->hfp_handle = record->handle;
		headset->hsp_handle = 0;
		DBG("Discovered Handsfree service on channel %d", ch);
	} else {
		headset->hsp_handle = record->handle;
		headset->hfp_handle = 0;
		DBG("Discovered Headset service on channel %d", ch);
	}

	return 0;
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	sdp_record_t *record = NULL;
	sdp_list_t *r;
	uuid_t uuid;

	assert(hs->pending != NULL);

	if (err < 0) {
		error("Unable to get service record: %s (%d)",
							strerror(-err), -err);
		p->err = -err;
		if (p->msg)
			error_connect_failed(dev->conn, p->msg, p->err);
		goto failed;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto failed_not_supported;
	}

	sdp_uuid16_create(&uuid, p->svclass);

	for (r = recs; r != NULL; r = r->next) {
		sdp_list_t *classes;
		uuid_t class;

		record = r->data;

		if (sdp_get_service_classes(record, &classes) < 0) {
			error("Unable to get service classes from record");
			continue;
		}

		memcpy(&class, classes->data, sizeof(uuid));

		sdp_list_free(classes, free);

		if (sdp_uuid_cmp(&class, &uuid) == 0)
			break;
	}

	if (r == NULL) {
		error("No record found with UUID 0x%04x", p->svclass);
		goto failed_not_supported;
	}

	if (headset_set_channel(hs, record, p->svclass) < 0) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed_not_supported;
	}

	/* Set svclass to 0 so we can easily check that SDP is no-longer
	 * going on (to know if bt_cancel_discovery needs to be called) */
	p->svclass = 0;

	err = rfcomm_connect(dev, NULL, NULL, NULL);
	if (err < 0) {
		error("Unable to connect: %s (%d)", strerror(-err), -err);
		p->err = -err;
		if (p->msg != NULL)
			error_connect_failed(dev->conn, p->msg, p->err);
		goto failed;
	}

	return;

failed_not_supported:
	if (p->svclass == HANDSFREE_SVCLASS_ID &&
			get_records(dev, NULL, NULL, NULL) == 0)
		return;
	if (p->msg) {
		DBusMessage *reply = btd_error_not_supported(p->msg);
		g_dbus_send_message(dev->conn, reply);
	}
failed:
	p->svclass = 0;
	hs->connecting_uuid = NULL;
	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int get_records(struct audio_device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = device->headset;
	uint16_t svclass;
	uuid_t uuid;
	int err;

	if (hs->pending && hs->pending->svclass == HANDSFREE_SVCLASS_ID)
		svclass = HEADSET_SVCLASS_ID;
	else
		svclass = hs->search_hfp ? HANDSFREE_SVCLASS_ID :
							HEADSET_SVCLASS_ID;

	if (svclass == HANDSFREE_SVCLASS_ID)
		hs->connecting_uuid = HFP_AG_UUID;
	else
		hs->connecting_uuid = HSP_AG_UUID;

	sdp_uuid16_create(&uuid, svclass);

	err = bt_search_service(&device->src, &device->dst, &uuid,
						get_record_cb, device, NULL);
	if (err < 0)
		return err;

	if (hs->pending) {
		hs->pending->svclass = svclass;
		return 0;
	}

	headset_set_state(device, HEADSET_STATE_CONNECTING);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	hs->pending->svclass = svclass;

	if (cb) {
		unsigned int id;
		id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
					cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

static int rfcomm_connect(struct audio_device *dev, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	char address[18];
	GError *err = NULL;

	if (!manager_allow_headset_connection(dev))
		return -ECONNREFUSED;

	if (hs->rfcomm_ch < 0)
		return get_records(dev, cb, user_data, cb_id);

	ba2str(&dev->dst, address);

	DBG("%s: Connecting to %s channel %d", dev->path, address,
		hs->rfcomm_ch);

	hs->tmp_rfcomm = bt_io_connect(BT_IO_RFCOMM, headset_connect_cb, dev,
					NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &dev->src,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_CHANNEL, hs->rfcomm_ch,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID);

	hs->rfcomm_ch = -1;

	if (!hs->tmp_rfcomm) {
		error("%s", err->message);
		g_error_free(err);
		return -EIO;
	}

	hs->hfp_active = hs->hfp_handle != 0 ? TRUE : FALSE;
	hs->rfcomm_initiator = FALSE;

	headset_set_state(dev, HEADSET_STATE_CONNECTING);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

static DBusMessage *hs_stop(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_PLAY_IN_PROGRESS)
		return btd_error_not_connected(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return reply;
}

static DBusMessage *hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	char hs_address[18];

	if (hs->state == HEADSET_STATE_DISCONNECTED)
		return btd_error_not_connected(msg);

	headset_shutdown(device);
	ba2str(&device->dst, hs_address);
	info("Disconnected from %s, %s", hs_address, device->path);

	return dbus_message_new_method_return(msg);

}

static DBusMessage *hs_connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	struct btd_adapter *adapter;
	int err;

	if (hs->state == HEADSET_STATE_CONNECTING)
		return btd_error_in_progress(msg);
	else if (hs->state > HEADSET_STATE_CONNECTING)
		return btd_error_already_connected(msg);

	adapter = device_get_adapter(device->btd_dev);

	if (hs->hfp_handle && !telephony_get_ready_state(adapter))
		return btd_error_not_ready(msg);

	device->auto_connect = FALSE;

	err = rfcomm_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	hs->auto_dc = FALSE;

	hs->pending->msg = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *hs_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;
	const char *state;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);


	/* Playing */
	value = (device->headset->state == HEADSET_STATE_PLAYING);
	dict_append_entry(&dict, "Playing", DBUS_TYPE_BOOLEAN, &value);

	/* State */
	state = state2str(device->headset->state);
	if (state)
		dict_append_entry(&dict, "State", DBUS_TYPE_STRING, &state);

	/* Connected */
	value = (device->headset->state >= HEADSET_STATE_CONNECTED);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable headset_methods[] = {
	{ "Connect",		"",	"",	hs_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	hs_disconnect },
	{ "Stop",		"",	"",	hs_stop },
	{ "GetProperties",	"",	"a{sv}",hs_get_properties },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable headset_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

void headset_update(struct audio_device *dev, uint16_t svc,
			const char *uuidstr)
{
	struct headset *headset = dev->headset;
	const sdp_record_t *record;

	record = btd_device_get_record(dev->btd_dev, uuidstr);
	if (!record)
		return;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		if (headset->hfp_handle &&
				(headset->hfp_handle != record->handle)) {
			error("More than one HFP record found on device");
			return;
		}

		headset->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		if (headset->hsp_handle &&
				(headset->hsp_handle != record->handle)) {
			error("More than one HSP record found on device");
			return;
		}

		headset->hsp_handle = record->handle;

		/* Ignore this record if we already have access to HFP */
		if (headset->hfp_handle)
			return;

		break;

	default:
		DBG("Invalid record passed to headset_update");
		return;
	}
}

static int headset_close_rfcomm(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	GIOChannel *rfcomm = hs->tmp_rfcomm ? hs->tmp_rfcomm : hs->rfcomm;

	if (rfcomm) {
		g_io_channel_shutdown(rfcomm, TRUE, NULL);
		g_io_channel_unref(rfcomm);
		hs->tmp_rfcomm = NULL;
		hs->rfcomm = NULL;
	}

	return 0;
}

static void headset_free(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	close_sco(dev);

	headset_close_rfcomm(dev);

	g_slist_free_full(hs->nrec_cbs, g_free);

	g_free(hs);
	dev->headset = NULL;
}

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct headset *hs = dev->headset;

	if (hs->state > HEADSET_STATE_DISCONNECTED) {
		DBG("Headset unregistered while device was connected!");
		headset_shutdown(dev);
	}

	DBG("Unregistered interface %s on path %s",
		AUDIO_HEADSET_INTERFACE, dev->path);

	headset_free(dev);
}

void headset_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
		AUDIO_HEADSET_INTERFACE);
}

struct headset *headset_init(struct audio_device *dev, uint16_t svc,
				const char *uuidstr)
{
	struct headset *hs;
	const sdp_record_t *record;

	hs = g_new0(struct headset, 1);
	hs->rfcomm_ch = -1;
	hs->search_hfp = server_is_enabled(&dev->src, HANDSFREE_SVCLASS_ID);

	record = btd_device_get_record(dev->btd_dev, uuidstr);
	if (!record)
		goto register_iface;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		hs->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		hs->hsp_handle = record->handle;
		break;

	default:
		DBG("Invalid record passed to headset_init");
		g_free(hs);
		return NULL;
	}

register_iface:
	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE,
					headset_methods, headset_signals, NULL,
					dev, path_unregister)) {
		g_free(hs);
		return NULL;
	}

	DBG("Registered interface %s on path %s",
		AUDIO_HEADSET_INTERFACE, dev->path);

	return hs;
}

uint32_t headset_config_init(GKeyFile *config)
{
	GError *err = NULL;
	char *str;

	/* Use the default values if there is no config file */
	if (config == NULL)
		return telephony_get_ag_features();

	str = g_key_file_get_string(config, "General", "SCORouting",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		if (strcmp(str, "PCM") == 0)
			sco_hci = FALSE;
		else if (strcmp(str, "HCI") == 0)
			sco_hci = TRUE;
		else
			error("Invalid Headset Routing value: %s", str);
		g_free(str);
	}

	return telephony_get_ag_features();
}

static gboolean hs_dc_timeout(struct audio_device *dev)
{
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	return FALSE;
}

gboolean headset_cancel_stream(struct audio_device *dev, unsigned int id)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	GSList *l;
	struct connect_cb *cb = NULL;

	if (!p)
		return FALSE;

	for (l = p->callbacks; l != NULL; l = l->next) {
		struct connect_cb *tmp = l->data;

		if (tmp->id == id) {
			cb = tmp;
			break;
		}
	}

	if (!cb)
		return FALSE;

	p->callbacks = g_slist_remove(p->callbacks, cb);
	g_free(cb);

	if (p->callbacks || p->msg)
		return TRUE;

	if (hs->auto_dc) {
		if (hs->rfcomm)
			hs->dc_timer = g_timeout_add_seconds(DC_TIMEOUT,
						(GSourceFunc) hs_dc_timeout,
						dev);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	}

	return TRUE;
}

static gboolean dummy_connect_complete(struct audio_device *dev)
{
	pending_connect_finalize(dev);
	return FALSE;
}

unsigned int headset_request_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;

	if (hs->state == HEADSET_STATE_PLAYING) {
		id = connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);
		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
		return id;
	}

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->state == HEADSET_STATE_CONNECTING ||
			hs->state == HEADSET_STATE_PLAY_IN_PROGRESS)
		return connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);

	if (hs->rfcomm == NULL) {
		if (rfcomm_connect(dev, cb, user_data, &id) < 0)
			return 0;
		hs->auto_dc = TRUE;
	} else if (sco_connect(dev, cb, user_data, &id) < 0)
		return 0;

	hs->pending->target_state = HEADSET_STATE_PLAYING;

	return id;
}

unsigned int headset_config_stream(struct audio_device *dev,
					gboolean auto_dc,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id = 0;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->state == HEADSET_STATE_CONNECTING)
		return connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb,
					user_data);

	if (hs->rfcomm)
		goto done;

	if (rfcomm_connect(dev, cb, user_data, &id) < 0)
		return 0;

	hs->auto_dc = auto_dc;
	hs->pending->target_state = HEADSET_STATE_CONNECTED;

	return id;

done:
	id = connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb, user_data);
	g_idle_add((GSourceFunc) dummy_connect_complete, dev);
	return id;
}

unsigned int headset_suspend_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;
	int sock;

	if (hs->state == HEADSET_STATE_DISCONNECTED ||
				hs->state == HEADSET_STATE_CONNECTING)
		return 0;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->sco) {
		sock = g_io_channel_unix_get_fd(hs->sco);

		/* shutdown but leave the socket open and wait for hup */
		shutdown(sock, SHUT_RDWR);
	} else {
		headset_set_state(dev, HEADSET_STATE_CONNECTED);

		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
	}

	id = connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb, user_data);

	return id;
}

gboolean headset_get_hfp_active(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->hfp_active;
}

void headset_set_hfp_active(struct audio_device *dev, gboolean active)
{
	struct headset *hs = dev->headset;

	hs->hfp_active = active;
}

gboolean headset_get_rfcomm_initiator(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->rfcomm_initiator;
}

void headset_set_rfcomm_initiator(struct audio_device *dev,
					gboolean initiator)
{
	struct headset *hs = dev->headset;

	hs->rfcomm_initiator = initiator;
}

GIOChannel *headset_get_rfcomm(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->tmp_rfcomm;
}

void headset_set_connecting_uuid(struct audio_device *dev, const char *uuid)
{
	struct headset *hs = dev->headset;

	hs->connecting_uuid = uuid;
}

int headset_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	struct headset *hs = dev->headset;

	if (hs->tmp_rfcomm)
		return -EALREADY;

	hs->tmp_rfcomm = g_io_channel_ref(io);

	return 0;
}

int headset_connect_sco(struct audio_device *dev, GIOChannel *io)
{
	struct headset *hs = dev->headset;

	if (hs->sco)
		return -EISCONN;

	hs->sco = g_io_channel_ref(io);

	return 0;
}

void headset_set_state(struct audio_device *dev, headset_state_t state)
{
	struct headset *hs = dev->headset;
	gboolean value;
	const char *state_str;
	headset_state_t old_state = hs->state;
	GSList *l;

	if (old_state == state)
		return;

	state_str = state2str(state);

	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		value = FALSE;
		close_sco(dev);

		if (dev->headset->slc)  {
			telephony_device_disconnect(dev->headset->slc);
			dev->headset->slc = NULL;
		}

		headset_close_rfcomm(dev);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		if (hs->state > HEADSET_STATE_CONNECTING) {
			emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);
			telephony_device_disconnected(dev);
		}
		break;
	case HEADSET_STATE_CONNECTING:
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		break;
	case HEADSET_STATE_CONNECTED:
		close_sco(dev);
		if (hs->state != HEADSET_STATE_PLAY_IN_PROGRESS)
			emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		if (hs->state < state) {
			value = TRUE;
			emit_property_changed(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_BOOLEAN, &value);
			telephony_device_connected(dev);
		} else if (hs->state == HEADSET_STATE_PLAYING) {
			value = FALSE;
			emit_property_changed(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Playing",
						DBUS_TYPE_BOOLEAN, &value);
		}
		break;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		break;
	case HEADSET_STATE_PLAYING:
		value = TRUE;
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);

		/* Do not watch HUP since we need to know when the link is
		   really disconnected */
		hs->sco_id = g_io_add_watch(hs->sco,
					G_IO_ERR | G_IO_NVAL,
					(GIOFunc) sco_cb, dev);

		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "Playing",
					DBUS_TYPE_BOOLEAN, &value);
		break;
	}

	hs->state = state;

	DBG("State changed %s: %s -> %s", dev->path, str_state[old_state],
		str_state[state]);

	for (l = headset_callbacks; l != NULL; l = l->next) {
		struct headset_state_callback *cb = l->data;
		cb->cb(dev, old_state, state, cb->user_data);
	}
}

headset_state_t headset_get_state(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->state;
}

int headset_get_channel(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->rfcomm_ch;
}

gboolean headset_is_active(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->state != HEADSET_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

headset_lock_t headset_get_lock(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->lock;
}

gboolean headset_lock(struct audio_device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (hs->lock & lock)
		return FALSE;

	hs->lock |= lock;

	return TRUE;
}

gboolean headset_unlock(struct audio_device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (!(hs->lock & lock))
		return FALSE;

	hs->lock &= ~lock;

	if (hs->lock)
		return TRUE;

	if (hs->state == HEADSET_STATE_PLAYING)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (hs->auto_dc) {
		if (hs->state == HEADSET_STATE_CONNECTED)
			hs->dc_timer = g_timeout_add_seconds(DC_TIMEOUT,
						(GSourceFunc) hs_dc_timeout,
						dev);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	}

	return TRUE;
}

gboolean headset_suspend(struct audio_device *dev, void *data)
{
	return TRUE;
}

gboolean headset_play(struct audio_device *dev, void *data)
{
	return TRUE;
}

int headset_get_sco_fd(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (!hs->sco)
		return -1;

	return g_io_channel_unix_get_fd(hs->sco);
}

gboolean headset_get_sco_hci(struct audio_device *dev)
{
	return sco_hci;
}

void headset_shutdown(struct audio_device *dev)
{
	struct pending_connect *p = dev->headset->pending;

	if (p && p->msg)
		error_connect_failed(dev->conn, p->msg, ECANCELED);

	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

unsigned int headset_add_state_cb(headset_state_cb cb, void *user_data)
{
	struct headset_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct headset_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	headset_callbacks = g_slist_append(headset_callbacks, state_cb);

	return state_cb->id;
}

gboolean headset_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = headset_callbacks; l != NULL; l = l->next) {
		struct headset_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			headset_callbacks = g_slist_remove(headset_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}
