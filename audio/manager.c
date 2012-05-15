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
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "glib-helper.h"
#include "btio.h"
#include "../src/adapter.h"
#include "../src/manager.h"
#include "../src/device.h"

#include "log.h"
#include "ipc.h"
#include "device.h"
#include "error.h"
#include "avdtp.h"
#include "media.h"
#include "a2dp.h"
#include "headset.h"
#include "gateway.h"
#include "sink.h"
#include "source.h"
#include "avrcp.h"
#include "control.h"
#include "manager.h"
#include "sdpd.h"
#include "telephony.h"
#include "unix.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

typedef enum {
	HEADSET	= 1 << 0,
	GATEWAY	= 1 << 1,
	SINK	= 1 << 2,
	SOURCE	= 1 << 3,
	CONTROL	= 1 << 4,
	TARGET	= 1 << 5,
	INVALID	= 1 << 6
} audio_service_type;

typedef enum {
		GENERIC_AUDIO = 0,
		ADVANCED_AUDIO,
		AV_REMOTE,
		GET_RECORDS
} audio_sdp_state_t;

struct audio_adapter {
	struct btd_adapter *btd_adapter;
	gboolean powered;
	gint ref;
};

static gboolean auto_connect = TRUE;
static int max_connected_headsets = 1;
static DBusConnection *connection = NULL;
static GKeyFile *config = NULL;
static GSList *adapters = NULL;
static GSList *devices = NULL;

static struct enabled_interfaces enabled = {
	.hfp		= TRUE,
	.headset	= TRUE,
	.gateway	= FALSE,
	.sink		= TRUE,
	.source		= FALSE,
	.control	= TRUE,
	.socket		= FALSE,
	.media		= TRUE,
};

static struct audio_adapter *find_adapter(GSList *list,
					struct btd_adapter *btd_adapter)
{
	for (; list; list = list->next) {
		struct audio_adapter *adapter = list->data;

		if (adapter->btd_adapter == btd_adapter)
			return adapter;
	}

	return NULL;
}

gboolean server_is_enabled(bdaddr_t *src, uint16_t svc)
{
	switch (svc) {
	case HEADSET_SVCLASS_ID:
		return enabled.headset;
	case HEADSET_AGW_SVCLASS_ID:
		return FALSE;
	case HANDSFREE_SVCLASS_ID:
		return enabled.headset && enabled.hfp;
	case HANDSFREE_AGW_SVCLASS_ID:
		return enabled.gateway;
	case AUDIO_SINK_SVCLASS_ID:
		return enabled.sink;
	case AUDIO_SOURCE_SVCLASS_ID:
		return enabled.source;
	case AV_REMOTE_TARGET_SVCLASS_ID:
	case AV_REMOTE_SVCLASS_ID:
		return enabled.control;
	default:
		return FALSE;
	}
}

static void handle_uuid(const char *uuidstr, struct audio_device *device)
{
	uuid_t uuid;
	uint16_t uuid16;

	if (bt_string2uuid(&uuid, uuidstr) < 0) {
		error("%s not detected as an UUID-128", uuidstr);
		return;
	}

	if (!sdp_uuid128_to_uuid(&uuid) && uuid.type != SDP_UUID16) {
		error("Could not convert %s to a UUID-16", uuidstr);
		return;
	}

	uuid16 = uuid.value.uuid16;

	if (!server_is_enabled(&device->src, uuid16)) {
		DBG("server not enabled for %s (0x%04x)", uuidstr, uuid16);
		return;
	}

	switch (uuid16) {
	case HEADSET_SVCLASS_ID:
		DBG("Found Headset record");
		if (device->headset)
			headset_update(device, uuid16, uuidstr);
		else
			device->headset = headset_init(device, uuid16,
							uuidstr);
		break;
	case HEADSET_AGW_SVCLASS_ID:
		DBG("Found Headset AG record");
		break;
	case HANDSFREE_SVCLASS_ID:
		DBG("Found Handsfree record");
		if (device->headset)
			headset_update(device, uuid16, uuidstr);
		else
			device->headset = headset_init(device, uuid16,
								uuidstr);
		break;
	case HANDSFREE_AGW_SVCLASS_ID:
		DBG("Found Handsfree AG record");
		if (enabled.gateway && (device->gateway == NULL))
			device->gateway = gateway_init(device);
		break;
	case AUDIO_SINK_SVCLASS_ID:
		DBG("Found Audio Sink");
		if (device->sink == NULL)
			device->sink = sink_init(device);
		break;
	case AUDIO_SOURCE_SVCLASS_ID:
		DBG("Found Audio Source");
		if (device->source == NULL)
			device->source = source_init(device);
		break;
	case AV_REMOTE_SVCLASS_ID:
	case AV_REMOTE_TARGET_SVCLASS_ID:
		DBG("Found AV %s", uuid16 == AV_REMOTE_SVCLASS_ID ?
							"Remote" : "Target");
		if (device->control)
			control_update(device->control, uuid16);
		else
			device->control = control_init(device, uuid16);

		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	default:
		DBG("Unrecognized UUID: 0x%04X", uuid16);
		break;
	}
}

static int audio_probe(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t src, dst;
	struct audio_device *audio_dev;

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst, NULL);

	audio_dev = manager_get_device(&src, &dst, TRUE);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	g_slist_foreach(uuids, (GFunc) handle_uuid, audio_dev);

	return 0;
}

static void audio_remove(struct btd_device *device)
{
	struct audio_device *dev;
	const char *path;

	path = device_get_path(device);

	dev = manager_find_device(path, NULL, NULL, NULL, FALSE);
	if (!dev)
		return;

	devices = g_slist_remove(devices, dev);

	audio_device_unregister(dev);

}

static struct audio_adapter *audio_adapter_ref(struct audio_adapter *adp)
{
	adp->ref++;

	DBG("%p: ref=%d", adp, adp->ref);

	return adp;
}

static void audio_adapter_unref(struct audio_adapter *adp)
{
	adp->ref--;

	DBG("%p: ref=%d", adp, adp->ref);

	if (adp->ref > 0)
		return;

	adapters = g_slist_remove(adapters, adp);
	btd_adapter_unref(adp->btd_adapter);
	g_free(adp);
}

static struct audio_adapter *audio_adapter_create(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = g_new0(struct audio_adapter, 1);
	adp->btd_adapter = btd_adapter_ref(adapter);

	return audio_adapter_ref(adp);
}

static struct audio_adapter *audio_adapter_get(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = find_adapter(adapters, adapter);
	if (!adp) {
		adp = audio_adapter_create(adapter);
		if (!adp)
			return NULL;
		adapters = g_slist_append(adapters, adp);
	} else
		audio_adapter_ref(adp);

	return adp;
}

static void state_changed(struct btd_adapter *adapter, gboolean powered)
{
	struct audio_adapter *adp;
	static gboolean telephony = FALSE;
	GSList *l;

	DBG("%s powered %s", adapter_get_path(adapter),
						powered ? "on" : "off");

	/* ignore powered change, adapter is powering down */
	if (powered && adapter_powering_down(adapter))
		return;

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	adp->powered = powered;

	if (powered) {
		if (telephony == FALSE) {
			telephony_init();
			telephony = TRUE;
		}
		telephony_adapter_init(adapter);
		return;
	}

	/* telephony not initialized just ignore power down */
	if (telephony == FALSE)
		return;

	telephony_adapter_exit(adapter);

	for (l = adapters; l; l = l->next) {
		adp = l->data;

		if (adp->powered == TRUE)
			return;
	}

	telephony_exit();
	telephony = FALSE;
}

static int headset_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	headset_config_init(config);

	btd_adapter_register_powered_callback(adapter, state_changed);

	return 0;
}

static void headset_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	btd_adapter_unregister_powered_callback(adapter, state_changed);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	audio_adapter_unref(adp);
}

static int gateway_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	return 0;
}

static void gateway_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	audio_adapter_unref(adp);
}

static int a2dp_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	adapter_get_address(adapter, &src);

	err = a2dp_register(connection, &src, config);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void a2dp_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	adapter_get_address(adapter, &src);
	a2dp_unregister(&src);
	audio_adapter_unref(adp);
}

static int avrcp_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	adapter_get_address(adapter, &src);

	err = avrcp_register(connection, &src, config);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void avrcp_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	adapter_get_address(adapter, &src);
	avrcp_unregister(&src);
	audio_adapter_unref(adp);
}

static int media_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	adapter_get_address(adapter, &src);

	err = media_register(connection, path, &src);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void media_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	media_unregister(path);
	audio_adapter_unref(adp);
}

static struct btd_device_driver audio_driver = {
	.name	= "audio",
	.uuids	= BTD_UUIDS(HSP_HS_UUID, HFP_HS_UUID, HSP_AG_UUID, HFP_AG_UUID,
			ADVANCED_AUDIO_UUID, A2DP_SOURCE_UUID, A2DP_SINK_UUID,
			AVRCP_TARGET_UUID, AVRCP_REMOTE_UUID),
	.probe	= audio_probe,
	.remove	= audio_remove,
};

static struct btd_adapter_driver headset_server_driver = {
	.name	= "audio-headset",
	.probe	= headset_server_probe,
	.remove	= headset_server_remove,
};

static struct btd_adapter_driver gateway_server_driver = {
	.name	= "audio-gateway",
	.probe	= gateway_server_probe,
	.remove	= gateway_server_remove,
};

static struct btd_adapter_driver a2dp_server_driver = {
	.name	= "audio-a2dp",
	.probe	= a2dp_server_probe,
	.remove	= a2dp_server_remove,
};

static struct btd_adapter_driver avrcp_server_driver = {
	.name	= "audio-control",
	.probe	= avrcp_server_probe,
	.remove	= avrcp_server_remove,
};

static struct btd_adapter_driver media_server_driver = {
	.name	= "media",
	.probe	= media_server_probe,
	.remove	= media_server_remove,
};

int audio_manager_init(DBusConnection *conn, GKeyFile *conf,
							gboolean *enable_sco)
{
	char **list;
	int i;
	gboolean b;
	GError *err = NULL;

	connection = dbus_connection_ref(conn);

	if (!conf)
		goto proceed;

	config = conf;

	list = g_key_file_get_string_list(config, "General", "Enable",
						NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "Headset"))
			enabled.headset = TRUE;
		else if (g_str_equal(list[i], "Gateway"))
			enabled.gateway = TRUE;
		else if (g_str_equal(list[i], "Sink"))
			enabled.sink = TRUE;
		else if (g_str_equal(list[i], "Source"))
			enabled.source = TRUE;
		else if (g_str_equal(list[i], "Control"))
			enabled.control = TRUE;
		else if (g_str_equal(list[i], "Socket"))
			enabled.socket = TRUE;
		else if (g_str_equal(list[i], "Media"))
			enabled.media = TRUE;

	}
	g_strfreev(list);

	list = g_key_file_get_string_list(config, "General", "Disable",
						NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "Headset"))
			enabled.headset = FALSE;
		else if (g_str_equal(list[i], "Gateway"))
			enabled.gateway = FALSE;
		else if (g_str_equal(list[i], "Sink"))
			enabled.sink = FALSE;
		else if (g_str_equal(list[i], "Source"))
			enabled.source = FALSE;
		else if (g_str_equal(list[i], "Control"))
			enabled.control = FALSE;
		else if (g_str_equal(list[i], "Socket"))
			enabled.socket = FALSE;
		else if (g_str_equal(list[i], "Media"))
			enabled.media = FALSE;
	}
	g_strfreev(list);

	b = g_key_file_get_boolean(config, "General", "AutoConnect", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		auto_connect = b;

	b = g_key_file_get_boolean(config, "Headset", "HFP",
					&err);
	if (err)
		g_clear_error(&err);
	else
		enabled.hfp = b;

	err = NULL;
	i = g_key_file_get_integer(config, "Headset", "MaxConnected",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		max_connected_headsets = i;

proceed:
	if (enabled.socket)
		unix_init();

	if (enabled.media)
		btd_register_adapter_driver(&media_server_driver);

	if (enabled.headset)
		btd_register_adapter_driver(&headset_server_driver);

	if (enabled.gateway)
		btd_register_adapter_driver(&gateway_server_driver);

	if (enabled.source || enabled.sink)
		btd_register_adapter_driver(&a2dp_server_driver);

	if (enabled.control)
		btd_register_adapter_driver(&avrcp_server_driver);

	btd_register_device_driver(&audio_driver);

	*enable_sco = (enabled.gateway || enabled.headset);

	return 0;
}

void audio_manager_exit(void)
{
	/* Bail out early if we haven't been initialized */
	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
	connection = NULL;

	if (config) {
		g_key_file_free(config);
		config = NULL;
	}

	if (enabled.socket)
		unix_exit();

	if (enabled.media)
		btd_unregister_adapter_driver(&media_server_driver);

	if (enabled.headset)
		btd_unregister_adapter_driver(&headset_server_driver);

	if (enabled.gateway)
		btd_unregister_adapter_driver(&gateway_server_driver);

	if (enabled.source || enabled.sink)
		btd_unregister_adapter_driver(&a2dp_server_driver);

	if (enabled.control)
		btd_unregister_adapter_driver(&avrcp_server_driver);

	btd_unregister_device_driver(&audio_driver);
}

GSList *manager_find_devices(const char *path,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					const char *interface,
					gboolean connected)
{
	GSList *result = NULL;
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;

		if ((path && (strcmp(path, "")) && strcmp(dev->path, path)))
			continue;

		if ((src && bacmp(src, BDADDR_ANY)) && bacmp(&dev->src, src))
			continue;

		if ((dst && bacmp(dst, BDADDR_ANY)) && bacmp(&dev->dst, dst))
			continue;

		if (interface && !strcmp(AUDIO_HEADSET_INTERFACE, interface)
				&& !dev->headset)
			continue;

		if (interface && !strcmp(AUDIO_GATEWAY_INTERFACE, interface)
				&& !dev->gateway)
			continue;

		if (interface && !strcmp(AUDIO_SINK_INTERFACE, interface)
				&& !dev->sink)
			continue;

		if (interface && !strcmp(AUDIO_SOURCE_INTERFACE, interface)
				&& !dev->source)
			continue;

		if (interface && !strcmp(AUDIO_CONTROL_INTERFACE, interface)
				&& !dev->control)
			continue;

		if (connected && !audio_device_is_active(dev, interface))
			continue;

		result = g_slist_append(result, dev);
	}

	return result;
}

struct audio_device *manager_find_device(const char *path,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					const char *interface,
					gboolean connected)
{
	struct audio_device *result;
	GSList *l;

	l = manager_find_devices(path, src, dst, interface, connected);
	if (l == NULL)
		return NULL;

	result = l->data;
	g_slist_free(l);
	return result;
}

struct audio_device *manager_get_device(const bdaddr_t *src,
					const bdaddr_t *dst,
					gboolean create)
{
	struct audio_device *dev;
	struct btd_adapter *adapter;
	struct btd_device *device;
	char addr[18];
	const char *path;

	dev = manager_find_device(NULL, src, dst, NULL, FALSE);
	if (dev)
		return dev;

	if (!create)
		return NULL;

	ba2str(src, addr);

	adapter = manager_find_adapter(src);
	if (!adapter) {
		error("Unable to get a btd_adapter object for %s",
				addr);
		return NULL;
	}

	ba2str(dst, addr);

	device = adapter_get_device(connection, adapter, addr);
	if (!device) {
		error("Unable to get btd_device object for %s", addr);
		return NULL;
	}

	path = device_get_path(device);

	dev = audio_device_register(connection, device, path, src, dst);
	if (!dev)
		return NULL;

	devices = g_slist_append(devices, dev);

	return dev;
}

gboolean manager_allow_headset_connection(struct audio_device *device)
{
	GSList *l;
	int connected = 0;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;
		struct headset *hs = dev->headset;

		if (dev == device)
			continue;

		if (device && bacmp(&dev->src, &device->src) != 0)
			continue;

		if (!hs)
			continue;

		if (headset_get_state(dev) > HEADSET_STATE_DISCONNECTED)
			connected++;

		if (connected >= max_connected_headsets)
			return FALSE;
	}

	return TRUE;
}

void manager_set_fast_connectable(gboolean enable)
{
	GSList *l;

	if (enable && !manager_allow_headset_connection(NULL)) {
		DBG("Refusing enabling fast connectable");
		return;
	}

	for (l = adapters; l != NULL; l = l->next) {
		struct audio_adapter *adapter = l->data;

		if (btd_adapter_set_fast_connectable(adapter->btd_adapter,
								enable))
			error("Changing fast connectable for hci%d failed",
				adapter_get_dev_id(adapter->btd_adapter));
	}
}
