/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Frederic Danis <frederic.danis@intel.com>
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

#include <stdlib.h>

#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "btio.h"
#include "log.h"
#include "device.h"
#include "error.h"
#include "glib-helper.h"
#include "sdp-client.h"
#include "headset.h"
#include "telephony.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"

#define AUDIO_TELEPHONY_INTERFACE "org.bluez.Telephony"

#define DEFAULT_HS_HS_CHANNEL 6
#define DEFAULT_HF_HS_CHANNEL 7

struct telsrv {
	GSList *servers;	/* server list */
};

struct tel_device {
	struct tel_agent	*agent;
	struct audio_device	*au_dev;
	GIOChannel		*rfcomm;
	uint16_t		version;
	uint16_t		features;
};

struct default_agent {
	char			*uuid;		/* agent property UUID */
	uint8_t			channel;
	const char		*r_uuid;
	uint16_t		r_class;
	uint16_t		r_profile;
};

struct tel_agent {
	char			*name;		/* agent DBus bus id */
	char			*path;		/* agent object path */
	uint16_t		version;
	uint16_t		features;
	struct default_agent	*properties;
};

static DBusConnection *connection = NULL;

struct telsrv telsrv;

static void free_agent(struct tel_agent *agent)
{
	g_free(agent->name);
	g_free(agent->path);
	g_free(agent);
}

static struct tel_agent *find_agent(const char *sender, const char *path,
						const char *uuid)
{
	GSList *l;

	for (l = telsrv.servers; l; l = l->next) {
		struct tel_agent *agent = l->data;

		if (sender && g_strcmp0(agent->name, sender) != 0)
			continue;

		if (path && g_strcmp0(agent->path, path) != 0)
			continue;

		if (uuid && g_strcmp0(agent->properties->uuid, uuid) != 0)
			continue;

		return agent;
	}

	return NULL;
}

static int parse_properties(DBusMessageIter *props, const char **uuid,
				uint16_t *version, uint16_t *features)
{
	gboolean has_uuid = FALSE;

	while (dbus_message_iter_get_arg_type(props) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(props, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);
		if (strcasecmp(key, "UUID") == 0) {
			if (var != DBUS_TYPE_STRING)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, uuid);
			has_uuid = TRUE;
		} else if (strcasecmp(key, "Version") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, version);
		} else if (strcasecmp(key, "Features") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, features);
		}

		dbus_message_iter_next(props);
	}

	return (has_uuid) ? 0 : -EINVAL;
}

static int dev_close(struct tel_device *dev)
{
	int sock;

	if (dev->rfcomm) {
		sock = g_io_channel_unix_get_fd(dev->rfcomm);
		shutdown(sock, SHUT_RDWR);
	}

	return 0;
}

static gboolean agent_sendfd(struct tel_device *dev, int fd,
				DBusPendingCallNotifyFunction notify)
{
	struct tel_agent *agent = dev->agent;
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	char *str;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.TelephonyAgent", "NewConnection");

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UNIX_FD, &fd);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = g_strdup(agent->properties->uuid);
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &str);
	g_free(str);

	dict_append_entry(&dict, "Version", DBUS_TYPE_UINT16, &dev->version);

	if (dev->features != 0xFFFF)
		dict_append_entry(&dict, "Features", DBUS_TYPE_UINT16,
							&dev->features);

	dbus_message_iter_close_container(&iter, &dict);

	if (dbus_connection_send_with_reply(connection, msg, &call, -1)
			== FALSE)
		return FALSE;

	dbus_pending_call_set_notify(call, notify, dev, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return TRUE;
}

static gboolean agent_disconnect_cb(GIOChannel *chan, GIOCondition cond,
						struct tel_device *dev)
{
	if (cond & G_IO_NVAL)
		return FALSE;

	headset_set_state(dev->au_dev, HEADSET_STATE_DISCONNECTED);

	return FALSE;
}

static void newconnection_reply(DBusPendingCall *call, void *user_data)
{
	struct tel_device *dev = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	if (!dev->rfcomm) {
		DBG("RFCOMM disconnected from server before agent reply");
		goto done;
	}

	dbus_error_init(&derr);
	if (!dbus_set_error_from_message(&derr, reply)) {
		DBG("Agent reply: file descriptor passed successfully");
		g_io_add_watch(dev->rfcomm, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) agent_disconnect_cb, dev);
		headset_slc_complete(dev->au_dev);
		goto done;
	}

	DBG("Agent reply: %s", derr.message);

	dbus_error_free(&derr);
	dev_close(dev);
	headset_set_state(dev->au_dev, HEADSET_STATE_DISCONNECTED);

done:
	dbus_message_unref(reply);
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct tel_device *dev = user_data;
	sdp_data_t *sdpdata;
	uuid_t uuid;
	sdp_list_t *profiles;
	sdp_profile_desc_t *desc;
	int sk, ret;

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
					-err);
		goto failed;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto failed;
	}

	sdpdata = sdp_data_get(recs->data, SDP_ATTR_SUPPORTED_FEATURES);
	if (sdpdata && sdpdata->dtd == SDP_UINT16)
		dev->features = sdpdata->val.uint16;

	sdp_uuid16_create(&uuid, dev->agent->properties->r_profile);

	sdp_get_profile_descs(recs->data, &profiles);
	if (profiles == NULL)
		goto failed;

	desc = profiles->data;

	if (sdp_uuid16_cmp(&desc->uuid, &uuid) == 0)
		dev->version = desc->version;

	sdp_list_free(profiles, free);

	sk = g_io_channel_unix_get_fd(dev->rfcomm);

	ret = agent_sendfd(dev, sk, newconnection_reply);

	return;

failed:
	headset_set_state(dev->au_dev, HEADSET_STATE_DISCONNECTED);
}

void *telephony_device_connecting(GIOChannel *io, void *telephony_device)
{
	struct audio_device *device = telephony_device;
	struct tel_device *dev;
	const char *agent_uuid;
	struct tel_agent *agent;
	uuid_t uuid;
	int err;

	/*TODO: check for HS roles */
	if (headset_get_hfp_active(device))
		agent_uuid = HFP_AG_UUID;
	else
		agent_uuid = HSP_AG_UUID;

	agent = find_agent(NULL, NULL, agent_uuid);
	if (agent == NULL) {
		error("No agent registered for %s", agent_uuid);
		return NULL;
	}

	dev = g_new0(struct tel_device, 1);
	dev->agent = agent;
	dev->au_dev = telephony_device;
	dev->rfcomm = io;
	dev->features = 0xFFFF;

	sdp_uuid16_create(&uuid, agent->properties->r_class);

	err = bt_search_service(&device->src, &device->dst, &uuid,
						get_record_cb, dev, NULL);
	if (err < 0) {
		g_free(dev);
		return NULL;
	}

	return dev;
}

void telephony_device_connected(void *telephony_device)
{
	DBG("telephony-dbus: device %p connected", telephony_device);
}

void telephony_device_disconnect(void *slc)
{
	struct tel_device *dev = slc;

	dev_close(dev);
}

void telephony_device_disconnected(void *telephony_device)
{
	DBG("telephony-dbus: device %p disconnected", telephony_device);
}

gboolean telephony_get_ready_state(void)
{
	return find_agent(NULL, NULL, HFP_AG_UUID) ? TRUE : FALSE;
}

uint32_t telephony_get_ag_features(void)
{
	return 0;
}

static struct default_agent default_properties[] = {
	{ HSP_HS_UUID,
		DEFAULT_HS_HS_CHANNEL,
		HSP_AG_UUID,
		HEADSET_AGW_SVCLASS_ID,
		HEADSET_PROFILE_ID },
	{ HSP_AG_UUID,
		DEFAULT_HS_AG_CHANNEL,
		HSP_HS_UUID,
		HEADSET_SVCLASS_ID,
		HEADSET_PROFILE_ID },
	{ HFP_HS_UUID,
		DEFAULT_HF_HS_CHANNEL,
		HFP_AG_UUID,
		HANDSFREE_AGW_SVCLASS_ID,
		HANDSFREE_PROFILE_ID },
	{ HFP_AG_UUID,
		DEFAULT_HF_AG_CHANNEL,
		HFP_HS_UUID,
		HANDSFREE_SVCLASS_ID,
		HANDSFREE_PROFILE_ID }
};

static struct tel_agent *agent_new(const char *sender, const char *path,
					const char *uuid, uint16_t version,
					uint16_t features)
{
	struct tel_agent *agent = NULL;
	unsigned int i;

	for (i = 0; i < sizeof(default_properties) /
				sizeof(struct default_agent) ; i++) {
		if (strcasecmp(uuid, default_properties[i].uuid) == 0) {
			agent = g_new0(struct tel_agent, 1);
			agent->properties = &default_properties[i];
			agent->name = g_strdup(sender);
			agent->path = g_strdup(path);
			agent->version = version;
			agent->features = features;
			break;
		}
	}

	return agent;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter args, props;
	const char *sender, *path, *uuid;
	uint16_t version = 0;
	uint16_t features = 0xFFFF;
	struct tel_agent *agent;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	if (find_agent(sender, path, NULL) != NULL)
		return btd_error_already_exists(msg);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	if (parse_properties(&props, &uuid, &version, &features) < 0)
		return btd_error_invalid_args(msg);

	if (find_agent(NULL, NULL, uuid) != NULL)
		return btd_error_already_exists(msg);

	/* initialize agent properties */
	agent = agent_new(sender, path, uuid, version, features);
	if (agent == NULL)
		return btd_error_invalid_args(msg);

	DBG("Register agent : %s%s for %s version 0x%04X with features 0x%02X",
					sender, path, uuid, version, features);

	telsrv.servers = g_slist_append(telsrv.servers, agent);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	const char *sender, *path;
	struct tel_agent *agent;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	sender = dbus_message_get_sender(msg);

	agent = find_agent(sender, path, NULL);
	if (agent == NULL)
		return btd_error_does_not_exist(msg);

	telsrv.servers = g_slist_remove(telsrv.servers, agent);

	DBG("Unregister agent : %s%s", sender, path);

	free_agent(agent);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable telsrv_methods[] = {
	{ "RegisterAgent", "oa{sv}", "", register_agent },
	{ "UnregisterAgent", "o", "", unregister_agent },
	{ NULL, NULL, NULL, NULL }
};

static void path_unregister(void *data)
{
	DBG("Unregistered interface %s", AUDIO_TELEPHONY_INTERFACE);
}

static int register_interface(void *adapter)
{
	const char *path;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -1;

	path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(connection, path,
					AUDIO_TELEPHONY_INTERFACE,
					telsrv_methods, NULL,
					NULL, adapter, path_unregister)) {
		error("D-Bus failed to register %s interface",
				AUDIO_TELEPHONY_INTERFACE);
		return -1;
	}

	DBG("Registered interface %s", AUDIO_TELEPHONY_INTERFACE);

	return 0;
}

static void unregister_interface(void *adapter)
{
	g_dbus_unregister_interface(connection, adapter_get_path(adapter),
			AUDIO_TELEPHONY_INTERFACE);
}

int telephony_init(void *adapter)
{
	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	return register_interface(adapter);
}

void telephony_exit(void *adapter)
{
	DBG("");

	unregister_interface(adapter);

	dbus_connection_unref(connection);
	connection = NULL;
}
