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
#include "manager.h"
#include "error.h"
#include "glib-helper.h"
#include "sdp-client.h"
#include "headset.h"
#include "telephony.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "sdpd.h"

#define AUDIO_TELEPHONY_INTERFACE "org.bluez.Telephony"
#define AUDIO_TELEPHONY_AGENT_INTERFACE "org.bluez.TelephonyAgent"

#define DEFAULT_HS_HS_CHANNEL 6
#define DEFAULT_HS_AG_CHANNEL 12
#define DEFAULT_HF_HS_CHANNEL 7
#define DEFAULT_HF_AG_CHANNEL 13

struct tel_agent;

struct tel_device {
	struct audio_device	*au_dev;
	char			*name;		/* agent DBus bus id */
	char			*path;		/* agent object path */
	struct default_agent	*properties;
	GIOChannel		*rfcomm;
	uint16_t		version;
	uint16_t		features;
};

struct default_agent {
	const char		*uuid;		/* agent property UUID */
	uint8_t			channel;
	const char		*r_uuid;
	uint16_t		r_class;
	uint16_t		r_profile;
	sdp_record_t		*(*record_init)(struct tel_agent *agent);
	BtIOConfirm		confirm;
	DBusPendingCallNotifyFunction connection_reply;
};

struct tel_agent {
	struct btd_adapter	*adapter;
	char			*name;		/* agent DBus bus id */
	char			*path;		/* agent object path */
	guint			watch;		/* agent disconnect watcher */
	uint16_t		version;
	uint16_t		features;
	struct default_agent	*properties;
	GIOChannel		*io;
	uint32_t		record_id;
};

static DBusConnection *connection = NULL;

static GSList *agents = NULL;	/* server list */

static void free_agent(struct tel_agent *agent)
{
	DBusMessage *msg;

	if (agent->record_id)
		remove_record_from_server(agent->record_id);

	if (agent->io) {
		g_io_channel_shutdown(agent->io, TRUE, NULL);
		g_io_channel_unref(agent->io);
	}

	if (agent->watch) {
		msg = dbus_message_new_method_call(agent->name, agent->path,
				AUDIO_TELEPHONY_AGENT_INTERFACE, "Release");
		dbus_message_set_no_reply(msg, TRUE);
		g_dbus_send_message(connection, msg);

		g_dbus_remove_watch(connection, agent->watch);
		agent->watch = 0;
	}

	g_free(agent->name);
	g_free(agent->path);
	g_free(agent);
}

static struct tel_agent *find_agent(struct btd_adapter *adapter,
					const char *sender, const char *path,
					const char *uuid)
{
	GSList *l;

	for (l = agents; l; l = l->next) {
		struct tel_agent *agent = l->data;

		if (agent->adapter != adapter)
			continue;

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

void *telephony_agent_by_uuid(void *adapter, const char *uuid)
{
	return find_agent(adapter, NULL, NULL, uuid);
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
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(dev->name, dev->path,
			AUDIO_TELEPHONY_AGENT_INTERFACE, "NewConnection");

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UNIX_FD, &fd);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Device", DBUS_TYPE_OBJECT_PATH,
						&dev->au_dev->path);
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING,
						&dev->properties->uuid);
	dict_append_entry(&dict, "Version", DBUS_TYPE_UINT16, &dev->version);

	if (dev->features != 0xFFFF)
		dict_append_entry(&dict, "Features", DBUS_TYPE_UINT16,
							&dev->features);

	dbus_message_iter_close_container(&iter, &dict);

	if (dbus_connection_send_with_reply(connection, msg, &call, -1)
			== FALSE) {
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_pending_call_set_notify(call, notify, dev, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return TRUE;
}

static gboolean hs_dev_disconnect_cb(GIOChannel *chan, GIOCondition cond,
						struct tel_device *dev)
{
	if (cond & G_IO_NVAL)
		return FALSE;

	headset_set_state(dev->au_dev, HEADSET_STATE_DISCONNECTED);

	return FALSE;
}

static void hs_newconnection_reply(DBusPendingCall *call, void *user_data)
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
					(GIOFunc) hs_dev_disconnect_cb, dev);
		headset_slc_complete(dev->au_dev);
		goto done;
	}

	DBG("Agent reply: %s", derr.message);

	dbus_error_free(&derr);
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
	int sk;

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

	sdp_uuid16_create(&uuid, dev->properties->r_profile);

	sdp_get_profile_descs(recs->data, &profiles);
	if (profiles == NULL)
		goto failed;

	desc = profiles->data;

	if (sdp_uuid16_cmp(&desc->uuid, &uuid) == 0)
		dev->version = desc->version;

	sdp_list_free(profiles, free);

	sk = g_io_channel_unix_get_fd(dev->rfcomm);

	if (agent_sendfd(dev, sk, dev->properties->connection_reply) == FALSE) {
		error("Failed to send RFComm socket to agent %s, path %s",
							dev->name, dev->path);
		goto failed;
	}

	return;

failed:
	headset_set_state(dev->au_dev, HEADSET_STATE_DISCONNECTED);
}

void *telephony_device_connecting(GIOChannel *io, void *telephony_device,
								void *agent)
{
	struct audio_device *device = telephony_device;
	struct tel_device *dev;
	struct tel_agent *ag = agent;
	uuid_t uuid;
	int err;

	dev = g_new0(struct tel_device, 1);
	dev->name = g_strdup(ag->name);
	dev->path = g_strdup(ag->path);
	dev->properties = ag->properties;
	dev->au_dev = telephony_device;
	dev->rfcomm = io;
	dev->features = 0xFFFF;

	sdp_uuid16_create(&uuid, dev->properties->r_class);

	err = bt_search_service(&device->src, &device->dst, &uuid,
						get_record_cb, dev, NULL);
	if (err < 0) {
		g_free(dev->name);
		g_free(dev->path);
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

	g_free(dev->name);
	g_free(dev->path);
	g_free(dev);
}

void telephony_device_disconnected(void *telephony_device)
{
	DBG("telephony-dbus: device %p disconnected", telephony_device);
}

static sdp_record_t *hsp_ag_record(struct tel_agent * agent)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_list_t *aproto, *proto[2];
	sdp_data_t *channel;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = agent->version;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &agent->properties->channel);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Headset Audio Gateway", 0, 0);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *hfp_ag_record(struct tel_agent * agent)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *channel, *features;
	uint8_t netid;
	uint16_t sdpfeat;
	sdp_data_t *network;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	netid = agent->features & AG_FEATURE_REJECT_A_CALL ? 1 : 0;
	network = sdp_data_alloc(SDP_UINT8, &netid);
	if (!network) {
		sdp_record_free(record);
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = agent->version;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &agent->properties->channel);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdpfeat = agent->features & 0x1F;
	features = sdp_data_alloc(SDP_UINT16, &sdpfeat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(record, SDP_ATTR_EXTERNAL_NETWORK, network);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static void headset_auth_cb(DBusError *derr, void *user_data)
{
	struct audio_device *device = user_data;
	GError *err = NULL;
	GIOChannel *io;

	if (device->hs_preauth_id) {
		g_source_remove(device->hs_preauth_id);
		device->hs_preauth_id = 0;
	}

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}

	io = headset_get_rfcomm(device);

	if (!bt_io_accept(io, headset_connect_cb, device, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}
}

static gboolean hs_preauth_cb(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct audio_device *device = user_data;

	DBG("Headset disconnected during authorization");

	audio_device_cancel_authorization(device, headset_auth_cb, device);

	headset_set_state(device, HEADSET_STATE_DISCONNECTED);

	device->hs_preauth_id = 0;

	return FALSE;
}

static void ag_confirm(GIOChannel *chan, gpointer data)
{
	struct tel_agent *agent = data;
	struct audio_device *device;
	gboolean hfp_active;
	bdaddr_t src, dst;
	int perr;
	GError *err = NULL;
	uint8_t ch;

	bt_io_get(chan, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_CHANNEL, &ch,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	/* TODO: to remove ? */
	if (ch == DEFAULT_HS_AG_CHANNEL)
		hfp_active = FALSE;
	else
		hfp_active = TRUE;

	device = manager_get_device(&src, &dst, TRUE);
	if (!device)
		goto drop;

	if (!manager_allow_headset_connection(device)) {
		DBG("Refusing headset: too many existing connections");
		goto drop;
	}

	if (!device->headset) {
		btd_device_add_uuid(device->btd_dev, agent->properties->r_uuid);
		if (!device->headset)
			goto drop;
	}

	if (headset_get_state(device) > HEADSET_STATE_DISCONNECTED) {
		DBG("Refusing new connection since one already exists");
		goto drop;
	}

	headset_set_hfp_active(device, hfp_active);
	headset_set_rfcomm_initiator(device, TRUE);
	headset_set_connecting_uuid(device, agent->properties->uuid);

	if (headset_connect_rfcomm(device, chan) < 0) {
		error("headset_connect_rfcomm failed");
		goto drop;
	}

	headset_set_state(device, HEADSET_STATE_CONNECTING);

	perr = audio_device_request_authorization(device,
						agent->properties->uuid,
						headset_auth_cb, device);
	if (perr < 0) {
		DBG("Authorization denied: %s", strerror(-perr));
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}

	device->hs_preauth_id = g_io_add_watch(chan,
					G_IO_NVAL | G_IO_HUP | G_IO_ERR,
					hs_preauth_cb, device);

#if 0
	device->auto_connect = auto_connect;
#endif

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

static struct default_agent default_properties[] = {
	{ HSP_AG_UUID,
		DEFAULT_HS_AG_CHANNEL,
		HSP_HS_UUID,
		HEADSET_SVCLASS_ID,
		HEADSET_PROFILE_ID,
		hsp_ag_record,
		ag_confirm,
		hs_newconnection_reply },
	{ HFP_AG_UUID,
		DEFAULT_HF_AG_CHANNEL,
		HFP_HS_UUID,
		HANDSFREE_SVCLASS_ID,
		HANDSFREE_PROFILE_ID,
		hfp_ag_record,
		ag_confirm,
		hs_newconnection_reply },
};

static void agent_disconnect_cb(DBusConnection *conn, void *user_data)
{
	struct tel_agent *agent = user_data;

	DBG("Agent exited without calling Unregister");

	agent->watch = 0;
	agents = g_slist_remove(agents, agent);
	free_agent(agent);
}

static struct tel_agent *agent_new(struct btd_adapter *adapter,
					const char *sender, const char *path,
					const char *uuid, uint16_t version,
					uint16_t features)
{
	struct tel_agent *agent = NULL;
	unsigned int i;

	for (i = 0; i < sizeof(default_properties) /
				sizeof(struct default_agent) ; i++) {
		if (strcasecmp(uuid, default_properties[i].uuid) == 0) {
			agent = g_new0(struct tel_agent, 1);
			agent->adapter = adapter;
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
	struct btd_adapter *adapter = data;
	DBusMessageIter args, props;
	const char *sender, *path, *uuid;
	uint16_t version = 0;
	uint16_t features = 0xFFFF;
	struct tel_agent *agent;
	sdp_record_t *record;
	bdaddr_t src;
	gboolean master = TRUE;
	GError *err = NULL;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	if (find_agent(adapter, sender, path, NULL) != NULL)
		return btd_error_already_exists(msg);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	if (parse_properties(&props, &uuid, &version, &features) < 0)
		return btd_error_invalid_args(msg);

	if (find_agent(adapter, NULL, NULL, uuid) != NULL)
		return btd_error_already_exists(msg);

	/* initialize agent properties */
	agent = agent_new(adapter, sender, path, uuid, version, features);
	if (agent == NULL)
		return btd_error_invalid_args(msg);

	agent->watch = g_dbus_add_disconnect_watch(conn, sender,
							agent_disconnect_cb,
							agent, NULL);

	record = agent->properties->record_init(agent);
	if (!record) {
		error("Unable to allocate new service record");
		return btd_error_failed(msg, "Unable to allocate new service " \
						"record");
	}

	DBG("Register agent : %s%s for %s version 0x%04X with features 0x%02X",
					sender, path, uuid, version, features);

	/* start RFComm agent server */
	adapter_get_address(adapter, &src);

	agent->io = bt_io_listen(BT_IO_RFCOMM, NULL, agent->properties->confirm,
				agent, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_CHANNEL, agent->properties->channel,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (agent->io == NULL) {
		error("Unable to register server");
		sdp_record_free(record);
		free_agent(agent);
		return btd_error_failed(msg, "Failed to register server");
	}

	/* advertise agent sdp record */
	if (add_record_to_server(&src, record) < 0) {
		error("Unable to register service record");
		sdp_record_free(record);
		free_agent(agent);
		return btd_error_failed(msg, "Failed to register sdp record");
	}

	agent->record_id = record->handle;

	agents = g_slist_append(agents, agent);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	const char *sender, *path;
	struct tel_agent *agent;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	sender = dbus_message_get_sender(msg);

	agent = find_agent(adapter, sender, path, NULL);
	if (agent == NULL)
		return btd_error_does_not_exist(msg);

	agents = g_slist_remove(agents, agent);

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

int telephony_adapter_init(void *adapter)
{
	DBG("adapter: %p", adapter);

	return register_interface(adapter);
}

void telephony_adapter_exit(void *adapter)
{
	struct tel_agent *agent;

	DBG("adapter: %p", adapter);

	unregister_interface(adapter);

	while ((agent = find_agent(adapter, NULL, NULL, NULL)) != NULL) {
		agents = g_slist_remove(agents, agent);
		free_agent(agent);
	}
}

int telephony_init(void)
{
	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	return 0;
}

void telephony_exit(void)
{
	DBG("");

	dbus_connection_unref(connection);
	connection = NULL;
}
