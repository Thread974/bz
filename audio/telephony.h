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

#include <stdint.h>
#include <errno.h>
#include <glib.h>

/* HFP feature bits */
#define AG_FEATURE_THREE_WAY_CALLING		0x0001
#define AG_FEATURE_EC_ANDOR_NR			0x0002
#define AG_FEATURE_VOICE_RECOGNITION		0x0004
#define AG_FEATURE_INBAND_RINGTONE		0x0008
#define AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG	0x0010
#define AG_FEATURE_REJECT_A_CALL		0x0020
#define AG_FEATURE_ENHANCED_CALL_STATUS		0x0040
#define AG_FEATURE_ENHANCED_CALL_CONTROL	0x0080
#define AG_FEATURE_EXTENDED_ERROR_RESULT_CODES	0x0100

#define HF_FEATURE_EC_ANDOR_NR			0x0001
#define HF_FEATURE_CALL_WAITING_AND_3WAY	0x0002
#define HF_FEATURE_CLI_PRESENTATION		0x0004
#define HF_FEATURE_VOICE_RECOGNITION		0x0008
#define HF_FEATURE_REMOTE_VOLUME_CONTROL	0x0010
#define HF_FEATURE_ENHANCED_CALL_STATUS		0x0020
#define HF_FEATURE_ENHANCED_CALL_CONTROL	0x0040

/* Notify telephony-*.c of connected/disconnected devices. Implemented by
 * telephony-*.c
 */
void *telephony_device_connecting(GIOChannel *io, void *telephony_device,
								void *agent);
void telephony_device_connected(void *telephony_device);
void telephony_device_disconnect(void *slc);
void telephony_device_disconnected(void *telephony_device);
void telephony_set_media_transport_path(void *slc, const char *path);
const char *telephony_get_agent_name(void *slc);

void *telephony_agent_by_uuid(void *adapter, const char *uuid);

int telephony_adapter_init(void *adapter);
void telephony_adapter_exit(void *adapter);
int telephony_init(void);
void telephony_exit(void);
