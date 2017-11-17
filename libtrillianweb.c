/*
 *   Trillian Web plugin for libpurple
 *   Copyright (C) 2017 Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
#include <unistd.h>
#endif
#include <errno.h>

#ifdef ENABLE_NLS
#      define GETTEXT_PACKAGE "purple-discord"
#      include <glib/gi18n-lib.h>
#	ifdef _WIN32
#		ifdef LOCALEDIR
#			unset LOCALEDIR
#		endif
#		define LOCALEDIR  wpurple_locale_dir()
#	endif
#else
#      define _(a) (a)
#      define N_(a) (a)
#endif

#include "purple.h"
#include "glibcompat.h"
#include "purplecompat.h"
#include "http.h"

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#define TRILLIANWEB_PLUGIN_ID "prpl-eionrobb-trillianweb"
#ifndef TRILLIANWEB_PLUGIN_VERSION
#define TRILLIANWEB_PLUGIN_VERSION "0.1"
#endif
#define TRILLIANWEB_PLUGIN_WEBSITE "https://github.com/EionRobb/purple-trillianweb"



typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	PurpleHttpKeepalivePool *keepalive_pool;
	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	
	gchar *host;
	gchar *session;
	guint64 sequence;
} TrillianAccount;

typedef GHashTable TrillianWebRequestData;
typedef GHashTable TrillianWebResponseData;
typedef void (*TrillianProxyCallbackFunc)(TrillianAccount *ta, TrillianWebResponseData *data, gpointer user_data);

typedef struct {
	TrillianAccount *ta;
	TrillianProxyCallbackFunc callback;
	gpointer user_data;
} TrillianProxyConnection;




static TrillianWebRequestData *
trillian_requestdata_new()
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static void
trillian_requestdata_add(TrillianWebRequestData *request, const gchar *key, const gchar *value)
{
	g_hash_table_insert(request, g_strdup(key), g_strdup(value));
}

static const gchar *
trillian_requestdata_get(TrillianWebRequestData *request, const gchar *key)
{
	return g_hash_table_lookup(request, key);
}

static gchar *
trillian_requestdata_get_string(TrillianWebRequestData *request)
{
	GHashTableIter iter;
	gpointer key, value;
	GString *str = g_string_new("");

	g_hash_table_iter_init(&iter, request);
	while (g_hash_table_iter_next(&iter, &key, &value))
	{
		g_string_append(str, purple_url_encode(key));
		g_string_append_c(str, '=');
		g_string_append(str, purple_url_encode(value));
		g_string_append_c(str, '&');
	}
	
	return g_string_free(str, FALSE);
}

static void
trillian_requestdata_free(TrillianWebRequestData *request)
{
	g_hash_table_unref(request);
}

static void
trillianweb_response_callback(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	const gchar *body;
	gsize body_len;
	TrillianProxyConnection *conn = user_data;
	GHashTable *data = trillian_requestdata_new();
	guint i;
	
	conn->ta->http_conns = g_slist_remove(conn->ta->http_conns, http_conn);
	if (purple_http_response_is_successful(response)) {

		body = purple_http_response_get_data(response, &body_len);
		
		gchar **tokens = g_strsplit_set(body, "&", -1);
		for (i = 0; tokens[i]; i++) {
			gchar **keyvals = g_strsplit_set(tokens[i], "=", 2);
			
			g_hash_table_insert(data, g_uri_unescape_string(keyvals[0], NULL), g_uri_unescape_string(keyvals[1], NULL));
			
			g_strfreev(keyvals);
		}
		g_strfreev(tokens);
		
		//purple_debug_misc("yahoo", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ta, data, conn->user_data);
		}
		
		g_hash_table_unref(data);
	}
	g_free(conn);
}

static PurpleHttpRequest *
trillianweb_prepare_fetch_url(TrillianAccount *ta, const gchar *url, const gchar *postdata)
{
	purple_debug_info("trillianweb", "Fetching url %s\n", url);

	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	
	if (postdata) {
		//purple_debug_info("trillianweb", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
		purple_http_request_set_method(request, "POST");
	}
	
	purple_http_request_set_keepalive_pool(request, ta->keepalive_pool);

	return request;
}

static gchar *trillian_requestdata_get_string(TrillianWebRequestData *request);

static void
trillian_fetch_url(TrillianAccount *ta, const gchar *url, TrillianWebRequestData *data, TrillianProxyCallbackFunc callback, gpointer user_data)
{
	PurpleHttpConnection *http_conn;
	TrillianProxyConnection *conn;
	PurpleHttpRequest *request;
	gchar *postdata;
	gboolean free_url = FALSE;

	if (purple_account_is_disconnected(ta->account)) return;

	conn = g_new0(TrillianProxyConnection, 1);
	conn->ta = ta;
	conn->callback = callback;
	conn->user_data = user_data;
	
	if (ta->session) {
		trillian_requestdata_add(data, "xsession", ta->session);
	}
	if (ta->sequence) {
		gchar *sequence_str = g_strdup_printf("%" G_GUINT64_FORMAT, ++ta->sequence);
		trillian_requestdata_add(data, "xsequence", sequence_str);
		g_free(sequence_str);
	}
	
	trillian_requestdata_add(data, "xusername", purple_account_get_username(ta->account));
	trillian_requestdata_add(data, "xpassword", purple_connection_get_password(ta->pc));
	
	if (url == NULL) {
		url = g_strdup_printf("https://%s/trillian", ta->host ? ta->host : "octopus.trillian.im");
		free_url = TRUE;
	}

	postdata = trillian_requestdata_get_string(data);
	
	request = trillianweb_prepare_fetch_url(ta, url, postdata);

	http_conn = purple_http_request(ta->pc, request, trillianweb_response_callback, conn);
	purple_http_request_unref(request);
	
	g_free(postdata);
	if (free_url) {
		g_free((gpointer) url);
	}
	
	ta->http_conns = g_slist_prepend(ta->http_conns, http_conn);
}

static void trillianweb_poll(TrillianAccount *ta);
static void trillianweb_process_response(TrillianAccount *, TrillianWebRequestData *, gpointer);

static void
trillianweb_get_avatar(TrillianAccount *ta, const gchar *username)
{
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "avatarGet");
	trillian_requestdata_add(data, "username", username);
	trillian_requestdata_add(data, "medium", "ASTRA");
	trillian_requestdata_add(data, "identity", "default");
	
	trillian_fetch_url(ta, NULL, data, trillianweb_process_response, NULL);
	
	trillian_requestdata_free(data);
}

static void
trillianweb_process_chunk(TrillianAccount *ta, TrillianWebRequestData *chunk, gpointer user_data)
{
	const gchar *e = trillian_requestdata_get(chunk, "e");
	
	if (purple_strequal(e, "session_nop")) {
		return;
	}
	
	if (purple_strequal(e, "session_info")) {
		ta->host = g_strdup(trillian_requestdata_get(chunk, "ip"));
		ta->session = g_strdup(trillian_requestdata_get(chunk, "session"));
		ta->sequence = g_ascii_strtoull(trillian_requestdata_get(chunk, "sequence"), NULL, 0);
		
	} else if (purple_strequal(e, "contactlist_update")) {
		const gchar *username = trillian_requestdata_get(chunk, "username");
		const gchar *status = trillian_requestdata_get(chunk, "status");
		const gchar *statusmsg = trillian_requestdata_get(chunk, "statusmsg");
		purple_protocol_got_user_status(ta->account, username, status, "message", statusmsg, NULL);
		
		const gchar *iconhash = trillian_requestdata_get(chunk, "iconhash");
		PurpleBuddyIcon *icon = purple_buddy_icons_find(ta->account, username);
		if ((!icon && iconhash) || !purple_strequal(purple_buddy_icon_get_checksum(icon), iconhash)) {
			trillianweb_get_avatar(ta, username);
		}
		
	} else if (purple_strequal(e, "message_receive")) {
		const gchar *type = trillian_requestdata_get(chunk, "type");
		const gchar *name = trillian_requestdata_get(chunk, "name");
		const gchar *msg_base64 = trillian_requestdata_get(chunk, "msg");
		gsize msg_len;
		gchar *msg = (gchar *)g_base64_decode(msg_base64, &msg_len);
		const gchar *time = trillian_requestdata_get(chunk, "time");
		gint64 timestamp = g_ascii_strtoll(time, NULL, 0);
		PurpleMessageFlags msg_flags;
		
		if (purple_strequal(type, "incoming_privateMessage")) {
			msg_flags = PURPLE_MESSAGE_RECV;
			purple_serv_got_im(ta->pc, name, msg, msg_flags, timestamp);
		}
		
	} else if (purple_strequal(e, "contactlist_initialize")) {
		gsize xml_len;
		gchar *contactlist_xml = (gchar *)g_base64_decode(trillian_requestdata_get(chunk, "contactlist"), &xml_len);
		PurpleXmlNode *cl = purple_xmlnode_from_str(contactlist_xml, xml_len);
		PurpleXmlNode *s = purple_xmlnode_get_child(cl, "s");
		PurpleXmlNode *g = purple_xmlnode_get_child(s, "g");
		
		do {
			PurpleXmlNode *t = purple_xmlnode_get_child(g, "t");
			gchar *group_name = purple_xmlnode_get_data(t);
			PurpleGroup *group = purple_blist_find_group(purple_url_decode(group_name));
			if (!group) {
				group = purple_group_new(purple_url_decode(group_name));
			}
			g_free(group_name);
			
			PurpleXmlNode *c = purple_xmlnode_get_child(g, "c");
			do {
				const gchar *medium = purple_xmlnode_get_attrib(c, "m");
				if (purple_strequal(medium, "ASTRA")) {
					const gchar *username = purple_xmlnode_get_attrib(c, "r");
					if (!purple_blist_find_buddy(ta->account, username)) {
						gchar *alias = purple_xmlnode_get_data(c);
						PurpleBuddy *buddy = purple_buddy_new(ta->account, username, purple_url_decode(alias));
						purple_blist_add_buddy(buddy, NULL, group, NULL);
						g_free(alias);
					}
				}
			} while ((c = purple_xmlnode_get_next_twin(c)));
			
			PurpleXmlNode *gc = purple_xmlnode_get_child(g, "gc");
			do {
				const gchar *medium = purple_xmlnode_get_attrib(gc, "m");
				if (purple_strequal(medium, "ASTRA")) {
					const gchar *name = purple_xmlnode_get_attrib(gc, "n");
					gchar *displayname = purple_xmlnode_get_data(gc);
					PurpleChat *chat = purple_blist_find_chat(ta->account, purple_url_decode(name));
					if (!chat) {
						GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
						g_hash_table_replace(components, g_strdup("name"), g_strdup(purple_url_decode(name)));
						
						PurpleChat *chat = purple_chat_new(ta->account, purple_url_decode(displayname), components);
						purple_blist_add_chat(chat, group, NULL);
					} else {
						purple_blist_alias_chat(chat, purple_url_decode(displayname));
					}
					g_free(displayname);
				}
			} while ((gc = purple_xmlnode_get_next_twin(gc)));
		} while ((g = purple_xmlnode_get_next_twin(g)));
		
		purple_xmlnode_free(cl);
		g_free(contactlist_xml);
		
	} else if (purple_strequal(e, "contactlist_add")) {
		const gchar *medium = trillian_requestdata_get(chunk, "medium");
		if (medium == NULL) {
			// Probably a group adding?
		} else if (purple_strequal(medium, "ASTRA")) {
			const gchar *username = trillian_requestdata_get(chunk, "username");
			if (!purple_blist_find_buddy(ta->account, username)) {
				const gchar *group_name = trillian_requestdata_get(chunk, "group");
				const gchar *displayname = trillian_requestdata_get(chunk, "displayname");
				
				PurpleGroup *group = purple_blist_find_group(group_name);
				if (!group) {
					group = purple_group_new(group_name);
				}
				
				PurpleBuddy *buddy = purple_buddy_new(ta->account, username, displayname);
				purple_blist_add_buddy(buddy, NULL, group, NULL);
			}
		}
		
	} else if (purple_strequal(e, "groupchat_add")) {
		const gchar *medium = trillian_requestdata_get(chunk, "medium");
		if (purple_strequal(medium, "ASTRA")) {
			const gchar *name = trillian_requestdata_get(chunk, "name");
			if (!purple_blist_find_chat(ta->account, name)) {
				const gchar *displayname = trillian_requestdata_get(chunk, "displayname");
				const gchar *group_name = trillian_requestdata_get(chunk, "group");
				GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
				PurpleGroup *group = purple_blist_find_group(group_name);
				if (!group) {
					group = purple_group_new(group_name);
				}
				
				g_hash_table_replace(components, g_strdup("name"), g_strdup(name));
				
				PurpleChat *chat = purple_chat_new(ta->account, displayname, components);
				purple_blist_add_chat(chat, group, NULL);
			}
		}
		
	} else if (purple_strequal(e, "groupchat_update")) {
		const gchar *medium = trillian_requestdata_get(chunk, "medium");
		if (purple_strequal(medium, "ASTRA")) {
			const gchar *name = trillian_requestdata_get(chunk, "name");
			const gchar *displayname = trillian_requestdata_get(chunk, "displayname");
			PurpleChat *chat = purple_blist_find_chat(ta->account, name);
			
			if (chat) {
				purple_blist_alias_chat(chat, displayname);
			}
		}
		
	} else if (purple_strequal(e, "contactlist_rename")) {
		const gchar *medium = trillian_requestdata_get(chunk, "medium");
		if (purple_strequal(medium, "ASTRA")) {
			const gchar *username = trillian_requestdata_get(chunk, "username");
			const gchar *name = trillian_requestdata_get(chunk, "name");
			
			purple_serv_got_alias(ta->pc, username, name);
		}
		
	} else if (purple_strequal(e, "avatar_set")) {
		const gchar *medium = trillian_requestdata_get(chunk, "medium");
		if (purple_strequal(medium, "ASTRA")) {
			const gchar *username = trillian_requestdata_get(chunk, "username");
			gsize avatar_len;
			const gchar *avatar_base64 = trillian_requestdata_get(chunk, "avatar");
			guchar *avatar = g_base64_decode(avatar_base64, &avatar_len);
			const gchar *hash = trillian_requestdata_get(chunk, "hash");
			
			purple_buddy_icons_set_for_user(ta->account, username, avatar, avatar_len, hash);
		}
		
	} else if (purple_strequal(e, "session_ready")) {
		purple_connection_set_state(ta->pc, PURPLE_CONNECTION_CONNECTED);
		
	} else {
		purple_debug_error("trillianweb", "Unknown event type %s\n", e);
	}
}

static void
trillianweb_process_response(TrillianAccount *ta, TrillianWebRequestData *response, gpointer user_data)
{
	gint i;
	gint n = atoi(trillian_requestdata_get(response, "n"));
	GHashTable **data = g_new0(GHashTable *, n + 1);
	
	for (i = 0; i < n; i++) {
		data[i] = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	}
	
	GHashTableIter iter;
	gchar *key, *value;

	g_hash_table_iter_init(&iter, response);
	while (g_hash_table_iter_next(&iter, (gpointer *)&key, (gpointer *)&value))
	{
		gsize len = strlen(key);
		gsize suffix = 0;
		gint pos;
		
		while(g_ascii_isdigit(key[len - suffix - 1])) {
			suffix++;
		}
		if (suffix) {
			pos = atoi(&key[len - suffix]);
			g_hash_table_insert(data[pos], g_strndup(key, len - suffix), value);
			continue;
		}
	}
	
	for (i = 0; i < n; i++) {
		trillianweb_process_chunk(ta, data[i], user_data);
		
		g_hash_table_unref(data[i]);
	}
	
	g_free(data);
	
}


static void
trillianweb_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	TrillianAccount *ta = purple_connection_get_protocol_data(pc);
	const gchar *status_id = purple_status_get_id(status);
	const gchar *message = purple_status_get_attr_string(status, "message");
	
	
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "sessionStatus");
	trillian_requestdata_add(data, "status", status_id);
	trillian_requestdata_add(data, "statusmsg", message);
	
	trillian_fetch_url(ta, NULL, data, trillianweb_process_response, NULL);
	
	trillian_requestdata_free(data);
}

static void
trillianweb_alias_buddy(PurpleConnection *pc, const char *who, const char *alias)
{
	TrillianAccount *ta = purple_connection_get_protocol_data(pc);
	
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "contactlistRename");
	trillian_requestdata_add(data, "medium", "ASTRA");
	trillian_requestdata_add(data, "username", who);
	trillian_requestdata_add(data, "identity", "default");
	trillian_requestdata_add(data, "name", alias);
	
	trillian_fetch_url(ta, NULL, data, trillianweb_process_response, NULL);
	
	trillian_requestdata_free(data);
}

static void
trillianweb_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
, const char *message
#endif
)
{
	TrillianAccount *ta = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	const gchar *group_name = purple_group_get_name(group);
	
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "contactlistAdd");
	trillian_requestdata_add(data, "medium", "ASTRA");
	trillian_requestdata_add(data, "username", buddy_name);
	trillian_requestdata_add(data, "identity", "default");
	trillian_requestdata_add(data, "connection", "1001");
	trillian_requestdata_add(data, "group", group_name);
	
	trillian_fetch_url(ta, NULL, data, trillianweb_process_response, NULL);
	
	trillian_requestdata_free(data);
}


static void
trillianweb_process_poll_response(TrillianAccount *ta, TrillianWebRequestData *response, gpointer user_data)
{
	trillianweb_process_response(ta, response, user_data);
	trillianweb_poll(ta);
}

static void
trillianweb_poll(TrillianAccount *ta)
{
	if (!ta->host || !ta->session) {
		//TODO die
		return;
	}
	
	TrillianWebRequestData *data = trillian_requestdata_new();
	PurplePresence *presence = purple_account_get_presence(ta->account);
	
	if (purple_presence_is_idle(presence)) {
		gchar *seconds = g_strdup_printf("%d", (int) (purple_presence_get_idle_time(presence) - time(NULL)));
		trillian_requestdata_add(data, "c", "sessionIdle");
		trillian_requestdata_add(data, "seconds", seconds);
		g_free(seconds);
	} else {
		trillian_requestdata_add(data, "c", "sessionPoll");
	}
	
	trillian_fetch_url(ta, NULL, data, trillianweb_process_poll_response, NULL);
	
	trillian_requestdata_free(data);
}

static void
trillianweb_logout(TrillianAccount *ta)
{
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "sessionLogout");
	
	trillian_fetch_url(ta, NULL, data, NULL, NULL);
	
	trillian_requestdata_free(data);
}

static void
trillianweb_login(PurpleAccount *account)
{
	TrillianAccount *ta;
	PurpleConnection *pc = purple_account_get_connection(account);
	PurpleConnectionFlags pc_flags;
	
	pc_flags = purple_connection_get_flags(pc);
	pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	purple_connection_set_flags(pc, pc_flags);
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
	
	ta = g_new0(TrillianAccount, 1);
	purple_connection_set_protocol_data(pc, ta);
	ta->account = account;
	ta->pc = pc;
	ta->keepalive_pool = purple_http_keepalive_pool_new();
	
	TrillianWebRequestData *data = trillian_requestdata_new();
	trillian_requestdata_add(data, "c", "sessionLogin");
	trillian_requestdata_add(data, "protocol", "2");
	trillian_requestdata_add(data, "lang", "en");
	trillian_requestdata_add(data, "client", "Trillian");
	trillian_requestdata_add(data, "version", "4.2.0.10");
	trillian_requestdata_add(data, "platform", "Web");
	trillian_requestdata_add(data, "device", "WEB");
	trillian_requestdata_add(data, "expire", "5");
	
	trillian_fetch_url(ta, "https://octopus.trillian.im/trillian", data, trillianweb_process_poll_response, NULL);
	
	trillian_requestdata_free(data);
}


static void 
trillianweb_close(PurpleConnection *pc)
{
	TrillianAccount *ta = purple_connection_get_protocol_data(pc);
	// PurpleAccount *account;
	
	g_return_if_fail(ta != NULL);
	
	trillianweb_logout(ta);
	
	g_free(ta->host);
	g_free(ta->session);
	ta->host = NULL;
	ta->session = NULL;
	
	while (ta->http_conns) {
		purple_http_conn_cancel(ta->http_conns->data);
	}
	
	purple_http_keepalive_pool_unref(ta->keepalive_pool);
	
	g_free(ta);
}




static const char *
trillianweb_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "trillian";
}

static GList *
trillianweb_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "away", _("Away"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "do not disturb", _("Do Not Disturb"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_INVISIBLE, "invisible", _("Invisible"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)

void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();
	
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();

	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{

// #ifdef ENABLE_NLS
	// bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	// bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
// #endif

	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);

	info = plugin->info;

	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}

	info->extra_info = prpl_info;
#if PURPLE_MINOR_VERSION >= 5
	prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
#endif
#if PURPLE_MINOR_VERSION >= 8
/* prpl_info->add_buddy_with_invite = trillianweb_add_buddy_with_invite; */
#endif

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
	// prpl_info->protocol_options = trillianweb_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

	// prpl_info->get_account_text_table = trillianweb_get_account_text_table;
	// prpl_info->list_emblem = trillianweb_list_emblem;
	// prpl_info->status_text = trillianweb_status_text;
	// prpl_info->tooltip_text = trillianweb_tooltip_text;
	prpl_info->list_icon = trillianweb_list_icon;
	prpl_info->set_status = trillianweb_set_status;
	// prpl_info->set_idle = trillianweb_set_idle;
	prpl_info->status_types = trillianweb_status_types;
	// prpl_info->chat_info = trillianweb_chat_info;
	// prpl_info->chat_info_defaults = trillianweb_chat_info_defaults;
	prpl_info->login = trillianweb_login;
	prpl_info->close = trillianweb_close;
	// prpl_info->send_im = trillianweb_send_im;
	// prpl_info->send_typing = trillianweb_send_typing;
	// prpl_info->join_chat = trillianweb_join_chat;
	// prpl_info->get_chat_name = trillianweb_get_chat_name;
	// prpl_info->chat_invite = trillianweb_chat_invite;
	// prpl_info->chat_send = trillianweb_chat_send;
	// prpl_info->set_chat_topic = trillianweb_chat_set_topic;
	// prpl_info->get_cb_real_name = trillianweb_get_real_name;
	prpl_info->add_buddy = trillianweb_add_buddy;
	prpl_info->alias_buddy = trillianweb_alias_buddy;
	// prpl_info->remove_buddy = trillianweb_buddy_remove;
	// prpl_info->group_buddy = trillianweb_fake_group_buddy;
	// prpl_info->rename_group = trillianweb_fake_group_rename;
	// prpl_info->get_info = trillianweb_get_info;
	// prpl_info->add_deny = trillianweb_block_user;
	// prpl_info->rem_deny = trillianweb_unblock_user;

	// prpl_info->roomlist_get_list = trillianweb_roomlist_get_list;
	// prpl_info->roomlist_room_serialize = trillianweb_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	TRILLIANWEB_PLUGIN_ID,				/* id */
	"Trillian (Web)",						/* name */
	TRILLIANWEB_PLUGIN_VERSION,			/* version */
	"",								/* summary */
	"",								/* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	TRILLIANWEB_PLUGIN_WEBSITE,			/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	NULL,/*trillianweb_actions,*/				/* actions */
	NULL,							/* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(trillianweb, plugin_init, info);

#else
/* Purple 3 plugin load functions */

G_MODULE_EXPORT GType trillianweb_protocol_get_type(void);
#define TRILLIANWEB_TYPE_PROTOCOL (trillianweb_protocol_get_type())
#define TRILLIANWEB_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), TRILLIANWEB_TYPE_PROTOCOL, DiscordProtocol))
#define TRILLIANWEB_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), TRILLIANWEB_TYPE_PROTOCOL, DiscordProtocolClass))
#define TRILLIANWEB_IS_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), TRILLIANWEB_TYPE_PROTOCOL))
#define TRILLIANWEB_IS_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), TRILLIANWEB_TYPE_PROTOCOL))
#define TRILLIANWEB_PROTOCOL_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), TRILLIANWEB_TYPE_PROTOCOL, DiscordProtocolClass))

typedef struct _DiscordProtocol {
	PurpleProtocol parent;
} DiscordProtocol;

typedef struct _DiscordProtocolClass {
	PurpleProtocolClass parent_class;
} DiscordProtocolClass;

static void
trillianweb_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = TRILLIANWEB_PLUGIN_ID;
	info->name = "Discord";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
	info->account_options = trillianweb_add_account_options(info->account_options);
}

static void
trillianweb_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = trillianweb_login;
	prpl_info->close = trillianweb_close;
	prpl_info->status_types = trillianweb_status_types;
	prpl_info->list_icon = trillianweb_list_icon;
}

static void
trillianweb_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = trillianweb_send_im;
	prpl_info->send_typing = trillianweb_send_typing;
}

static void
trillianweb_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = trillianweb_chat_send;
	prpl_info->info = trillianweb_chat_info;
	prpl_info->info_defaults = trillianweb_chat_info_defaults;
	prpl_info->join = trillianweb_join_chat;
	prpl_info->get_name = trillianweb_get_chat_name;
	prpl_info->invite = trillianweb_chat_invite;
	prpl_info->set_topic = trillianweb_chat_set_topic;
	prpl_info->get_user_real_name = trillianweb_get_real_name;
}

static void
trillianweb_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = trillianweb_add_buddy;
	prpl_info->remove_buddy = trillianweb_buddy_remove;
	prpl_info->set_status = trillianweb_set_status;
	prpl_info->set_idle = trillianweb_set_idle;
	prpl_info->group_buddy = trillianweb_fake_group_buddy;
	prpl_info->rename_group = trillianweb_fake_group_rename;
	prpl_info->get_info = trillianweb_get_info;
}

static void
trillianweb_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_account_text_table = trillianweb_get_account_text_table;
	prpl_info->status_text = trillianweb_status_text;
	prpl_info->get_actions = trillianweb_actions;
	prpl_info->list_emblem = trillianweb_list_emblem;
	prpl_info->tooltip_text = trillianweb_tooltip_text;
}

static void
trillianweb_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	prpl_info->add_deny = trillianweb_block_user;
	prpl_info->rem_deny = trillianweb_unblock_user;
}

static void
trillianweb_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	prpl_info->get_list = trillianweb_roomlist_get_list;
	prpl_info->room_serialize = trillianweb_roomlist_serialize;
}

static PurpleProtocol *trillianweb_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	DiscordProtocol, trillianweb_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
									  trillianweb_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
									  trillianweb_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
									  trillianweb_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
									  trillianweb_protocol_client_iface_init)
								  
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
									  trillianweb_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
									  trillianweb_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	trillianweb_protocol_register_type(plugin);
	trillianweb_protocol = purple_protocols_add(TRILLIANWEB_TYPE_PROTOCOL, error);

	if (!trillianweb_protocol) {
		return FALSE;
	}

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error)) {
		return FALSE;
	}

	if (!purple_protocols_remove(trillianweb_protocol, error)) {
		return FALSE;
	}

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
#ifdef ENABLE_NLS
	bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif
	
	return purple_plugin_info_new(
	  "id", TRILLIANWEB_PLUGIN_ID,
	  "name", "Trillian (Web)",
	  "version", TRILLIANWEB_PLUGIN_VERSION,
	  "category", _("Protocol"),
	  "summary", _("Trillian Protocol Plugins."),
	  "description", _("Adds Trillian protocol support to libpurple."),
	  "website", TRILLIANWEB_PLUGIN_WEBSITE,
	  "abi-version", PURPLE_ABI_VERSION,
	  "flags", PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
				 PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
	  NULL);
}

PURPLE_PLUGIN_INIT(trillianweb, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
