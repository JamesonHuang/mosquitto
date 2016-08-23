#include <stdio.h>
#include <string.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <pwd.h>
#include <shadow.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
    bool is_local_host = ( strcmp(user_data, "127.0.0.1") == 0 );
    if (is_local_host) {
        return MOSQ_ERR_SUCCESS;
    }
    if (username == NULL) {
		return MOSQ_ERR_ACL_DENIED;
    }

    struct passwd *pwd = getpwnam(username);
    if ( pwd == NULL ) {
		return MOSQ_ERR_ACL_DENIED;
    }
    else {
		return MOSQ_ERR_SUCCESS;
    }
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
    bool is_local_host = ( strcmp(user_data, "127.0.0.1") == 0 );
    if ( is_local_host ) {
        return MOSQ_ERR_SUCCESS;
    }
    if (username == NULL || password == NULL) {
        return MOSQ_ERR_AUTH;
    }
    struct passwd *pwd = getpwnam(username);
    if ( pwd == NULL ) {
        return MOSQ_ERR_AUTH;
    }
    struct spwd *spwd = getspnam(username);
    if ( spwd == NULL ) {
        return MOSQ_ERR_AUTH;
    }
    else {
        pwd->pw_passwd = spwd->sp_pwdp;
    }

    char *encrypted = crypt(password, pwd->pw_passwd);
    if (encrypted == NULL) {
        return MOSQ_ERR_AUTH;
    }
    if ( strcmp(encrypted, pwd->pw_passwd) == 0 ) {
        return MOSQ_ERR_SUCCESS;
    }
    else {
        return MOSQ_ERR_AUTH;
    }
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
	return MOSQ_ERR_AUTH;
}

