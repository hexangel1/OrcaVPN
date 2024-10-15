#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "vpnserver.h"
#include "vpnclient.h"
#include "helper.h"
#include "logger.h"
#include "encrypt/encryption.h"

#define VPNSERVER_MODE 0
#define VPNCLIENT_MODE 1

static int daemon_state = 0;
static int working_mode = -1;
static const char *config_file = NULL;
static const char *pid_file = NULL;
static const char *log_file = NULL;

static int get_command_line_options(int argc, char **argv)
{
	int opt, retval = 0;
	extern int optopt;
	extern char *optarg;
	while ((opt = getopt(argc, argv, ":hdm:c:p:l:")) != -1) {
		switch (opt) {
		case 'd':
			daemon_state = 1;
			break;
		case 'm':
			if (!strcmp(optarg, "server"))
				working_mode = VPNSERVER_MODE;
			else if (!strcmp(optarg, "client"))
				working_mode = VPNCLIENT_MODE;
			else
				working_mode = -1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'h':
			retval = -1;
			break;
		case ':':
			fprintf(stderr, "Opt -%c require an operand\n", optopt);
			retval = -1;
			break;
		case '?':
			fprintf(stderr, "Unrecognized option: -%c\n", optopt);
			retval = -1;
			break;
		}
	}
	return retval;
}

static const char usage[] = "Usage: %s "
	"[-d] [-m mode] [-c configfile] [-p pidfile] [-l logfile]\n";

int main(int argc, char **argv)
{
	int res = get_command_line_options(argc, argv);
	if (res == -1) {
		fprintf(stderr, usage, argv[0]);
		exit(EXIT_FAILURE);
	}
	if (geteuid() != 0) {
		fprintf(stderr, "Required root privileges\n");
		exit(EXIT_FAILURE);
	}
	if (daemon_state)
		daemonize(pid_file);
	init_logger("orcavpnd", log_file, daemon_state, log_file ? 2 : 0);
	init_encryption(CIPHER_KEY_LEN);
	switch (working_mode) {
	case VPNSERVER_MODE:
		if (!config_file)
			config_file = "config/server/orcavpn.conf";
		run_vpnserver(config_file);
		break;
	case VPNCLIENT_MODE:
		if (!config_file)
			config_file = "config/client/orcavpn.conf";
		run_vpnclient(config_file);
		break;
	default:
		log_mesg(LOG_ERR, "Unknown working mode");
		exit(EXIT_FAILURE);
	}
	return 0;
}
