/** Yubicrack, a tool to brute force the access code of a Yubikey.
*
* Copyright © 2010 by Thomas Roth <code@leveldown.de>
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <ykpers.h>
#include <yubikey.h>

/* Global variables, so that we can use them
 * in the bruteforce function. */
YK_KEY *yk;
YK_CONFIG *coreconfig;
int coreconfignum;
unsigned int serial = 0;
bool changed[6] = {false, false, false, false, false, false};

/* This prints the actual accesscode with an
 * individual message in front of it. */
/*void print_access_code(char* text, unsigned char* access_code) {
	printf("%s: %02x%02x%02x%02x%02x%02x\n",
		text,
		access_code[0],
		access_code[1],
		access_code[2],
		access_code[3],
		access_code[4],
		access_code[5]);
}*/

// Print the access_code, with carriage return or new line depending on "rewrite"
void print_access_code(char* text, unsigned char* access_code, int rewrite) {
	if (rewrite==1)
		printf("%s: %02x%02x%02x%02x%02x%02x\r",
			text,
			access_code[0],
			access_code[1],
			access_code[2],
			access_code[3],
			access_code[4],
			access_code[5]);
	else
		printf("%s: %02x%02x%02x%02x%02x%02x\n",
			text,
			access_code[0],
			access_code[1],
			access_code[2],
			access_code[3],
			access_code[4],
			access_code[5]);
}

/* Iterate through all possible access codes.
 * This could take a loooooooooong time. */
static inline int bruteforce(unsigned char* s, unsigned char* t, int deep) {
	
	int id = 5 - deep;
	unsigned char start = 0;
	if (!changed[id]) start = s[id];
	changed[id] = true;
	for(t[id]=start; t[id]<255; t[id]++) { // MODIFIER L'INITIALISATION ICI
		if(deep > 0) {if(bruteforce(s, t, deep - 1) == 0) return 0;} // Exit from recursion because has found the correct value
		if(!yk_write_config(yk,
				coreconfig, coreconfignum,
				t)) {
			print_access_code("Fail", t, 1);
		} else {
			print_access_code("\aWin", t, 0);
			return 0;
		}
	}
	return -1;
}

char* filenameforkey() {
	char* filename = "";
	
	if (serial==0) {
		filename = "progress.txt";
	}else{
		sprintf(filename, "%d%s", serial, ".txt");
	}
	return filename;
}

void loadfromfile(unsigned char* access_code) {
	
	FILE* fp = fopen("progress.txt", "r");
    if(!fp) {
        perror("Status file opening failed. Cannot load.");
        return;
    }
	unsigned int input_data = 0;

	for(int i = 0; i < 6; i++) {
		int ret = fscanf(fp, "%02x", &input_data);
		if (ret > 0)
			access_code[i] = (unsigned char) input_data;
	}
	
    if (ferror(fp))
		puts("Can't load previous position.");
    else if (feof(fp))
        puts("Previous position loaded.");

    fclose(fp);
	
}

void savetofile(unsigned char* access_code) {
	
	FILE* fp = fopen("progress.txt", "w");
    if(!fp) {
        perror("Status file opening failed. Cannot save.");
        return;
    }

	for(int i = 0; i < 6; i++) {
		fprintf(fp, "%02x", access_code[i]);
	}
	
    if (ferror(fp))
		puts("Can't save current position.");
    else if (feof(fp))
        puts("Current position saved.");

    fclose(fp);
	
}

int main(int argc, char** argv) {

	char showmessage = 1;
	if((argc == 2) && (strcmp(argv[1], "-y") == 0)) showmessage = 0;
	if(showmessage == 1) {
		puts("--------------------------------------------");
		puts("Hi! You're going to crack the access code of");
		puts("a Yubikey. As soon as the appropriate code  ");
		puts("is found, the AES key will be set to zeros.");
		puts("Then delete the slot configuration thanks to");
		puts("the command \"ykman otp delete [slot]\".");
		puts("Brute forcing the code can take a very long ");
		puts("time, and with long I mean like more than a ");
		puts("year.");
		puts("(By the way you can bypass this message by  ");
		puts("passing the -y option to the program.) ");
		puts("--------------------------------------------");
		puts("Type \"start\" to continue.");

		char acknowledge[256];
		fgets(acknowledge, 256, stdin);
		if(strcmp(acknowledge, "start\n") != 0) {
			puts("Quitting.");
			return EXIT_SUCCESS;
		}
	} 

	yk = 0;
	unsigned char access_code[6];
	unsigned char starting_from[6];
	serial = 0;
	
	const char* aeshash="00000000000000000000000000000000";
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = ykds_alloc();

	if(!yk_init()) {
		fputs("Failed to init Yubikey.\n", stderr);
		return EXIT_FAILURE;
	}
	if(!(yk = yk_open_first_key())) {
		fputs("No Yubikey found.\n", stderr);
		return EXIT_FAILURE;
	}
	
	if(!(yk_get_serial(yk, 2, 0, &serial))) {
		fputs("Yubikey serial unretrievable.\n", stderr);
		serial = 0;
		return EXIT_FAILURE;
	}else
		printf("Yubikey serial : %d\n", serial);
	
	
	// Load starting access_code from saved file...
	loadfromfile(starting_from);
	
	// Display where we're starting from...
	print_access_code("Starting from: ", starting_from, 0);
	
	if(!yk_get_status(yk,st)) {
		fputs("Failed to get status of the Yubikey.\n", stderr);
		return EXIT_FAILURE;
	}
	
	printf("Found Yubikey. Version: %d.%d.%d Touch level: %d\n",
		ykds_version_major(st),
		ykds_version_minor(st),
		ykds_version_build(st),
		ykds_touch_level(st));

	printf("Which slot to use ? 1 or 2 ?\n");
	char slotnumber[2];
	int slot;
	fgets(slotnumber, 2, stdin);
	if(strcmp(slotnumber, "1\n") == 0) {
		slot=1;
	}else{
		slot=2;
	}

	if(!ykp_configure_for(cfg, slot, st)) {
		printf("Can't set configuration to %d.\n", slot);
		return EXIT_FAILURE;
	}
	
	if(ykp_AES_key_from_hex(cfg, aeshash)) {
		fputs("Bad AES key. WTF did you do to my source?", stderr);
		return EXIT_FAILURE;
	}

	coreconfig = ykp_core_config(cfg);
	coreconfignum = ykp_config_num(cfg);
	bruteforce(starting_from, access_code, 5);

	// save the result to a file named following the serial of the key if readable
	// savetofile(access_code);

	if(st) free(st);
	if(!yk_close_key(yk)) {
		fputs("Can't close Yubikey! What the hell are you doing over there?", stderr);
		return EXIT_FAILURE;
	}
	if(!yk_release()) {
		fputs("Can't release Yubikey.", stderr);
		return EXIT_FAILURE;
	}

	if(cfg) ykp_free_config(cfg);

	return EXIT_SUCCESS;
}
