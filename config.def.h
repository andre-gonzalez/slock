static const char *colorname[NUMCOLS] = {
	[INIT] =   "black",     /* after initialization */
	[INPUT] =  "#005577",   /* during input */
	[FAILED] = "#CC3333",   /* wrong password */
	[CAPS] =   "#FFD300",       /* CapsLock on */
	[PAM] =    "#9400D3",   /* waiting for PAM (password or finger) */
};




/* PAM service for authentication: /etc/pam.d/slock. NixOS creates it with
 * security.pam.services.slock. Without that file, PAM uses "other". */
static const char *pam_service = "slock";

/* treat a cleared input like a wrong password (color) */
static const int failonclear = 1;


/* allow control key to trigger fail on clear */
static const int controlkeyclear = 0;

/* time in seconds before the monitor shuts down */
static const int monitortime = 5;



