/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <X11/extensions/Xrandr.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <X11/XKBlib.h>
#include <X11/XF86keysym.h>
#include <X11/extensions/dpms.h>
#include <security/pam_appl.h>

#include "arg.h"
#include "util.h"

char *argv0;


enum {
	INIT,
	INPUT,
	FAILED,
	CAPS,
	PAM,
	NUMCOLS
};

struct lock {
	int screen;
	Window root, win;
	Pixmap pmap;
	unsigned long colors[NUMCOLS];
};

struct xrandr {
	int active;
	int evbase;
	int errbase;
};

#include "config.h"

static void
die(const char *errstr, ...)
{
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	exit(1);
}


#ifdef __linux__
#include <fcntl.h>
#include <linux/oom.h>

static void
dontkillme(void)
{
	FILE *f;
	const char oomfile[] = "/proc/self/oom_score_adj";

	if (!(f = fopen(oomfile, "w"))) {
		if (errno == ENOENT)
			return;
		die("slock: fopen %s: %s\n", oomfile, strerror(errno));
	}
	fprintf(f, "%d", OOM_SCORE_ADJ_MIN);
	if (fclose(f)) {
		if (errno == EACCES)
			die("slock: unable to disable OOM killer. "
			    "Make sure to suid or sgid slock.\n");
		else
			die("slock: fclose %s: %s\n", oomfile, strerror(errno));
	}
}
#endif

/*
 * PAM conversation: answer every hidden prompt (pam_unix's "Password: ")
 * with the typed password, which arrives in appdata_ptr. Info and error
 * messages (pam_fprintd's "Place your finger on the reader") need no answer;
 * they go to stderr. The responses are one array of num_msg entries, as
 * Linux-PAM expects, and PAM frees them.
 */
static int
pamconv(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *r;
	int i;

	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;
	if (!(r = calloc(num_msg, sizeof(*r))))
		return PAM_BUF_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			if (!(r[i].resp = strdup((const char *)appdata_ptr)))
				goto fail;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			fprintf(stderr, "slock: %s\n", msg[i]->msg);
			break;
		default: /* PAM_PROMPT_ECHO_ON: the user name is already known */
			goto fail;
		}
	}
	*resp = r;
	return PAM_SUCCESS;

fail:
	for (i = 0; i < num_msg; i++) {
		if (r[i].resp) {
			explicit_bzero(r[i].resp, strlen(r[i].resp));
			free(r[i].resp);
		}
	}
	free(r);
	return PAM_CONV_ERR;
}

static const char *
getusername(void)
{
	struct passwd *pw;

	errno = 0;
	if (!(pw = getpwuid(getuid()))) {
		if (errno)
			die("slock: getpwuid: %s\n", strerror(errno));
		else
			die("slock: cannot retrieve password entry\n");
	}
	return pw->pw_name;
}

static void
readpw(Display *dpy, struct xrandr *rr, struct lock **locks, int nscreens,
       const char *username)
{
	XRRScreenChangeNotifyEvent *rre;
	char buf[32], passwd[256];
	int num, screen, running, failure, oldc, retval;
	struct pam_conv conv = { pamconv, passwd };
	pam_handle_t *pamh;
	unsigned int len, color;
	int caps;
	unsigned int indicators;
	KeySym ksym;
	XEvent ev;

	len = 0;
	caps = 0;
	running = 1;
	failure = 0;
	oldc = INIT;

	if (!XkbGetIndicatorState(dpy, XkbUseCoreKbd, &indicators))
		caps = indicators & 1;

	while (running && !XNextEvent(dpy, &ev)) {
		if (ev.type == KeyPress) {
			explicit_bzero(&buf, sizeof(buf));
			num = XLookupString(&ev.xkey, buf, sizeof(buf), &ksym, 0);
			if (IsKeypadKey(ksym)) {
				if (ksym == XK_KP_Enter)
					ksym = XK_Return;
				else if (ksym >= XK_KP_0 && ksym <= XK_KP_9)
					ksym = (ksym - XK_KP_0) + XK_0;
			}
			if (IsFunctionKey(ksym) ||
			    IsKeypadKey(ksym) ||
			    IsMiscFunctionKey(ksym) ||
			    IsPFKey(ksym) ||
			    IsPrivateKeypadKey(ksym))
				continue;
			switch (ksym) {
			case XK_Return:
				passwd[len] = '\0';
				/* PAM can block (pam_fprintd waits for a finger):
				 * show the PAM color while it runs. */
				for (screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(dpy, locks[screen]->win,
					                     locks[screen]->colors[PAM]);
					XClearWindow(dpy, locks[screen]->win);
				}
				XSync(dpy, False);
				oldc = PAM;

				pamh = NULL;
				retval = pam_start(pam_service, username, &conv, &pamh);
				if (retval == PAM_SUCCESS)
					retval = pam_authenticate(pamh, 0);
				if (retval == PAM_SUCCESS)
					retval = pam_acct_mgmt(pamh, 0);
				if (retval == PAM_SUCCESS)
					running = 0;
				else
					fprintf(stderr, "slock: %s\n",
					        pam_strerror(pamh, retval));
				if (pamh)
					pam_end(pamh, retval);
				if (running) {
					XBell(dpy, 100);
					failure = 1;
				}
				explicit_bzero(&passwd, sizeof(passwd));
				len = 0;
				break;
			case XK_Escape:
				explicit_bzero(&passwd, sizeof(passwd));
				len = 0;
				break;
			case XK_BackSpace:
				if (len)
					passwd[--len] = '\0';
				break;
			case XK_Caps_Lock:
				caps = !caps;
				break;
			case XF86XK_AudioLowerVolume:
			case XF86XK_AudioMute:
			case XF86XK_AudioRaiseVolume:
			case XF86XK_AudioPlay:
			case XF86XK_AudioStop:
			case XF86XK_AudioPrev:
			case XF86XK_AudioNext:
				XSendEvent(dpy, DefaultRootWindow(dpy), True, KeyPressMask, &ev);
				break;
			default:
				if (controlkeyclear && iscntrl((int)buf[0]))
					continue;
				if (num && (len + num < sizeof(passwd)))
				{
					memcpy(passwd + len, buf, num);
					len += num;
				}
				break;
			}
			color = len ? (caps ? CAPS : INPUT) : (failure || failonclear ? FAILED : INIT);
			if (running && oldc != color) {
				for (screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(dpy,
					                     locks[screen]->win,
					                     locks[screen]->colors[color]);
					XClearWindow(dpy, locks[screen]->win);
				}
				oldc = color;
			}
		} else if (rr->active && ev.type == rr->evbase + RRScreenChangeNotify) {
			rre = (XRRScreenChangeNotifyEvent*)&ev;
			for (screen = 0; screen < nscreens; screen++) {
				if (locks[screen]->win == rre->window) {
					if (rre->rotation == RR_Rotate_90 ||
					    rre->rotation == RR_Rotate_270)
						XResizeWindow(dpy, locks[screen]->win,
						              rre->height, rre->width);
					else
						XResizeWindow(dpy, locks[screen]->win,
						              rre->width, rre->height);
					XClearWindow(dpy, locks[screen]->win);
					break;
				}
			}
		} else {
			for (screen = 0; screen < nscreens; screen++)
				XRaiseWindow(dpy, locks[screen]->win);
		}
	}
}

static struct lock *
lockscreen(Display *dpy, struct xrandr *rr, int screen)
{
	char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
	int i, ptgrab, kbgrab;
	struct lock *lock;
	XColor color, dummy;
	XSetWindowAttributes wa;
	Cursor invisible;

	if (dpy == NULL || screen < 0 || !(lock = malloc(sizeof(struct lock))))
		return NULL;

	lock->screen = screen;
	lock->root = RootWindow(dpy, lock->screen);


	for (i = 0; i < NUMCOLS; i++) {
		XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen),
		                 colorname[i], &color, &dummy);
		lock->colors[i] = color.pixel;
	}

	/* init */
	wa.override_redirect = 1;
	wa.background_pixel = lock->colors[INIT];
	lock->win = XCreateWindow(dpy, lock->root, 0, 0,
	                          DisplayWidth(dpy, lock->screen),
	                          DisplayHeight(dpy, lock->screen),
	                          0, DefaultDepth(dpy, lock->screen),
	                          CopyFromParent,
	                          DefaultVisual(dpy, lock->screen),
	                          CWOverrideRedirect | CWBackPixel, &wa);
	lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap,
	                                &color, &color, 0, 0);
	XDefineCursor(dpy, lock->win, invisible);

	/* Try to grab mouse pointer *and* keyboard for 600ms, else fail the lock */
	for (i = 0, ptgrab = kbgrab = -1; i < 6; i++) {
		if (ptgrab != GrabSuccess) {
			ptgrab = XGrabPointer(dpy, lock->root, False,
			                      ButtonPressMask | ButtonReleaseMask |
			                      PointerMotionMask, GrabModeAsync,
			                      GrabModeAsync, None,
			                      invisible,
			                      CurrentTime);
		}
		if (kbgrab != GrabSuccess) {
			kbgrab = XGrabKeyboard(dpy, lock->root, True,
			                       GrabModeAsync, GrabModeAsync, CurrentTime);
		}

		/* input is grabbed: we can lock the screen */
		if (ptgrab == GrabSuccess && kbgrab == GrabSuccess) {
			XMapRaised(dpy, lock->win);
			if (rr->active)
				XRRSelectInput(dpy, lock->win, RRScreenChangeNotifyMask);

			XSelectInput(dpy, lock->root, SubstructureNotifyMask);
			return lock;
		}

		/* retry on AlreadyGrabbed but fail on other errors */
		if ((ptgrab != AlreadyGrabbed && ptgrab != GrabSuccess) ||
		    (kbgrab != AlreadyGrabbed && kbgrab != GrabSuccess))
			break;

		usleep(100000);
	}

	/* we couldn't grab all input: fail out */
	if (ptgrab != GrabSuccess)
		fprintf(stderr, "slock: unable to grab mouse pointer for screen %d\n",
		        screen);
	if (kbgrab != GrabSuccess)
		fprintf(stderr, "slock: unable to grab keyboard for screen %d\n",
		        screen);
	return NULL;
}

static void
usage(void)
{
	die("usage: slock [-v] [cmd [arg ...]]\n");
}

int
main(int argc, char **argv) {
	struct xrandr rr;
	struct lock **locks;
	uid_t duid;
	gid_t dgid;
	const char *username;
	Display *dpy;
	int s, nlocks, nscreens;
	CARD16 standby, suspend, off;
	ARGBEGIN {
	case 'v':
		fprintf(stderr, "slock-"VERSION"\n");
		return 0;
	default:
		usage();
	} ARGEND

	/*
	 * Drop privileges to the user who runs slock, not to nobody.
	 * pam_unix checks the password through unix_chkpwd, and unix_chkpwd
	 * checks only the password of its calling user. fprintd also allows a
	 * verify only for the session user (polkit).
	 */
	duid = getuid();
	dgid = getgid();

#ifdef __linux__
	dontkillme();
#endif

	username = getusername();

	if (!(dpy = XOpenDisplay(NULL)))
		die("slock: cannot open display\n");

	/* drop privileges */
	if (setgroups(0, NULL) < 0)
		die("slock: setgroups: %s\n", strerror(errno));
	if (setgid(dgid) < 0)
		die("slock: setgid: %s\n", strerror(errno));
	if (setuid(duid) < 0)
		die("slock: setuid: %s\n", strerror(errno));




	/* check for Xrandr support */
	rr.active = XRRQueryExtension(dpy, &rr.evbase, &rr.errbase);

	/* get number of screens in display "dpy" and blank them */
	nscreens = ScreenCount(dpy);
	if (!(locks = calloc(nscreens, sizeof(struct lock *))))
		die("slock: out of memory\n");
	for (nlocks = 0, s = 0; s < nscreens; s++) {
		if ((locks[s] = lockscreen(dpy, &rr, s)) != NULL) {
			nlocks++;
		} else {
			break;
		}
	}
	XSync(dpy, 0);

	/* did we manage to lock everything? */
	if (nlocks != nscreens)
		return 1;

	/* DPMS magic to disable the monitor */
	if (!DPMSCapable(dpy))
		die("slock: DPMSCapable failed\n");
	if (!DPMSEnable(dpy))
		die("slock: DPMSEnable failed\n");
	if (!DPMSGetTimeouts(dpy, &standby, &suspend, &off))
		die("slock: DPMSGetTimeouts failed\n");
	if (!standby || !suspend || !off)
		die("slock: at least one DPMS variable is zero\n");
	if (!DPMSSetTimeouts(dpy, monitortime, monitortime, monitortime))
		die("slock: DPMSSetTimeouts failed\n");

	XSync(dpy, 0);

	/* run post-lock command */
	if (argc > 0) {
		switch (fork()) {
		case -1:
			die("slock: fork failed: %s\n", strerror(errno));
		case 0:
			if (close(ConnectionNumber(dpy)) < 0)
				die("slock: close: %s\n", strerror(errno));
			execvp(argv[0], argv);
			fprintf(stderr, "slock: execvp %s: %s\n", argv[0], strerror(errno));
			_exit(1);
		}
	}

	/* everything is now blank. Wait for the correct password */
	readpw(dpy, &rr, locks, nscreens, username);
	/* reset DPMS values to inital ones */
	DPMSSetTimeouts(dpy, standby, suspend, off);
	XSync(dpy, 0);

	return 0;
}
