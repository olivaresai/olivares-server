// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

//go:build linux && cgo && olivares_pam

package localpam

/*
#cgo LDFLAGS: -lpam
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <security/pam_appl.h>

// The conversation talks to the console's terminal: every prompt and message goes to standard
// output, every answer comes from standard input, a secret one with echo off. libpam_misc's
// misc_conv writes its prompts to standard error, which the console's unit gives to the journal,
// so the operator saw nothing and typed blind. Each call of the conversation waits at most its
// deadline; what was typed is wiped from every buffer here and never logged.
static void olivares_say(const char *text) {
	size_t left = strlen(text);
	while (left > 0) {
		ssize_t n = write(1, text, left);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n <= 0) {
			return;
		}
		text += n;
		left -= (size_t)n;
	}
}

// olivares_quiet turns echo off on a terminal before its prompt is shown, discarding what was typed
// ahead, as the distribution's conversation does, so a secret typed before its prompt is not taken.
// It returns 1 when it changed the terminal, 0 when fd 0 is a pipe or a file, -1 when fd 0 is a
// character device it could not quieten: then no secret is read, never one with echo on.
static int olivares_quiet(struct termios *saved) {
	struct termios quiet;
	struct stat st;
	if (tcgetattr(0, saved) != 0) {
		return fstat(0, &st) == 0 && !S_ISCHR(st.st_mode) ? 0 : -1;
	}
	quiet = *saved;
	quiet.c_lflag &= ~(tcflag_t)ECHO;
	return tcsetattr(0, TCSAFLUSH, &quiet) == 0 ? 1 : -1;
}

// olivares_now_ms reads the monotonic clock, so a step of the wall clock neither stretches nor ends a
// deadline.
static long long olivares_now_ms(void) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// olivares_answer reads one line from fd 0 until the deadline, in monotonic milliseconds. A line
// longer than the buffer, or one holding a NUL (^@), is refused, never cut down into a credential.
static int olivares_answer(char *line, size_t size, long long deadline) {
	size_t n = 0;
	for (;;) {
		long long left = deadline - olivares_now_ms();
		if (left <= 0) {
			break;
		}
		struct pollfd in = { 0, POLLIN, 0 };
		int ready = poll(&in, 1, (int)left);
		if (ready < 0 && errno == EINTR) {
			continue;
		}
		if (ready <= 0) {
			break;
		}
		char c;
		ssize_t got = read(0, &c, 1);
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			break;
		}
		if (c == '\n' || c == '\r') {
			line[n] = 0;
			return 0;
		}
		if (c == 0 || n + 1 >= size) {
			break;
		}
		line[n++] = c;
	}
	line[n] = 0;
	return -1;
}

static int olivares_converse(int count, const struct pam_message **messages, struct pam_response **responses, void *data) {
	// One deadline for this call of the conversation, whatever number of messages it carries.
	long long deadline = olivares_now_ms() + (long long)*(const long *)data * 1000;
	struct pam_response *answers = calloc((size_t)count, sizeof *answers);
	if (count <= 0 || answers == NULL) {
		free(answers);
		return PAM_CONV_ERR;
	}
	for (int i = 0; i < count; i++) {
		const char *text = messages[i]->msg != NULL ? messages[i]->msg : "";
		switch (messages[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON: {
			int secret = messages[i]->msg_style == PAM_PROMPT_ECHO_OFF;
			struct termios saved;
			int quieted = secret ? olivares_quiet(&saved) : 0;
			if (quieted < 0) {
				goto refused;
			}
			olivares_say(text);
			char line[512];
			int ok = olivares_answer(line, sizeof line, deadline);
			// A refused answer's typed rest is discarded, never left in the line for ^R to show
			// or for the next menu line to take.
			if (quieted == 1) {
				tcsetattr(0, ok == 0 ? TCSADRAIN : TCSAFLUSH, &saved);
			}
			if (secret) {
				olivares_say("\n");
			}
			if (ok == 0) {
				answers[i].resp = strdup(line);
			}
			explicit_bzero(line, sizeof line);
			if (ok != 0 || answers[i].resp == NULL) {
				goto refused;
			}
			break;
		}
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			olivares_say(text);
			olivares_say("\n");
			break;
		default:
			goto refused;
		}
	}
	*responses = answers;
	return PAM_SUCCESS;
refused:
	for (int i = 0; i < count; i++) {
		if (answers[i].resp != NULL) {
			explicit_bzero(answers[i].resp, strlen(answers[i].resp));
			free(answers[i].resp);
		}
	}
	free(answers);
	return PAM_CONV_ERR;
}

static long olivares_conversation_seconds;
static struct pam_conv olivares_conversation = { olivares_converse, &olivares_conversation_seconds };

static int olivares_pam_start(const char *service, const char *user, long seconds, pam_handle_t **handle) {
	olivares_conversation_seconds = seconds;
	return pam_start(service, user, &olivares_conversation, handle);
}

static const char *olivares_pam_user(pam_handle_t *handle) {
	const void *item = NULL;
	if (pam_get_item(handle, PAM_USER, &item) != PAM_SUCCESS) {
		return NULL;
	}
	return (const char *)item;
}
*/
import "C"

import (
	"time"
	"unsafe"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

// Built reports that this binary carries the adapter.
const Built = true

// conversationTimeout bounds each answer the console waits for, so an abandoned prompt does not
// hold tty1 for good.
var conversationTimeout = 5 * time.Minute

// Start opens a transaction on service for login, naming the console's terminal.
func (Stack) Start(service, login string) (auth.Transaction, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cLogin := C.CString(login)
	defer C.free(unsafe.Pointer(cLogin))
	var handle *C.pam_handle_t
	status := C.olivares_pam_start(cService, cLogin, C.long(conversationTimeout/time.Second), &handle)
	if status != C.PAM_SUCCESS || handle == nil {
		if handle != nil {
			C.pam_end(handle, status)
		}
		return nil, errRefused
	}
	t := &transaction{handle: handle, login: login, status: status}
	cTerminal := C.CString(consoleTerminal)
	defer C.free(unsafe.Pointer(cTerminal))
	if t.status = C.pam_set_item(handle, C.int(C.PAM_TTY), unsafe.Pointer(cTerminal)); t.status != C.PAM_SUCCESS {
		_ = t.Close()
		return nil, errRefused
	}
	return t, nil
}

// ChangePassword runs the distribution password service's chauthtok group for login.
func (s Stack) ChangePassword(service, login string) error {
	transaction, err := s.Start(service, login)
	if err != nil {
		return err
	}
	defer transaction.Close()
	changer, ok := transaction.(interface{ ChangeCredential() error })
	if !ok {
		return errRefused
	}
	return changer.ChangeCredential()
}

// transaction is one open transaction. status is the last result, which the library's end takes.
type transaction struct {
	handle *C.pam_handle_t
	login  string
	status C.int
	closed bool
}

// Authenticate runs the service's auth group, refusing an empty credential, and refuses a module
// that changed whom the transaction is for.
func (t *transaction) Authenticate() error {
	t.status = C.pam_authenticate(t.handle, C.int(C.PAM_DISALLOW_NULL_AUTHTOK))
	if t.status != C.PAM_SUCCESS {
		return errRefused
	}
	user := C.olivares_pam_user(t.handle)
	if user == nil || C.GoString(user) != t.login {
		t.status = C.PAM_AUTH_ERR
		return errRefused
	}
	return nil
}

// ChangeCredential runs the service's native password-change conversation and refuses a module
// that changed whom the transaction is for.
func (t *transaction) ChangeCredential() error {
	t.status = C.pam_chauthtok(t.handle, C.int(C.PAM_DISALLOW_NULL_AUTHTOK))
	if t.status != C.PAM_SUCCESS {
		return errRefused
	}
	user := C.olivares_pam_user(t.handle)
	if user == nil || C.GoString(user) != t.login {
		t.status = C.PAM_AUTH_ERR
		return errRefused
	}
	return nil
}

// Account runs the service's account group. An account whose credential must be changed first is
// refused: changing it is the host layer's entry, not a sign-in.
func (t *transaction) Account() error {
	t.status = C.pam_acct_mgmt(t.handle, C.int(C.PAM_DISALLOW_NULL_AUTHTOK))
	if t.status != C.PAM_SUCCESS {
		return errRefused
	}
	return nil
}

// Close ends the transaction once.
func (t *transaction) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	C.pam_end(t.handle, t.status)
	return nil
}
