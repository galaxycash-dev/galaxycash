// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <galaxycash.h>
#include <galaxyscript.h>
#include <hash.h>
#include <memory>
#include <pow.h>
#include <stack>
#include <stdint.h>
#include <uint256.h>
#include <util.h>
#include <netbase.h>
#include <net.h>
#include <regex>

extern "C" {
    #include "duktape.c"
}
#include <dukglue/dukglue.h>

static duk_context *ctx = nullptr;

#define BIT(x) (1 << x)
static const std::regex ext_json(
    "\\.json$", std::regex::icase
);
bool IsJsonFile(const std::string file) {
    return std::regex_search(file, ext_json);
}
static const std::regex ext_js(
    "\\.js$", std::regex::icase
);
bool IsJSFile(const std::string file) {
    return std::regex_search(file, ext_js);
}
static const std::regex ext_module(
    "\\.module$", std::regex::icase
);
bool IsModuleFile(const std::string file) {
    return std::regex_search(file, ext_module);
}

std::string RandName()
{
    char name[17];
    memset(name, 0, sizeof(name));
    GetRandBytes((unsigned char*)name, sizeof(name) - 1);
    return name;
}

#define  DUK_COMMONJS_MODULE_ID_LIMIT  256

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef WIN32
#include <netdb.h>
#endif
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#endif
#include <time.h>
#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif


#ifndef WIN32
#include <unistd.h>
#else 
#include <sys/unistd.h>
#include <direct.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <wincrypt.h>
#define poll WSAPoll
#else
#include <poll.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/* Straight flag rename */
#if !defined(DUK_ENUM_INCLUDE_INTERNAL)
#define DUK_ENUM_INCLUDE_INTERNAL DUK_ENUM_INCLUDE_HIDDEN
#endif

/* Flags for duk_push_string_file_raw() */
#define DUK_STRING_PUSH_SAFE              (1 << 0)    /* no error if file does not exist */

extern void duk_dump_context_stdout(duk_context *ctx);
extern void duk_dump_context_stderr(duk_context *ctx);
extern const char *duk_push_string_file_raw(duk_context *ctx, const char *path, duk_uint_t flags);
extern void duk_eval_file(duk_context *ctx, const char *path);
extern void duk_eval_file_noresult(duk_context *ctx, const char *path);
extern duk_int_t duk_peval_file(duk_context *ctx, const char *path);
extern duk_int_t duk_peval_file_noresult(duk_context *ctx, const char *path);
extern void duk_compile_file(duk_context *ctx, duk_uint_t flags, const char *path);
extern duk_int_t duk_pcompile_file(duk_context *ctx, duk_uint_t flags, const char *path);
extern void duk_to_defaultvalue(duk_context *ctx, duk_idx_t idx, duk_int_t hint);

#define duk_push_string_file(ctx,path) \
	duk_push_string_file_raw((ctx), (path), 0)

#if defined(__cplusplus)
}
#endif  /* end 'extern "C"' wrapper */

/*
 *  duk_dump_context_{stdout,stderr}()
 */

void duk_dump_context_stdout(duk_context *ctx) {
	duk_push_context_dump(ctx);
	fprintf(stdout, "%s\n", duk_safe_to_string(ctx, -1));
	duk_pop(ctx);
}

void duk_dump_context_stderr(duk_context *ctx) {
	duk_push_context_dump(ctx);
	fprintf(stderr, "%s\n", duk_safe_to_string(ctx, -1));
	duk_pop(ctx);
}

/*
 *  duk_push_string_file() and duk_push_string_file_raw()
 */

const char *duk_push_string_file_raw(duk_context *ctx, const char *path, duk_uint_t flags) {
	FILE *f = NULL;
	char *buf;
	long sz;  /* ANSI C typing */

	if (!path) {
		goto fail;
	}
	f = fopen(path, "rb");
	if (!f) {
		goto fail;
	}
	if (fseek(f, 0, SEEK_END) < 0) {
		goto fail;
	}
	sz = ftell(f);
	if (sz < 0) {
		goto fail;
	}
	if (fseek(f, 0, SEEK_SET) < 0) {
		goto fail;
	}
	buf = (char *) duk_push_fixed_buffer(ctx, (duk_size_t) sz);
	if ((size_t) fread(buf, 1, (size_t) sz, f) != (size_t) sz) {
		duk_pop(ctx);
		goto fail;
	}
	(void) fclose(f);  /* ignore fclose() error */
	return duk_buffer_to_string(ctx, -1);

 fail:
	if (f) {
		(void) fclose(f);  /* ignore fclose() error */
	}

	if (flags & DUK_STRING_PUSH_SAFE) {
		duk_push_undefined(ctx);
	} else {
		(void) duk_type_error(ctx, "read file error");
	}
	return NULL;
}

/*
 *  duk_eval_file(), duk_compile_file(), and their variants
 */

void duk_eval_file(duk_context *ctx, const char *path) {
	duk_push_string_file_raw(ctx, path, 0);
	duk_push_string(ctx, path);
	duk_compile(ctx, DUK_COMPILE_EVAL);
	duk_push_global_object(ctx);  /* 'this' binding */
	duk_call_method(ctx, 0);
}

void duk_eval_file_noresult(duk_context *ctx, const char *path) {
	duk_eval_file(ctx, path);
	duk_pop(ctx);
}

duk_int_t duk_peval_file(duk_context *ctx, const char *path) {
	duk_int_t rc;

	duk_push_string_file_raw(ctx, path, DUK_STRING_PUSH_SAFE);
	duk_push_string(ctx, path);
	rc = duk_pcompile(ctx, DUK_COMPILE_EVAL);
	if (rc != 0) {
		return rc;
	}
	duk_push_global_object(ctx);  /* 'this' binding */
	rc = duk_pcall_method(ctx, 0);
	return rc;
}

duk_int_t duk_peval_file_noresult(duk_context *ctx, const char *path) {
	duk_int_t rc;

	rc = duk_peval_file(ctx, path);
	duk_pop(ctx);
	return rc;
}

void duk_compile_file(duk_context *ctx, duk_uint_t flags, const char *path) {
	duk_push_string_file_raw(ctx, path, 0);
	duk_push_string(ctx, path);
	duk_compile(ctx, flags);
}

duk_int_t duk_pcompile_file(duk_context *ctx, duk_uint_t flags, const char *path) {
	duk_int_t rc;

	duk_push_string_file_raw(ctx, path, DUK_STRING_PUSH_SAFE);
	duk_push_string(ctx, path);
	rc = duk_pcompile(ctx, flags);
	return rc;
}

/*
 *  duk_to_defaultvalue()
 */

void duk_to_defaultvalue(duk_context *ctx, duk_idx_t idx, duk_int_t hint) {
	duk_require_type_mask(ctx, idx, DUK_TYPE_MASK_OBJECT |
	                                DUK_TYPE_MASK_BUFFER |
	                                DUK_TYPE_MASK_LIGHTFUNC);
	duk_to_primitive(ctx, idx, hint);
}


#define  ERROR_FROM_ERRNO(ctx)  do { \
		error("%s (errno=%d)", strerror(errno), errno); \
	} while (0)

static void set_nonblocking(duk_context *ctx, int fd) {
#ifndef WIN32
	int rc;
	int flags;

	rc = fcntl(fd, F_GETFL);
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}
	flags = rc;

	flags |= O_NONBLOCK;

	rc = fcntl(fd, F_SETFL, flags);
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}
#else
    unsigned long argp = 1;
    ioctlsocket(fd, FIONBIO, &argp);
#endif
}

static void set_reuseaddr(duk_context *ctx, int fd) {
	int val;
	int rc;

	val = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &val, sizeof(val));
	if (rc != 0) {
		ERROR_FROM_ERRNO(ctx);
	}
}

#if defined(__APPLE__)
static void set_nosigpipe(duk_context *ctx, int fd) {
	int val;
	int rc;

	val = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const void *) &val, sizeof(val));
	if (rc != 0) {
		ERROR_FROM_ERRNO(ctx);
	}
}
#endif

static int socket_create_server_socket(duk_context *ctx) {
	const char *addr = duk_to_string(ctx, 0);
	int port = duk_to_int(ctx, 1);
	int sock;
	struct sockaddr_in sockaddr;
	struct hostent *ent;
	struct in_addr **addr_list;
	struct in_addr *addr_inet;
	int i;
	int rc;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	set_nonblocking(ctx, sock);
	set_reuseaddr(ctx, sock);
#if defined(__APPLE__)
	set_nosigpipe(ctx, sock);
#endif

	ent = gethostbyname(addr);
	if (!ent) {
		ERROR_FROM_ERRNO(ctx);
	}

	addr_list = (struct in_addr **) ent->h_addr_list;
	addr_inet = NULL;
	for (i = 0; addr_list[i]; i++) {
		addr_inet = addr_list[i];
		break;
	}
	if (!addr_inet) {
		(void) duk_error(ctx, DUK_ERR_ERROR, "cannot resolve %s", addr);
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr = *addr_inet;

	rc = bind(sock, (const struct sockaddr *) &sockaddr, sizeof(sockaddr));
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	rc = listen(sock, 10 /*backlog*/);
	if (rc < 0) {
		(void) close(sock);
		ERROR_FROM_ERRNO(ctx);
	}

	duk_push_int(ctx, sock);
	return 1;
}

static int socket_close(duk_context *ctx) {
	int sock = duk_to_int(ctx, 0);
	int rc;

	rc = close(sock);
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}
	return 0;
}

static int socket_accept(duk_context *ctx) {
	int sock = duk_to_int(ctx, 0);
	int rc;
	struct sockaddr_in addr;
	socklen_t addrlen;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addrlen = sizeof(addr);

	rc = accept(sock, (struct sockaddr *) &addr, &addrlen);
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	set_nonblocking(ctx, sock);
#if defined(__APPLE__)
	set_nosigpipe(ctx, sock);
#endif

	if (addrlen == sizeof(addr)) {
		uint32_t tmp = ntohl(addr.sin_addr.s_addr);

		duk_push_object(ctx);

		duk_push_string(ctx, "fd");
		duk_push_int(ctx, rc);
		duk_put_prop(ctx, -3);
		duk_push_string(ctx, "addr");
		duk_push_sprintf(ctx, "%d.%d.%d.%d", ((tmp >> 24) & 0xff), ((tmp >> 16) & 0xff), ((tmp >> 8) & 0xff), (tmp & 0xff));
		duk_put_prop(ctx, -3);
		duk_push_string(ctx, "port");
		duk_push_int(ctx, ntohs(addr.sin_port));
		duk_put_prop(ctx, -3);

		return 1;
	}

	return 0;
}

static int socket_connect(duk_context *ctx) {
	const char *addr = duk_to_string(ctx, 0);
	int port = duk_to_int(ctx, 1);
	int sock;
	struct sockaddr_in sockaddr;
	struct hostent *ent;
	struct in_addr **addr_list;
	struct in_addr *addr_inet;
	int i;
	int rc;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	set_nonblocking(ctx, sock);
#if defined(__APPLE__)
	set_nosigpipe(ctx, sock);
#endif

	ent = gethostbyname(addr);
	if (!ent) {
		ERROR_FROM_ERRNO(ctx);
	}

	addr_list = (struct in_addr **) ent->h_addr_list;
	addr_inet = NULL;
	for (i = 0; addr_list[i]; i++) {
		addr_inet = addr_list[i];
		break;
	}
	if (!addr_inet) {
		(void) duk_error(ctx, DUK_ERR_ERROR, "cannot resolve %s", addr);
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr = *addr_inet;

	rc = connect(sock, (const struct sockaddr *) &sockaddr, (socklen_t) sizeof(sockaddr));
	if (rc < 0) {
		if (errno == EINPROGRESS) {
            LogErrorStr("connect() returned EINPROGRESS as expected, need to poll writability\n");
		} else {
			ERROR_FROM_ERRNO(ctx);
		}
	}

	duk_push_int(ctx, sock);
	return 1;
}

static int socket_read(duk_context *ctx) {
	int sock = duk_to_int(ctx, 0);
	char readbuf[1024];
	int rc;
	void *data;

	rc = recvfrom(sock, readbuf, sizeof(readbuf), 0, NULL, NULL);
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	data = duk_push_fixed_buffer(ctx, rc);
	memcpy(data, readbuf, rc);
	return 1;
}

static int socket_write(duk_context *ctx) {
	int sock = duk_to_int(ctx, 0);
	const char *data;
	size_t len;
	ssize_t rc;

	data = (const char *) duk_require_buffer_data(ctx, 1, &len);

	/* MSG_NOSIGNAL: avoid SIGPIPE */
#if defined(__APPLE__) || defined(WIN32)
	rc = sendto(sock, data, len, 0, NULL, 0);
#else
	rc = sendto(sock, data, len, MSG_NOSIGNAL, NULL, 0);
#endif
	if (rc < 0) {
		ERROR_FROM_ERRNO(ctx);
	}

	duk_push_int(ctx, rc);
	return 1;
}

static duk_function_list_entry socket_funcs[] = {
	{ "createServerSocket", socket_create_server_socket, 2 },
	{ "close", socket_close, 1 },
	{ "accept", socket_accept, 1 },
	{ "connect", socket_connect, 2 },
	{ "read", socket_read, 1 },
	{ "write", socket_write, 2 },
	{ NULL, NULL, 0 }
};

void duk_socket_register(duk_context *ctx) {
	/* Set global 'Socket'. */
	duk_push_global_object(ctx);
	duk_push_object(ctx);
	duk_put_function_list(ctx, -1, socket_funcs);
	duk_put_prop_string(ctx, -2, "Socket");
	duk_pop(ctx);
}


/* Initialize the console system */
extern void duk_console_init(duk_context *ctx, bool hasproxy);

static duk_ret_t duk__console_log_helper(duk_context *ctx, const char *error_name) {
	duk_idx_t n = duk_get_top(ctx);
	duk_idx_t i;

	duk_get_global_string(ctx, "console");
	duk_get_prop_string(ctx, -1, "format");

	for (i = 0; i < n; i++) {
		if (duk_check_type_mask(ctx, i, DUK_TYPE_MASK_OBJECT)) {
			/* Slow path formatting. */
			duk_dup(ctx, -1);  /* console.format */
			duk_dup(ctx, i);
			duk_call(ctx, 1);
			duk_replace(ctx, i);  /* arg[i] = console.format(arg[i]); */
		}
	}

	duk_pop_2(ctx);

	duk_push_string(ctx, " ");
	duk_insert(ctx, 0);
	duk_join(ctx, n);

	if (error_name) {
		duk_push_error_object(ctx, DUK_ERR_ERROR, "%s", duk_require_string(ctx, -1));
		duk_push_string(ctx, "name");
		duk_push_string(ctx, error_name);
		duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_VALUE);  /* to get e.g. 'Trace: 1 2 3' */
		duk_get_prop_string(ctx, -1, "stack");
	}

	LogPrintStr(std::string(duk_to_string(ctx, -1)) + "\n");

	return 0;
}

static duk_ret_t duk__console_assert(duk_context *ctx) {
	if (duk_to_boolean(ctx, 0)) {
		return 0;
	}
	duk_remove(ctx, 0);

	return duk__console_log_helper(ctx, "AssertionError");
}

static duk_ret_t duk__console_log(duk_context *ctx) {
	return duk__console_log_helper(ctx, NULL);
}

static duk_ret_t duk__console_trace(duk_context *ctx) {
	return duk__console_log_helper(ctx, "Trace");
}

static duk_ret_t duk__console_info(duk_context *ctx) {
	return duk__console_log_helper(ctx, NULL);
}

static duk_ret_t duk__console_warn(duk_context *ctx) {
	return duk__console_log_helper(ctx, NULL);
}

static duk_ret_t duk__console_error(duk_context *ctx) {
	return duk__console_log_helper(ctx, "Error");
}

static duk_ret_t duk__console_dir(duk_context *ctx) {
	/* For now, just share the formatting of .log() */
	return duk__console_log_helper(ctx, 0);
}

static void duk__console_reg_vararg_func(duk_context *ctx, duk_c_function func, const char *name) {
	duk_push_c_function(ctx, func, DUK_VARARGS);
	duk_push_string(ctx, "name");
	duk_push_string(ctx, name);
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_VALUE | DUK_DEFPROP_FORCE);  /* Improve stacktraces by displaying function name */
	duk_put_prop_string(ctx, -2, name);
}

void duk_console_init(duk_context *ctx, bool hasproxy) {
	duk_push_object(ctx);

	/* Custom function to format objects; user can replace.
	 * For now, try JX-formatting and if that fails, fall back
	 * to ToString(v).
	 */
	duk_eval_string(ctx,
		"(function (E) {"
		    "return function format(v){"
		        "try{"
		            "return E('jx',v);"
		        "}catch(e){"
		            "return String(v);"  /* String() allows symbols, ToString() internal algorithm doesn't. */
		        "}"
		    "};"
		"})(Duktape.enc)");
	duk_put_prop_string(ctx, -2, "format");


	duk__console_reg_vararg_func(ctx, duk__console_assert, "assert");
	duk__console_reg_vararg_func(ctx, duk__console_log, "log");
	duk__console_reg_vararg_func(ctx, duk__console_log, "debug");  /* alias to console.log */
	duk__console_reg_vararg_func(ctx, duk__console_trace, "trace");
	duk__console_reg_vararg_func(ctx, duk__console_info, "info");

	duk__console_reg_vararg_func(ctx, duk__console_warn, "warn");
	duk__console_reg_vararg_func(ctx, duk__console_error, "error");
	duk__console_reg_vararg_func(ctx, duk__console_error, "exception");  /* alias to console.error */
	duk__console_reg_vararg_func(ctx, duk__console_dir, "dir");

	duk_put_global_string(ctx, "console");

	/* Proxy wrapping: ensures any undefined console method calls are
	 * ignored silently.  This was required specifically by the
	 * DeveloperToolsWG proposal (and was implemented also by Firefox:
	 * https://bugzilla.mozilla.org/show_bug.cgi?id=629607).  This is
	 * apparently no longer the preferred way of implementing console.
	 * When Proxy is enabled, whitelist at least .toJSON() to avoid
	 * confusing JX serialization of the console object.
	 */

	if (hasproxy) {
		/* Tolerate failure to initialize Proxy wrapper in case
		 * Proxy support is disabled.
		 */
		(void) duk_peval_string_noresult(ctx,
			"(function(){"
			    "var D=function(){};"
			    "var W={toJSON:true};"  /* whitelisted */
			    "console=new Proxy(console,{"
			        "get:function(t,k){"
			            "var v=t[k];"
			            "return typeof v==='function'||W[k]?v:D;"
			        "}"
			    "});"
			"})();"
		);
	}
}


static duk_ret_t fileio_read_file(duk_context *ctx) {
	const char *fn;
	char *buf;
	size_t len;
	size_t off;
	int rc;
	FILE *f;

	fn = duk_require_string(ctx, 0);
	f = fopen(fn, "rb");
	if (!f) {
		(void) duk_type_error(ctx, "cannot open file %s for reading, errno %ld: %s",
		                      fn, (long) errno, strerror(errno));
	}

	rc = fseek(f, 0, SEEK_END);
	if (rc < 0) {
		(void) fclose(f);
		(void) duk_type_error(ctx, "fseek() failed for %s, errno %ld: %s",
		                      fn, (long) errno, strerror(errno));
	}
	len = (size_t) ftell(f);
	rc = fseek(f, 0, SEEK_SET);
	if (rc < 0) {
		(void) fclose(f);
		(void) duk_type_error(ctx, "fseek() failed for %s, errno %ld: %s",
		                      fn, (long) errno, strerror(errno));
	}

	buf = (char *) duk_push_fixed_buffer(ctx, (duk_size_t) len);
	for (off = 0; off < len;) {
		size_t got;
		got = fread((void *) (buf + off), 1, len - off, f);
		if (ferror(f)) {
			(void) fclose(f);
			(void) duk_type_error(ctx, "error while reading %s", fn);
		}
		if (got == 0) {
			if (feof(f)) {
				break;
			} else {
				(void) fclose(f);
				(void) duk_type_error(ctx, "error while reading %s", fn);
			}
		}
		off += got;
	}

	if (f) {
		(void) fclose(f);
	}

	return 1;
}

static duk_ret_t fileio_write_file(duk_context *ctx) {
	const char *fn;
	const char *buf;
	size_t len;
	size_t off;
	FILE *f;

	fn = duk_require_string(ctx, 0);
	f = fopen(fn, "wb");
	if (!f) {
		(void) duk_type_error(ctx, "cannot open file %s for writing, errno %ld: %s",
		          fn, (long) errno, strerror(errno));
	}

	len = 0;
	buf = (char *) duk_require_buffer_data(ctx, 1, &len);
	for (off = 0; off < len;) {
		size_t got;
		got = fwrite((const void *) (buf + off), 1, len - off, f);
		if (ferror(f)) {
			(void) fclose(f);
			(void) duk_type_error(ctx, "error while writing %s", fn);
		}
		if (got == 0) {
			(void) fclose(f);
			(void) duk_type_error(ctx, "error while writing %s", fn);
		}
		off += got;
	}

	if (f) {
		(void) fclose(f);
	}

	return 0;
}


static duk_ret_t duk_native_print(duk_context *ctx) {
	duk_push_string(ctx, " ");
	duk_insert(ctx, 0);
	duk_join(ctx, duk_get_top(ctx) - 1);
	LogPrintf("%s\n", duk_safe_to_string(ctx, -1));
	return 0;
}

static void duk_print_register(duk_context *ctx) {
	duk_push_c_function(ctx, duk_native_print, DUK_VARARGS);
	duk_put_global_string(ctx, "print");
}

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf _snprintf
#endif

#if 0  /* Enable manually */
#define DUK__ASSERT(x) do { \
		if (!(x)) { \
			fprintf(stderr, "ASSERTION FAILED at %s:%d: " #x "\n", __FILE__, __LINE__); \
			fflush(stderr);  \
		} \
	} while (0)
#define DUK__ASSERT_TOP(ctx,val) do { \
		DUK__ASSERT(duk_get_top((ctx)) == (val)); \
	} while (0)
#else
#define DUK__ASSERT(x) do { (void) (x); } while (0)
#define DUK__ASSERT_TOP(ctx,val) do { (void) ctx; (void) (val); } while (0)
#endif

static void duk__resolve_module_id(duk_context *ctx, const char *req_id, const char *mod_id) {
	duk_uint8_t buf[DUK_COMMONJS_MODULE_ID_LIMIT];
	duk_uint8_t *p;
	duk_uint8_t *q;
	duk_uint8_t *q_last;  /* last component */
	duk_int_t int_rc;

	DUK__ASSERT(req_id != NULL);
	/* mod_id may be NULL */

	/*
	 *  A few notes on the algorithm:
	 *
	 *    - Terms are not allowed to begin with a period unless the term
	 *      is either '.' or '..'.  This simplifies implementation (and
	 *      is within CommonJS modules specification).
	 *
	 *    - There are few output bound checks here.  This is on purpose:
	 *      the resolution input is length checked and the output is never
	 *      longer than the input.  The resolved output is written directly
	 *      over the input because it's never longer than the input at any
	 *      point in the algorithm.
	 *
	 *    - Non-ASCII characters are processed as individual bytes and
	 *      need no special treatment.  However, U+0000 terminates the
	 *      algorithm; this is not an issue because U+0000 is not a
	 *      desirable term character anyway.
	 */

	/*
	 *  Set up the resolution input which is the requested ID directly
	 *  (if absolute or no current module path) or with current module
	 *  ID prepended (if relative and current module path exists).
	 *
	 *  Suppose current module is 'foo/bar' and relative path is './quux'.
	 *  The 'bar' component must be replaced so the initial input here is
	 *  'foo/bar/.././quux'.
	 */

	if (mod_id != NULL && req_id[0] == '.') {
		int_rc = snprintf((char *) buf, sizeof(buf), "%s/../%s", mod_id, req_id);
	} else {
		int_rc = snprintf((char *) buf, sizeof(buf), "%s", req_id);
	}
	if (int_rc >= (duk_int_t) sizeof(buf) || int_rc < 0) {
		/* Potentially truncated, NUL not guaranteed in any case.
		 * The (int_rc < 0) case should not occur in practice.
		 */
		goto resolve_error;
	}
	DUK__ASSERT(strlen((const char *) buf) < sizeof(buf));  /* at most sizeof(buf) - 1 */

	/*
	 *  Resolution loop.  At the top of the loop we're expecting a valid
	 *  term: '.', '..', or a non-empty identifier not starting with a period.
	 */

	p = buf;
	q = buf;
	for (;;) {
		duk_uint_fast8_t c;

		/* Here 'p' always points to the start of a term.
		 *
		 * We can also unconditionally reset q_last here: if this is
		 * the last (non-empty) term q_last will have the right value
		 * on loop exit.
		 */

		DUK__ASSERT(p >= q);  /* output is never longer than input during resolution */

		q_last = q;

		c = *p++;
		if (c == 0) {
			goto resolve_error;
		} else if (c == '.') {
			c = *p++;
			if (c == '/') {
				/* Term was '.' and is eaten entirely (including dup slashes). */
				goto eat_dup_slashes;
			}
			if (c == '.' && *p == '/') {
				/* Term was '..', backtrack resolved name by one component.
				 *  q[-1] = previous slash (or beyond start of buffer)
				 *  q[-2] = last char of previous component (or beyond start of buffer)
				 */
				p++;  /* eat (first) input slash */
				DUK__ASSERT(q >= buf);
				if (q == buf) {
					goto resolve_error;
				}
				DUK__ASSERT(*(q - 1) == '/');
				q--;  /* Backtrack to last output slash (dups already eliminated). */
				for (;;) {
					/* Backtrack to previous slash or start of buffer. */
					DUK__ASSERT(q >= buf);
					if (q == buf) {
						break;
					}
					if (*(q - 1) == '/') {
						break;
					}
					q--;
				}
				goto eat_dup_slashes;
			}
			goto resolve_error;
		} else if (c == '/') {
			/* e.g. require('/foo'), empty terms not allowed */
			goto resolve_error;
		} else {
			for (;;) {
				/* Copy term name until end or '/'. */
				*q++ = c;
				c = *p++;
				if (c == 0) {
					/* This was the last term, and q_last was
					 * updated to match this term at loop top.
					 */
					goto loop_done;
				} else if (c == '/') {
					*q++ = '/';
					break;
				} else {
					/* write on next loop */
				}
			}
		}

	 eat_dup_slashes:
		for (;;) {
			/* eat dup slashes */
			c = *p;
			if (c != '/') {
				break;
			}
			p++;
		}
	}
 loop_done:
	/* Output #1: resolved absolute name. */
	DUK__ASSERT(q >= buf);
	duk_push_lstring(ctx, (const char *) buf, (size_t) (q - buf));

	/* Output #2: last component name. */
	DUK__ASSERT(q >= q_last);
	DUK__ASSERT(q_last >= buf);
	duk_push_lstring(ctx, (const char *) q_last, (size_t) (q - q_last));
	return;

 resolve_error:
	(void) duk_type_error(ctx, "cannot resolve module id: %s", (const char *) req_id);
}

/* Stack indices for better readability. */
#define DUK__IDX_REQUESTED_ID   0   /* module id requested */
#define DUK__IDX_REQUIRE        1   /* current require() function */
#define DUK__IDX_REQUIRE_ID     2   /* the base ID of the current require() function, resolution base */
#define DUK__IDX_RESOLVED_ID    3   /* resolved, normalized absolute module ID */
#define DUK__IDX_LASTCOMP       4   /* last component name in resolved path */
#define DUK__IDX_DUKTAPE        5   /* Duktape object */
#define DUK__IDX_MODLOADED      6   /* Duktape.modLoaded[] module cache */
#define DUK__IDX_UNDEFINED      7   /* 'undefined', artifact of lookup */
#define DUK__IDX_FRESH_REQUIRE  8   /* new require() function for module, updated resolution base */
#define DUK__IDX_EXPORTS        9   /* default exports table */
#define DUK__IDX_MODULE         10  /* module object containing module.exports, etc */

static duk_ret_t duk__require(duk_context *ctx) {
	const char *str_req_id;  /* requested identifier */
	const char *str_mod_id;  /* require.id of current module */
	duk_int_t pcall_rc;

	/* NOTE: we try to minimize code size by avoiding unnecessary pops,
	 * so the stack looks a bit cluttered in this function.  DUK__ASSERT_TOP()
	 * assertions are used to ensure stack configuration is correct at each
	 * step.
	 */

	/*
	 *  Resolve module identifier into canonical absolute form.
	 */

	str_req_id = duk_require_string(ctx, DUK__IDX_REQUESTED_ID);
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "id");
	str_mod_id = duk_get_string(ctx, DUK__IDX_REQUIRE_ID);  /* ignore non-strings */
	duk__resolve_module_id(ctx, str_req_id, str_mod_id);
	str_req_id = NULL;
	str_mod_id = NULL;

	/* [ requested_id require require.id resolved_id last_comp ] */
	DUK__ASSERT_TOP(ctx, DUK__IDX_LASTCOMP + 1);

	/*
	 *  Cached module check.
	 *
	 *  If module has been loaded or its loading has already begun without
	 *  finishing, return the same cached value (module.exports).  The
	 *  value is registered when module load starts so that circular
	 *  references can be supported to some extent.
	 */

	duk_push_global_stash(ctx);
	duk_get_prop_string(ctx, -1, "\xff" "module:Duktape");
	duk_remove(ctx, -2);  /* Lookup stashed, original 'Duktape' object. */
	duk_get_prop_string(ctx, DUK__IDX_DUKTAPE, "modLoaded");  /* Duktape.modLoaded */
	duk_require_type_mask(ctx, DUK__IDX_MODLOADED, DUK_TYPE_MASK_OBJECT);
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODLOADED + 1);

	duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	if (duk_get_prop(ctx, DUK__IDX_MODLOADED)) {
		/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded Duktape.modLoaded[id] ] */
		duk_get_prop_string(ctx, -1, "exports");  /* return module.exports */
		return 1;
	}
	DUK__ASSERT_TOP(ctx, DUK__IDX_UNDEFINED + 1);

	/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded undefined ] */

	/*
	 *  Module not loaded (and loading not started previously).
	 *
	 *  Create a new require() function with 'id' set to resolved ID
	 *  of module being loaded.  Also create 'exports' and 'module'
	 *  tables but don't register exports to the loaded table yet.
	 *  We don't want to do that unless the user module search callbacks
	 *  succeeds in finding the module.
	 */

	/* Fresh require: require.id is left configurable (but not writable)
	 * so that is not easy to accidentally tweak it, but it can still be
	 * done with Object.defineProperty().
	 *
	 * XXX: require.id could also be just made non-configurable, as there
	 * is no practical reason to touch it (at least from ECMAScript code).
	 */
	duk_push_c_function(ctx, duk__require, 1 /*nargs*/);
	duk_push_string(ctx, "name");
	duk_push_string(ctx, "require");
	duk_def_prop(ctx, DUK__IDX_FRESH_REQUIRE, DUK_DEFPROP_HAVE_VALUE);  /* not writable, not enumerable, not configurable */
	duk_push_string(ctx, "id");
	duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	duk_def_prop(ctx, DUK__IDX_FRESH_REQUIRE, DUK_DEFPROP_HAVE_VALUE | DUK_DEFPROP_SET_CONFIGURABLE);  /* a fresh require() with require.id = resolved target module id */

	/* Module table:
	 * - module.exports: initial exports table (may be replaced by user)
	 * - module.id is non-writable and non-configurable, as the CommonJS
	 *   spec suggests this if possible
	 * - module.filename: not set, defaults to resolved ID if not explicitly
	 *   set by modSearch() (note capitalization, not .fileName, matches Node.js)
	 * - module.name: not set, defaults to last component of resolved ID if
	 *   not explicitly set by modSearch()
	 */
	duk_push_object(ctx);  /* exports */
	duk_push_object(ctx);  /* module */
	duk_push_string(ctx, "exports");
	duk_dup(ctx, DUK__IDX_EXPORTS);
	duk_def_prop(ctx, DUK__IDX_MODULE, DUK_DEFPROP_HAVE_VALUE | DUK_DEFPROP_SET_WRITABLE | DUK_DEFPROP_SET_CONFIGURABLE);  /* module.exports = exports */
	duk_push_string(ctx, "id");
	duk_dup(ctx, DUK__IDX_RESOLVED_ID);  /* resolved id: require(id) must return this same module */
	duk_def_prop(ctx, DUK__IDX_MODULE, DUK_DEFPROP_HAVE_VALUE);  /* module.id = resolved_id; not writable, not enumerable, not configurable */
	duk_compact(ctx, DUK__IDX_MODULE);  /* module table remains registered to modLoaded, minimize its size */
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODULE + 1);

	/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded undefined fresh_require exports module ] */

	/* Register the module table early to modLoaded[] so that we can
	 * support circular references even in modSearch().  If an error
	 * is thrown, we'll delete the reference.
	 */
	duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	duk_dup(ctx, DUK__IDX_MODULE);
	duk_put_prop(ctx, DUK__IDX_MODLOADED);  /* Duktape.modLoaded[resolved_id] = module */

	/*
	 *  Call user provided module search function and build the wrapped
	 *  module source code (if necessary).  The module search function
	 *  can be used to implement pure Ecmacsript, pure C, and mixed
	 *  ECMAScript/C modules.
	 *
	 *  The module search function can operate on the exports table directly
	 *  (e.g. DLL code can register values to it).  It can also return a
	 *  string which is interpreted as module source code (if a non-string
	 *  is returned the module is assumed to be a pure C one).  If a module
	 *  cannot be found, an error must be thrown by the user callback.
	 *
	 *  Because Duktape.modLoaded[] already contains the module being
	 *  loaded, circular references for C modules should also work
	 *  (although expected to be quite rare).
	 */

	duk_push_string(ctx, "(function(require,exports,module){");

	/* Duktape.modSearch(resolved_id, fresh_require, exports, module). */
	duk_get_prop_string(ctx, DUK__IDX_DUKTAPE, "modSearch");  /* Duktape.modSearch */
	duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	duk_dup(ctx, DUK__IDX_FRESH_REQUIRE);
	duk_dup(ctx, DUK__IDX_EXPORTS);
	duk_dup(ctx, DUK__IDX_MODULE);  /* [ ... Duktape.modSearch resolved_id last_comp fresh_require exports module ] */
	pcall_rc = duk_pcall(ctx, 4 /*nargs*/);  /* -> [ ... source ] */
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODULE + 3);

	if (pcall_rc != DUK_EXEC_SUCCESS) {
		/* Delete entry in Duktape.modLoaded[] and rethrow. */
		goto delete_rethrow;
	}

	/* If user callback did not return source code, module loading
	 * is finished (user callback initialized exports table directly).
	 */
	if (!duk_is_string(ctx, -1)) {
		/* User callback did not return source code, so module loading
		 * is finished: just update modLoaded with final module.exports
		 * and we're done.
		 */
		goto return_exports;
	}

	/* Finish the wrapped module source.  Force module.filename as the
	 * function .fileName so it gets set for functions defined within a
	 * module.  This also ensures loggers created within the module get
	 * the module ID (or overridden filename) as their default logger name.
	 * (Note capitalization: .filename matches Node.js while .fileName is
	 * used elsewhere in Duktape.)
	 */
	duk_push_string(ctx, "\n})");  /* Newline allows module last line to contain a // comment. */
	duk_concat(ctx, 3);
	if (!duk_get_prop_string(ctx, DUK__IDX_MODULE, "filename")) {
		/* module.filename for .fileName, default to resolved ID if
		 * not present.
		 */
		duk_pop(ctx);
		duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	}
	pcall_rc = duk_pcompile(ctx, DUK_COMPILE_EVAL);
	if (pcall_rc != DUK_EXEC_SUCCESS) {
		goto delete_rethrow;
	}
	pcall_rc = duk_pcall(ctx, 0);  /* -> eval'd function wrapper (not called yet) */
	if (pcall_rc != DUK_EXEC_SUCCESS) {
		goto delete_rethrow;
	}

	/* Module has now evaluated to a wrapped module function.  Force its
	 * .name to match module.name (defaults to last component of resolved
	 * ID) so that it is shown in stack traces too.  Note that we must not
	 * introduce an actual name binding into the function scope (which is
	 * usually the case with a named function) because it would affect the
	 * scope seen by the module and shadow accesses to globals of the same name.
	 * This is now done by compiling the function as anonymous and then forcing
	 * its .name without setting a "has name binding" flag.
	 */

	duk_push_string(ctx, "name");
	if (!duk_get_prop_string(ctx, DUK__IDX_MODULE, "name")) {
		/* module.name for .name, default to last component if
		 * not present.
		 */
		duk_pop(ctx);
		duk_dup(ctx, DUK__IDX_LASTCOMP);
	}
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_VALUE | DUK_DEFPROP_FORCE);

	/*
	 *  Call the wrapped module function.
	 *
	 *  Use a protected call so that we can update Duktape.modLoaded[resolved_id]
	 *  even if the module throws an error.
	 */

	/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded undefined fresh_require exports module mod_func ] */
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODULE + 2);

	duk_dup(ctx, DUK__IDX_EXPORTS);  /* exports (this binding) */
	duk_dup(ctx, DUK__IDX_FRESH_REQUIRE);  /* fresh require (argument) */
	duk_get_prop_string(ctx, DUK__IDX_MODULE, "exports");  /* relookup exports from module.exports in case it was changed by modSearch */
	duk_dup(ctx, DUK__IDX_MODULE);  /* module (argument) */
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODULE + 6);

	/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded undefined fresh_require exports module mod_func exports fresh_require exports module ] */

	pcall_rc = duk_pcall_method(ctx, 3 /*nargs*/);
	if (pcall_rc != DUK_EXEC_SUCCESS) {
		/* Module loading failed.  Node.js will forget the module
		 * registration so that another require() will try to load
		 * the module again.  Mimic that behavior.
		 */
		goto delete_rethrow;
	}

	/* [ requested_id require require.id resolved_id last_comp Duktape Duktape.modLoaded undefined fresh_require exports module result(ignored) ] */
	DUK__ASSERT_TOP(ctx, DUK__IDX_MODULE + 2);

	/* fall through */

 return_exports:
	duk_get_prop_string(ctx, DUK__IDX_MODULE, "exports");
	duk_compact(ctx, -1);  /* compact the exports table */
	return 1;  /* return module.exports */

 delete_rethrow:
	duk_dup(ctx, DUK__IDX_RESOLVED_ID);
	duk_del_prop(ctx, DUK__IDX_MODLOADED);  /* delete Duktape.modLoaded[resolved_id] */
	(void) duk_throw(ctx);  /* rethrow original error */
	return 0;  /* not reachable */
}

void duk_module_register(duk_context *ctx) {
	/* Stash 'Duktape' in case it's modified. */
	duk_push_global_stash(ctx);
	duk_get_global_string(ctx, "Duktape");
	duk_put_prop_string(ctx, -2, "\xff" "module:Duktape");
	duk_pop(ctx);

	/* Register `require` as a global function. */
	duk_eval_string(ctx,
		"(function(req){"
		"var D=Object.defineProperty;"
		"D(req,'name',{value:'require'});"
		"D(this,'require',{value:req,writable:true,configurable:true});"
		"D(Duktape,'modLoaded',{value:Object.create(null),writable:true,configurable:true});"
		"})");
	duk_push_c_function(ctx, duk__require, 1 /*nargs*/);
	duk_call(ctx, 1);
	duk_pop(ctx);
}

#undef DUK__ASSERT
#undef DUK__ASSERT_TOP
#undef DUK__IDX_REQUESTED_ID
#undef DUK__IDX_REQUIRE
#undef DUK__IDX_REQUIRE_ID
#undef DUK__IDX_RESOLVED_ID
#undef DUK__IDX_LASTCOMP
#undef DUK__IDX_DUKTAPE
#undef DUK__IDX_MODLOADED
#undef DUK__IDX_UNDEFINED
#undef DUK__IDX_FRESH_REQUIRE
#undef DUK__IDX_EXPORTS
#undef DUK__IDX_MODULE


const char *polyfill =
"function setTimeout(func, delay) {"
"   var cb_func;"
"   var bind_args;"
"   var timer_id;"
"   if (typeof delay !== 'number') {"
"       if (typeof delay === 'undefined') {"
"           delay = 0;"
"       } else {"
"           throw new TypeError('invalid delay');"
"       }"
"   }"
"   if (typeof func === 'string') {"
"       cb_func = eval.bind(this, func);"
"   } else if (typeof func !== 'function') {"
"       throw new TypeError('callback is not a function/string');"
"   } else if (arguments.length > 2) {"
"       bind_args = Array.prototype.slice.call(arguments, 2);"
"       bind_args.unshift(this);"
"       cb_func = func.bind.apply(func, bind_args);"
"   } else {"
"       cb_func = func;"
"   }"
"   timer_id = EventLoop.createTimer(cb_func, delay, true);"
"   return timer_id;"
"}"
"function clearTimeout(timer_id) {"
"   if (typeof timer_id !== 'number') {"
"       throw new TypeError('timer ID is not a number');"
"   }"
"   var success = EventLoop.deleteTimer(timer_id);"
"}"
"function setInterval(func, delay) {"
"   var cb_func;"
"   var bind_args;"
"   var timer_id;"
"   if (typeof delay !== 'number') {"
"       if (typeof delay === 'undefined') {"
"           delay = 0;"
"       } else {"
"           throw new TypeError('invalid delay');"
"       }"
"   }"
"   if (typeof func === 'string') {"
"       cb_func = eval.bind(this, func);"
"   } else if (typeof func !== 'function') {"
"       throw new TypeError('callback is not a function/string');"
"   } else if (arguments.length > 2) {"
"       bind_args = Array.prototype.slice.call(arguments, 2);"
"       bind_args.unshift(this);"
"       cb_func = func.bind.apply(func, bind_args);"
"   } else {"
"       cb_func = func;"
"   }"
"   timer_id = EventLoop.createTimer(cb_func, delay, false);"
"   return timer_id;"
"}"
"function clearInterval(timer_id) {"
"   if (typeof timer_id !== 'number') {"
"       throw new TypeError('timer ID is not a number');"
"   }"
"   EventLoop.deleteTimer(timer_id);"
"}"
"function requestEventLoopExit() {"
"   EventLoop.requestExit();"
"}"
"EventLoop.socketListening = {};"
"EventLoop.socketReading = {};"
"EventLoop.socketConnecting = {};"
"EventLoop.fdPollHandler = function(fd, revents) {"
"   var data;"
"   var cb;"
"   var rc;"
"   var acc_res;"
"   if (revents & Poll.POLLIN) {"
"       cb = this.socketReading[fd];"
"       if (cb) {"
"           data = Socket.read(fd);"
"           if (data.length === 0) {"
"               this.close(fd);"
"               return;"
"           }"
"           cb(fd, data);"
"       } else {"
"           cb = this.socketListening[fd];"
"           if (cb) {"
"               acc_res = Socket.accept(fd);"
"               cb(acc_res.fd, acc_res.addr, acc_res.port);"
"           }"
"       }"
"   }"
"   if (revents & Poll.POLLOUT) {"
"       cb = this.socketConnecting[fd];"
"       if (cb) {"
"           delete this.socketConnecting[fd];"
"           cb(fd);"
"       }"
"   }"
"   if ((revents & ~(Poll.POLLIN | Poll.POLLOUT)) !== 0)"
"       this.close(fd);"
"}"
"EventLoop.server = function(address, port, cb_accepted) {"
"   var fd = Socket.createServerSocket(address, port);"
"   this.socketListening[fd] = cb_accepted;"
"   this.listenFd(fd, Poll.POLLIN);"
"}"
"EventLoop.connect = function(address, port, cb_connected) {"
"   var fd = Socket.connect(address, port);"
"   this.socketConnecting[fd] = cb_connected;"
"   this.listenFd(fd, Poll.POLLOUT);"
"}"
"EventLoop.close = function(fd) {"
"   EventLoop.listenFd(fd, 0);"
"   delete this.socketListening[fd];"
"   delete this.socketReading[fd];"
"   delete this.socketConnecting[fd];"
"   Socket.close(fd);"
"}"
"EventLoop.setReader = function(fd, cb_read) {"
"   this.socketReading[fd] = cb_read;"
"   this.listenFd(fd, Poll.POLLIN);"
"}"
"EventLoop.write = function(fd, data) {"
"   if (typeof data === 'string') {"
"       data = new TextEncoder().encode(data);"
"   }"
"   var rc = Socket.write(fd, data);"
"}";


bool GSInit() {
    ctx = duk_create_heap_default();
    if (!ctx) return false;

    duk_console_init(ctx, false);
	duk_print_register(ctx);
	duk_socket_register(ctx);
	duk_module_register(ctx);

    duk_peval_string_noresult(ctx, polyfill);

    return true;
}

void GSShutdown() {
    if (ctx) duk_destroy_heap(ctx);
}

bool GSExec(const std::string &code) {
    if (code.empty()) return false;
	duk_push_global_object(ctx);
    duk_peval_string_noresult(ctx, code.c_str());
	return true;
}

bool GSLoadBinary(const std::vector<uint8_t> &code) {
    if (code.empty()) return false;
	void *p = duk_push_buffer(ctx, code.size(), 0);
	memcpy(p, code.data(), code.size());
	duk_load_function(ctx);
    return true;
}

bool GSExecBinary(const std::vector<uint8_t> &code) {
    if (code.empty()) return false;
	if (!GSLoadBinary(code)) return false;
	if (duk_pcall(ctx, 0) != DUK_EXEC_SUCCESS) {
        LogPrintf("Script Error: %s\n", duk_safe_to_string(ctx, -1));
        return false;
    }
    return true;
}