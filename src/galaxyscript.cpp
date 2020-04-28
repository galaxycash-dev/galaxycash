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

#include <regex>

extern "C" {
    #include "duktape.c"
}
#include <dukglue/dukglue.h>

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

#include <fcntl.h>

//example:
//  write(stdin_fileno, buffer, size)
//  read(stdout_fileno, buffer, size)
typedef struct {
    void* proc;
    int pid;
    int stdin_fileno;
    int stdout_fileno;
}subprocess_t;


static duk_context *ctx = nullptr;


//linux maybe utf-8
#ifdef WIN32
#define DUKLIB_DEFAULT_SYSENCODING    "GBK"


#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>



#include <windows.h>
#include <io.h>



//  parent ---write---> pipe ---read---> child
//         inheritance        heritance
static BOOL _create_pipe_stdin(HANDLE* stdin_rd, HANDLE* stdin_wr);

//  parent <---read--- pipe <---write--- child
//         inheritance       heritance
static BOOL _create_pipe_stdout(HANDLE* stdout_rd, HANDLE* stdout_wr);

static int _parse_environment_path_var(char** * result);
static void _destroy_environment_path_result(char** result, int nr_paths);
static BOOL _is_file_exists(const char* fn);
static char* _find_image_path(char* file);
static char* _combine_args(char* args[]);


BOOL _create_pipe_stdin(HANDLE* stdin_rd, HANDLE* stdin_wr)
{
    HANDLE pipe_rd;
    HANDLE pipe_wr;
    HANDLE pipe_wr_dup;
    SECURITY_ATTRIBUTES attr; 
    BOOL success;

    //prepare stdout pipe
    ZeroMemory(&attr, sizeof(attr));
    attr.nLength               = sizeof(attr);
    attr.bInheritHandle        = TRUE;
    attr.lpSecurityDescriptor  = NULL;
    success = CreatePipe(&pipe_rd, &pipe_wr, &attr, 0);
    if (!success) {
        return FALSE;
    }

    success = DuplicateHandle(GetCurrentProcess(), pipe_wr,
            GetCurrentProcess(), &pipe_wr_dup,
            0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!success) {
        CloseHandle(pipe_rd);
        CloseHandle(pipe_wr);
        return FALSE;
    }

    CloseHandle(pipe_wr);
    *stdin_rd = pipe_rd;
    *stdin_wr = pipe_wr_dup;

    return TRUE;
}

BOOL _create_pipe_stdout(HANDLE* stdout_rd, HANDLE* stdout_wr)
{
    HANDLE pipe_wr;
    HANDLE pipe_rd;
    HANDLE pipe_rd_dup;
    SECURITY_ATTRIBUTES attr; 
    BOOL success;

    //prepare stdout pipe
    ZeroMemory(&attr, sizeof(attr));
    attr.nLength               = sizeof(attr);
    attr.bInheritHandle        = TRUE;
    attr.lpSecurityDescriptor  = NULL;
    success = CreatePipe(&pipe_rd, &pipe_wr, &attr, 0);
    if (!success) {
        return FALSE;
    }

    success = DuplicateHandle(GetCurrentProcess(), pipe_rd,
            GetCurrentProcess(), &pipe_rd_dup,
            0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!success) {
        CloseHandle(pipe_rd);
        CloseHandle(pipe_wr);
        return FALSE;
    }

    CloseHandle(pipe_rd);
    *stdout_rd = pipe_rd_dup;
    *stdout_wr = pipe_wr;

    return TRUE;
}

int _parse_environment_path_var(char** * result)
{
    char* env_path;
    int nr_bytes;//inclued '\0'

    char** paths = NULL;
    int nr_paths = 0;

    char* pend;
    char* prev;
    char* p;
    char* q;

    int i;

    ////Test
    //SetEnvironmentVariable("PATH", "C:\\Windows ; C:\\Windows\\System32; ;");

    nr_bytes = GetEnvironmentVariable("PATH", NULL, 0);
    if (nr_bytes > 0) {
        env_path = (char*)malloc(nr_bytes);
        GetEnvironmentVariable("PATH", env_path, nr_bytes);
        for (i = 0;i < nr_bytes;i++) {
            if (env_path[i] == '/') {
                env_path[i] = '\\';
            }
        }

        prev = NULL;
        pend = env_path + nr_bytes-1;
        p = env_path;

        while (p < pend) {
            if ((prev == NULL) && !isspace(*p)) {
                prev = p;
                continue;
            } 
            
            if (*p == ';') {
                if (prev != NULL) {
                    for (q = p;prev < q;q--) {
                        if (!isspace(q[-1])) {
                            break;
                        }
                    }

                    if (q - prev > 0) {
                        if (paths == NULL) {
                            nr_paths = 0;
                            paths = (char**)malloc(sizeof(char*) * (nr_paths + 1));
                        } else {
                            paths = (char**)realloc(paths, sizeof(char*) * (nr_paths + 1));
                        }

                        paths[nr_paths] = (char*)malloc(q - prev + 1);
                        memset(paths[nr_paths], 0, q - prev + 1);
                        memcpy(paths[nr_paths], prev, q - prev);

                        nr_paths++;
                    }
                }
                prev = NULL;
            }

            p++;
        }
    }

    *result = paths;

    return nr_paths;
}

void _destroy_environment_path_result(char** result, int nr_paths)
{
    int i;

    for (i = 0;i < nr_paths;i++) {
        free(result[i]);
    }

    free(result);
}

BOOL _is_file_exists(const char* fn)
{
    fs::path p = fn;
    if (!fs::exists(p)) return FALSE;
    if (fs::is_directory(p)) return FALSE;
    return TRUE;
}

char* _find_image_path(char* file)
{
    char* appname = NULL;

    char** paths;
    int nr_paths;
    int path_size;
    char* args0;
    int args0_size;
    char ext[4];
    int i;

    ////////////////////////////////////////////////////////
    //check extension name
    args0_size = strlen(file);
    if (args0_size <= 0) {
        return NULL;
    }

    args0 = (char*)malloc(args0_size + 4 + 1);
    memset(args0, 0, args0_size + 4 + 1);
    memcpy(args0, file, args0_size);
    memcpy(ext, args0 + args0_size - 4, 4);

    ext[0] = tolower(ext[0]);
    ext[1] = tolower(ext[1]);
    ext[2] = tolower(ext[2]);
    ext[3] = tolower(ext[3]);
    if (strncmp(ext, ".exe", 4) != 0) {
        strcat(args0, ".exe");
    }
    args0_size = strlen(args0);

    if ((args0[0] == '.') && (args0[1] == '\\')) {
        return args0;
    } 
    if ((args0[0] == '.') && (args0[1] == '.') && (args0[2] == '\\')) {
        return args0;
    } 
    if (_is_file_exists(args0)) {
        return args0;
    }

    ////////////////////////////////////////////////////////
    //build appname from PATH environment
    nr_paths = _parse_environment_path_var(&paths);
    if (nr_paths <= 0) {
        return args0;
    }

    for (i = 0;i < nr_paths;i++) {
        path_size = strlen(paths[i]);
        appname = (char*)malloc(path_size + 1 + args0_size + 1);
        memset(appname, 0, path_size + 1 + args0_size + 1);
        memcpy(appname, paths[i], path_size);
        if (appname[path_size-1] != '\\') {
            appname[path_size++] = '\\';
        }
        memcpy(appname+path_size, args0, args0_size);

        if (_is_file_exists(appname)) {
            free(args0);
            args0 = appname;
            break;
        }

        free(appname);
        appname = NULL;
    }

    _destroy_environment_path_result(paths, nr_paths);

    return args0;
}

char* _combine_args(char* args[])
{
    char* cmdline = NULL;
    int cmdline_size = 0;
    int n_str;

    while (*args != NULL) {
        n_str = strlen(*args);
        if (cmdline == NULL) {
            cmdline_size = 0;
            cmdline = (char*)malloc(n_str + 1);
        } else {
            cmdline = (char*)realloc(cmdline, cmdline_size + 1 + n_str + 1);
        }

        memcpy(&cmdline[cmdline_size], *args, n_str);
        cmdline_size += n_str;
        if (*(args+1) != NULL) {
            cmdline[cmdline_size++] = ' ';
        }
        cmdline[cmdline_size] = '\0';

        args++;
    }

    return cmdline;
}


subprocess_t* psopen(char* file, char* args[])
{
    subprocess_t* ps = NULL;
    HANDLE stdout_wr = INVALID_HANDLE_VALUE;
    HANDLE stdout_rd = INVALID_HANDLE_VALUE;
    HANDLE stdin_wr  = INVALID_HANDLE_VALUE;
    HANDLE stdin_rd  = INVALID_HANDLE_VALUE;
    int h_stdout_rd  = -1;
    int h_stdin_wr   = -1;
    char* appname = NULL;
    char* cmdline = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL success;

    ////////////////////////////////////////////////////////
    if ((args == NULL) || (args[0] == NULL)) {
        return NULL;
    }

    if (file != NULL) {
        appname = _find_image_path(file);
    } else {
        appname = _find_image_path(args[0]);
    }
    if (appname == NULL) {
        return NULL;
    }
    cmdline = _combine_args(args);
    if (cmdline == NULL) {
        free(appname);
        return NULL;
    }

    ////////////////////////////////////////////////////////
    success = _create_pipe_stdout(&stdout_rd, &stdout_wr);
    if (!success) {
        goto L_ERROR;
    }

    success = _create_pipe_stdin(&stdin_rd, &stdin_wr);
    if (!success) {
        goto L_ERROR;
    }

    ////////////////////////////////////////////////////////
    h_stdin_wr = _open_osfhandle((intptr_t)stdin_wr, 0);
    if (h_stdin_wr == -1) {
        goto L_ERROR;
    }
    stdin_wr = INVALID_HANDLE_VALUE;

    h_stdout_rd = _open_osfhandle((intptr_t)stdout_rd, 0);
    if (h_stdin_wr == -1) {
        goto L_ERROR;
    }
    stdout_rd = INVALID_HANDLE_VALUE;

    ////////////////////////////////////////////////////////
    ZeroMemory(&si, sizeof(si));
    si.cb           = sizeof(si);
    si.hStdInput    = stdin_rd;
    si.hStdOutput   = stdout_wr;
    si.hStdError    = stdout_wr;
    si.dwFlags      = STARTF_USESTDHANDLES;

    // Start the child process.
    // XXX: found exe from PATH, then set lpApplicationName!
    success = CreateProcess(
        appname,            //lpApplicationName
        cmdline,            //lpCommandLine
        //NULL,               //lpApplicationName
        //cmdline,            //lpCommandLine
        NULL,               //lpProcessAttributes for Security
        NULL,               //lpThreadAttributes for Security
        TRUE,               //bInHeritanceHandles
        CREATE_NO_WINDOW,   //dwCreationFlags
        NULL,               //lpEnvironment
        NULL,               //lpCurrentDirectory
        &si,                //lpStartupInfo
        &pi                 //lpProcessInformation
    );

    if (!success) {
        goto L_ERROR;
    }

    ////////////////////////////////////////////////////////
    free(appname);
    appname = NULL;
    free(cmdline);
    cmdline = NULL;

    CloseHandle(pi.hThread);

    // handle have hold by child, no need to have it.
    CloseHandle(stdout_wr);
    stdout_wr = INVALID_HANDLE_VALUE;
    CloseHandle(stdin_rd);
    stdin_rd = INVALID_HANDLE_VALUE;

    ps = (subprocess_t*)malloc(sizeof(subprocess_t));
    ps->pid             = GetProcessId(pi.hProcess);
    ps->proc            = (void*)pi.hProcess;
    ps->stdin_fileno    = h_stdin_wr;
    ps->stdout_fileno   = h_stdout_rd;

    return ps;

L_ERROR:
    if (appname != NULL) {
        free(appname);
    }
    if (cmdline != NULL) {
        free(cmdline);
    }
    if (h_stdout_rd != -1) {
        close(h_stdout_rd);
    }
    if (h_stdin_wr != -1) {
        close(h_stdin_wr);
    }
    if (stdout_wr != INVALID_HANDLE_VALUE) {
        CloseHandle(stdout_wr);
    }
    if (stdout_rd != INVALID_HANDLE_VALUE) {
        CloseHandle(stdout_rd);
    }
    if (stdin_wr != INVALID_HANDLE_VALUE) {
        CloseHandle(stdin_wr);
    }
    if (stdin_rd != INVALID_HANDLE_VALUE) {
        CloseHandle(stdin_rd);
    }

    return NULL;
}

int pswait(subprocess_t* ps)
{
    DWORD exitcode = 0;

    if (ps == NULL) {
        return -1;
    }

    if ((HANDLE)ps->proc != INVALID_HANDLE_VALUE) {
        WaitForSingleObject((HANDLE)ps->proc, INFINITE);
        if (!GetExitCodeProcess((HANDLE)ps->proc, &exitcode)) {
            exitcode = -1;
        }

        close(ps->stdin_fileno);
        close(ps->stdout_fileno);
        CloseHandle((HANDLE)ps->proc);

        ps->proc = (void*)INVALID_HANDLE_VALUE;
    }

    return exitcode;
}

void psclose(subprocess_t* ps)
{
    if (ps == NULL) {
        return;
    }

    if ((HANDLE)ps->proc != INVALID_HANDLE_VALUE) {
        close(ps->stdin_fileno);
        close(ps->stdout_fileno);

        WaitForSingleObject((HANDLE)ps->proc, 10);
        CloseHandle((HANDLE)ps->proc);

        ps->proc = (void*)INVALID_HANDLE_VALUE;
    }

    free(ps);
}

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

//  parent ---write---> pipe ---read---> child
//         inheritance        heritance
static int _create_pipe_stdin(int* stdin_rd, int* stdin_wr);

//  parent <---read--- pipe <---write--- child
//         inheritance       heritance
static int _create_pipe_stdout(int* stdout_rd, int* stdout_wr);


int _create_pipe_stdin(int* stdin_rd, int* stdin_wr)
{
    int h[2];
    int h_rd;

    if (pipe(h) < 0) {
        return -1;
    }

    h_rd = dup(h[0]);
    close(h[0]);

    *stdin_rd = h_rd;
    *stdin_wr = h[1];

    return 0;
}

int _create_pipe_stdout(int* stdout_rd, int* stdout_wr)
{
    int h[2];
    int h_wr;

    if (pipe(h) < 0) {
        return -1;
    }

    h_wr = dup(h[1]);
    close(h[1]);

    *stdout_rd = h[0];
    *stdout_wr = h_wr;

    return 0;
}

subprocess_t* psopen(char* file, char* args[])
{
    subprocess_t* ps;
    pid_t pid; 
    int stdin_wr;
    int stdin_rd;
    int stdout_wr;
    int stdout_rd;

    if (_create_pipe_stdin(&stdin_rd, &stdin_wr) < 0) {
        return NULL;
    }
    if (_create_pipe_stdout(&stdout_rd, &stdout_wr) < 0) {
        close(stdin_rd);
        close(stdin_wr);
        return NULL;
    }

    pid = vfork();
    if (pid < 0) {
        close(stdin_rd);
        close(stdin_wr);
        close(stdout_rd);
        close(stdout_wr);
        return NULL;
    }

    if (pid == 0) {
        //_exit() do not flush then close standard I/O
        //so I just use exit()
        if (dup2(stdin_rd, STDIN_FILENO) < 0) {
            exit(-1);
        }
        if (dup2(stdout_wr, STDOUT_FILENO) < 0) {
            exit(-1);
        }
        execvp(args[0], args);
        exit(-1);
    }
    
    close(stdin_rd);
    close(stdout_wr);

    ps = (subprocess_t*)malloc(sizeof(subprocess_t));
    ps->pid             = pid;
    ps->proc            = (void*)pid;
    ps->stdin_fileno    = stdin_wr;
    ps->stdout_fileno   = stdout_rd;

    return ps;
}


int pswait(subprocess_t* ps)
{
    int status;
    int returncode = 0;

    if (ps->pid > 0) {
        if (waitpid(ps->pid , &status, 0) == -1) {
            returncode = -1;
        } else {
            returncode = (char)(status >> 8);
        }
        ps->pid = 0;

        close(ps->stdin_fileno);
        close(ps->stdout_fileno);
    }

    return returncode;
}

void psclose(subprocess_t* ps)
{
    int i;
    int signals[] = {SIGINT, SIGTERM, SIGABRT, SIGKILL};

    if (ps->pid > 0) {
        close(ps->stdin_fileno);
        close(ps->stdout_fileno);

        for (i = 0;i < sizeof(signals)/sizeof(signals[0]);i++) {
            if (kill(ps->pid, 0) == -1) {
                break;
            }
            kill(ps->pid, signals[i]);
            usleep(10 * 1000);
        }

        ps->pid = 0;
    }

    free(ps);
}
#endif


int gs_include(duk_context* ctx, const char* fn);
int gs_eval_string(duk_context* ctx, const char* s);

int gs_put_args(duk_context* ctx, int argc, char* argv[]);

//nr_vars DUK_VARARGS
int gs_put_c_method(duk_context* ctx,
        const char* function_name,
        duk_c_function function_entry);

int gs_put_c_function(duk_context* ctx,
        const char* function_name,
        duk_c_function function_entry);

const char* gs_type_name(duk_context* ctx, duk_idx_t index);


int dukopen_gs(duk_context* ctx);

//windows:
//  file != NULL: file + " " + args[1] + " " + args[2] + " " + ...
//  file == NULL: args[0] + " " + args[1] + " " + args[2] + " " + ...
//
//linux: 
//  execvp(file, args);
//
subprocess_t* psopen(char* file, char* args[]);

//wait child exit or terminated, then close all handle.
int pswait(subprocess_t* ps);

//kill child if not exist nor terminated, then close all handle, and free all.
void psclose(subprocess_t* ps);



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

#ifdef WIN32 
#include <windows.h>
#include <direct.h>
#include <io.h>
#endif

#ifdef __linux__
#include <unistd.h>
#endif



static int _helper_get_stack_raw(duk_context* ctx, void*);
static void _helper_add_dollar_prefix(duk_context* ctx, int idx);
static void _helper_unpack_timeobj(duk_context* ctx, struct tm* ts, int idx);
static void _helper_pack_timeobj(duk_context* ctx, struct tm* ts, int idx);
static int _helper_path_normpath(duk_context* ctx, char* s, int len);

static int _strobj_encode(duk_context* ctx);
static int _strobj_decode(duk_context* ctx);
static int _fileobj_close(duk_context* ctx);
static int _fileobj_read(duk_context* ctx);
static int _fileobj_write(duk_context* ctx);
static int _statobj_tostring(duk_context* ctx);
static int _timeobj_tostring(duk_context* ctx);

static int _ord(duk_context* ctx);
static int _chr(duk_context* ctx);
static int _hex(duk_context* ctx);
static int _dir(duk_context* ctx);
static int _globals(duk_context* ctx);
static int _include(duk_context* ctx);
static int _deepcopy1(duk_context* ctx);

static int _fs_open(duk_context* ctx);
static int _fs_file_put_content(duk_context* ctx);
static int _fs_file_get_content(duk_context* ctx);

static int _os_getcwd(duk_context* ctx);
static int _ospath_isdir(duk_context* ctx);
static int _ospath_isfile(duk_context* ctx);
static int _ospath_exists(duk_context* ctx);
static int _ospath_join(duk_context* ctx);
static int _ospath_dirname(duk_context* ctx);
static int _ospath_split(duk_context* ctx);
static int _ospath_splitext(duk_context* ctx);
static int _ospath_normpath(duk_context* ctx);
static int _ospath_abspath(duk_context* ctx);

static int _time_time(duk_context* ctx);
static int _time_localtime(duk_context* ctx);
static int _time_gmtime(duk_context* ctx);
static int _time_asctime(duk_context* ctx);
static int _time_ctime(duk_context* ctx);
static int _time_strftime(duk_context* ctx);

static void _dukopen_buildin_extend(duk_context* ctx);
static void _push_traces_obj(duk_context* ctx);
static void _push_fs_obj(duk_context* ctx);
static void _push_os_path_obj(duk_context* ctx);
static void _push_os_obj(duk_context* ctx);
static void _push_time_obj(duk_context* ctx);
static void _push_sys_obj(duk_context* ctx);
static void _push_subprocess_obj(duk_context* ctx);
static void _set_modsearch(duk_context* ctx);

//#define duk_alloc_raw(c, size)        malloc(size)
//#define duk_realloc_raw(c, p, size)   realloc(p, size)
//#define duk_free_raw(c, p)            free(p)

////////////////////////////////////////////////////////////
int _helper_get_stack_raw(duk_context* ctx, void*) 
{
    const char* s;
    const char fmt[] = "ExceptionError: \"%s\"\n";
    char* p;

    ////////////////////////////////////////////////////////
    //'throw "string"' Exception
    if (duk_is_string(ctx, -1)) {
        s = duk_get_string(ctx, -1);
        p = (char*)duk_alloc_raw(ctx, sizeof(fmt) + strlen(s) + 1);
        sprintf(p, fmt, s);
        duk_pop(ctx);
        duk_push_lstring(ctx, p, strlen(p));
        duk_free_raw(ctx, p);
        return 1;
    }

    ////////////////////////////////////////////////////////
    //Other exception is object, and object have property named "stack"
	if (!duk_is_object(ctx, -1)) {
		return 1;
	}
	if (!duk_has_prop_string(ctx, -1, "stack")) {
		return 1;
	}

    //...|object|

	duk_get_prop_string(ctx, -1, "stack");  /* caller coerces */
    //...|object|message|

	duk_remove(ctx, -2);//delete object
    //...|message|

	return 1;
}

void _helper_add_dollar_prefix(duk_context* ctx, int idx)
{
    const char* k;
    char* newk;
    duk_size_t n;

    if (idx < 0) {
        idx = duk_get_top(ctx) + idx;
    }

    k = duk_get_lstring(ctx, idx, &n);
    newk = (char*)duk_alloc_raw(ctx, n + 1);
    memset(newk, 0, n + 1);
    newk[0] = '$';
    memcpy(&newk[1], k, n);
    duk_push_lstring(ctx, newk, n + 1);
    duk_free_raw(ctx, newk);

    duk_replace(ctx, idx);
}


void _helper_unpack_timeobj(duk_context* ctx, struct tm* ts, int idx)
{
    duk_get_prop_string(ctx, idx, "tm_year");
    ts->tm_year = duk_to_int(ctx, -1) - 1900;
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_mon");
    ts->tm_mon = duk_to_int(ctx, -1) - 1;
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_mday");
    ts->tm_mday = duk_to_int(ctx, -1);
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_hour");
    ts->tm_hour = duk_to_int(ctx, -1);
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_min");
    ts->tm_min = duk_to_int(ctx, -1);
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_sec");
    ts->tm_sec = duk_to_int(ctx, -1);
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_wday");
    ts->tm_wday = duk_to_int(ctx, -1);
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_yday");
    ts->tm_yday = duk_to_int(ctx, -1) - 1;
    duk_pop(ctx);

    duk_get_prop_string(ctx, idx, "tm_isdst");
    ts->tm_isdst = duk_to_int(ctx, -1);
    duk_pop(ctx);
}

void _helper_pack_timeobj(duk_context* ctx, struct tm* ts, int idx)
{
    duk_push_int(ctx, ts->tm_year + 1900);
    duk_put_prop_string(ctx, idx-1, "tm_year");

    duk_push_int(ctx, ts->tm_mon + 1);
    duk_put_prop_string(ctx, idx-1, "tm_mon");

    duk_push_int(ctx, ts->tm_mday);
    duk_put_prop_string(ctx, idx-1, "tm_mday");

    duk_push_int(ctx, ts->tm_hour);
    duk_put_prop_string(ctx, idx-1, "tm_hour");

    duk_push_int(ctx, ts->tm_min);
    duk_put_prop_string(ctx, idx-1, "tm_min");
    
    duk_push_int(ctx, ts->tm_sec);
    duk_put_prop_string(ctx, idx-1, "tm_sec");

    duk_push_int(ctx, ts->tm_wday);
    duk_put_prop_string(ctx, idx-1, "tm_wday");

    duk_push_int(ctx, ts->tm_yday + 1);
    duk_put_prop_string(ctx, idx-1, "tm_yday");

    duk_push_int(ctx, ts->tm_isdst);
    duk_put_prop_string(ctx, idx-1, "tm_isdst");
}

//@param s      no mater with or without '\0'
//@param len    length not included '\0'
int _helper_path_normpath(duk_context* ctx, char* s, int len)
{
    char** stack;
    int max_depth = 128;
    int depth = 0;
    char* p;
    char* prev;
    char* pend;
    int n;
    int i;
    int j;
#ifdef DUK_F_WINDOWS
    const char split_char = '\\';
#endif
#ifdef DUK_F_LINUX
    const char split_char = '/';
#endif

    stack = (char**)duk_alloc_raw(ctx, sizeof(char*) * max_depth);

    prev    = s;
    pend    = s + len;
    p       = prev;
    while (p < pend) {
        if (depth == max_depth - 1) {
            max_depth *= 2;
            stack = (char**)duk_realloc_raw(ctx, stack, sizeof(char*) * max_depth);
        }

        if ((*p == '/') || (*p == '\\')) {
            if (prev < p) {
                n = p-prev;
                stack[depth] = (char*)duk_alloc_raw(ctx, n+1);
                memset(stack[depth], 0, n+1);
                memcpy(stack[depth], prev, n);
                depth++;
                prev = p+1;
                p = prev;
            } else {
                p++;
            }
        } else {
            p++;
        }
    }
    if (prev < p) {
        n = p-prev;
        stack[depth] = (char*)duk_alloc_raw(ctx, n+1);
        memset(stack[depth], 0, n+1);
        memcpy(stack[depth], prev, n);
        depth++;
    }

    i = 0;
    while (i < depth) {
        if (strcmp(stack[i], "..") == 0) {
            if (i > 0) {
                duk_free_raw(ctx, stack[i-1]);
                duk_free_raw(ctx, stack[i]);
                for (j = i+1;j < depth;j++) {
                    stack[j-2] = stack[j];
                }
                depth = depth-2;
                i--;
            } else {
                duk_free_raw(ctx, stack[i]);
                for (j = i+1;j < depth;j++) {
                    stack[j-1] = stack[j];
                }
                depth = depth-1;
            }

        } else if (strcmp(stack[i], ".") == 0) {
            duk_free_raw(ctx, stack[i]);
            for (j = i+1;j < depth;j++) {
                stack[j-1] = stack[j];
            }
            depth = depth-1;

        } else {
            i++;
        }
    }

    p = s;
    for (i = 0;i < depth;i++) {
        n = strlen(stack[i]);
        memcpy(p, stack[i], n);
        p += n;
        
        if (i < depth - 1) {
            *p++ = split_char;
        }

        duk_free_raw(ctx, stack[i]);
    }
    //when s not end with '\0',
    //still need to add '\0',
    //to prevent user just puts(s),
    //this will overflow!
    if (p < pend) {
        *p = '\0';
    }
    duk_free_raw(ctx, stack);

    return p - s;
}


// obj.close();
int _fileobj_close(duk_context* ctx)
{
    FILE* fp;

    //check parameters
    duk_push_this(ctx);
    duk_get_prop_string(ctx, -1, "__handler__");
    fp = (FILE *) duk_get_pointer(ctx, -1);
    duk_pop(ctx);

    if (fp == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "fp of fclose(fp) is NULL!");
    }

    //close
    fclose(fp);

    return 0;
}

// obj.read(size);  --max read size
// obj.read();      --read all bytes
int _fileobj_read(duk_context* ctx)
{
    FILE* fp;
    unsigned char* rawbuf;
    unsigned char* dukbuf;
    unsigned long len;
    unsigned long pos;
    unsigned long fsize;
    unsigned long bytes_read;

    //check parameters
    if ((duk_get_top(ctx) == 1) && !duk_is_number(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "size must be interger");
        len = duk_to_uint32(ctx, 0);
    } else {
        len = 0;
    }

    duk_push_this(ctx);
    duk_get_prop_string(ctx, -1, "__handler__");
    fp = (FILE *) duk_get_pointer(ctx, -1);
    duk_pop(ctx);

    if (fp == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "fp of fclose(fp) is NULL!");
    }

    //actual read
    pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, pos, SEEK_SET);

    if ((len == 0) || (len > fsize - pos)) {
        len = fsize - pos;
    }

    //fixed bug:
    //  when fopen(fn, "r"), fread will convert "\r\n" to "\n",
    //  but fseek not check this!
    //  so we need to load this temporary then push to duktape.
    rawbuf = (unsigned char*)duk_alloc_raw(ctx, len);
    bytes_read = fread(rawbuf, sizeof(unsigned char), len, fp);

    dukbuf = (unsigned char*)duk_push_fixed_buffer(ctx, bytes_read);
    memcpy(dukbuf, rawbuf, bytes_read);
    duk_free_raw(ctx, rawbuf);

    return 1;
}


// obj.write(buffer);
// obj.write(string);
int _fileobj_write(duk_context* ctx)
{
    FILE* fp;
    unsigned char* buf;
    size_t len;
    unsigned long bytes_wrote;

    //check parameters
    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing buffer or string to write");
    }

    if (!duk_is_buffer(ctx, 0) && !duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "just buffer or string accept");
    }

    duk_push_this(ctx);
    duk_get_prop_string(ctx, -1, "__handler__");
    fp = (FILE *) duk_get_pointer(ctx, -1);
    duk_pop(ctx);

    if (fp == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "fp of fclose(fp) is NULL!");
    }

    if (duk_is_buffer(ctx, 0)) {
        buf = (unsigned char*)duk_get_buffer(ctx, 0, &len);
    } else {//buf is NOT 'NUL-Terminated'!
        buf = (unsigned char*)duk_get_lstring(ctx, 0, &len);
    }

    if ((len <= 0) || (buf == NULL)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "invalid buffer or string!");
    }

    bytes_wrote = fwrite(buf, sizeof(char), len, fp);
    duk_push_int(ctx, bytes_wrote);

    return 1;
}

int _timeobj_tostring(duk_context* ctx)
{
    struct tm ts;
    char buf[100];

    duk_push_this(ctx);
    _helper_unpack_timeobj(ctx, &ts, -1);
    duk_pop(ctx);

    sprintf(buf,
            "time.struct_time(tm_year=%d, tm_mon=%d, tm_mday=%d, "
            "tm_hour=%d, tm_min=%d, tm_sec=%d, tm_wday=%d, "
            "tm_yday=%d, tm_isdst=%d)",
            ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
            ts.tm_hour, ts.tm_min, ts.tm_sec, ts.tm_wday,
            ts.tm_yday, ts.tm_isdst);

    duk_push_string(ctx, buf);

    return 1;
}

static int _psobj_stdin_write(duk_context* ctx)
{
    int f;
    const char* buf;
    duk_size_t size;
    int nr_bytes;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_RANGE_ERROR, "accept one argument only");
    }
    if (!duk_is_string(ctx, 0) && !duk_is_buffer(ctx, 0)) {
        duk_error(ctx, DUK_ERR_RANGE_ERROR, "need string or buffer");
    }

    if (duk_is_string(ctx, 0)) {
        buf = duk_get_lstring(ctx, 0, &size);
    } else {
        buf = (const char *) duk_get_buffer(ctx, 0, &size);
    }

    duk_push_this(ctx);
    duk_get_prop_string(ctx, -1, "__handler__");
    f = (intptr_t) duk_get_pointer(ctx, -1);
    duk_pop(ctx);

    nr_bytes = write(f, buf, size);
    if (nr_bytes != size) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "native write fail");
    }

    duk_push_int(ctx, nr_bytes);

    return 1;
}

static int _psobj_stdout_read(duk_context* ctx)
{
    char* buf = NULL;
    int size = 0;
    int nr_bytes;
    int f;

    if ((duk_get_top(ctx) != 0) && duk_is_number(ctx, 0)) {
        size = duk_get_int(ctx, 0);
    }

    if (size <= 0) {
        size = 1024;
    }

    duk_push_this(ctx);
    duk_get_prop_string(ctx, -1, "__handler__");
    f = (intptr_t )duk_get_pointer(ctx, -1);
    duk_pop(ctx);

    buf = (char *) duk_alloc_raw(ctx, size);
    nr_bytes = read(f, buf, size);
    if (nr_bytes < 0) {
        duk_free(ctx, buf);
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "native read fail");
    }

    if (nr_bytes == 0) {
        duk_free(ctx, buf);
        duk_push_null(ctx);
        return 1;
    }

    duk_push_lstring(ctx, buf, nr_bytes);
    duk_free(ctx, buf);

    return 1;
}

static int _psobj_wait(duk_context* ctx)
{
    subprocess_t* ps;
    int returncode;

    duk_push_this(ctx);

    duk_get_prop_string(ctx, -1, "__handler__");
    if (duk_is_undefined(ctx, -1)) {
        ps = NULL;
    } else {
        ps = (subprocess_t*)duk_get_pointer(ctx, -1);
    }
    duk_pop(ctx);

    if (ps == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing '__handler__'!");
    }

    returncode = pswait(ps);

    duk_push_int(ctx, returncode);
    duk_put_prop_string(ctx, -2, "returncode");

    duk_push_int(ctx, returncode);
    return 1;
}

static int _psobj_close(duk_context* ctx)
{
    subprocess_t* ps;

    duk_push_this(ctx);

    duk_get_prop_string(ctx, -1, "__handler__");
    if (duk_is_undefined(ctx, -1)) {
        ps = NULL;
    } else {
        ps = (subprocess_t*)duk_get_pointer(ctx, -1);
    }
    duk_pop(ctx);

    if (ps == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing '__handler__'!");
    }

    psclose(ps);

    duk_push_undefined(ctx);
    duk_put_prop_string(ctx, -2, "__handler__");

    return 0;
}

static int _psobj_finalizer(duk_context* ctx)
{
    subprocess_t* ps;

    duk_get_prop_string(ctx, -1, "__handler__");
    if (!duk_is_undefined(ctx, -1)) {
        ps = (subprocess_t*)duk_get_pointer(ctx, -1);
        psclose(ps);
    }
    duk_pop(ctx);

    return 0;
}


int _ord(duk_context* ctx)
{
    const char* s;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_RANGE_ERROR, "just accept one argument!");
    }
    if (duk_get_type(ctx, -1) != DUK_TYPE_STRING) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "string only!");
    }

    s = duk_get_string(ctx, 0);
    if (strlen(s) == 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "null string not allow!");
    }

    duk_push_int(ctx, *s);

    return 1;
}

int _chr(duk_context* ctx)
{
    int v;
    char s[2];

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "one argument only!");
    }
    if (duk_get_type(ctx, -1) != DUK_TYPE_NUMBER) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "number only!");
    }

    v = duk_get_int(ctx, 0);
    s[0] = (char)v;
    s[1] = '\0';
    duk_push_string(ctx, s);

    return 1;
}

int _hex(duk_context* ctx)
{
    int v;
    char s[20];

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "one argument only!");
    }
    if (duk_get_type(ctx, -1) != DUK_TYPE_NUMBER) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "number only!");
    }

    v = duk_get_int(ctx, 0);
    sprintf(s, "0x%08x", v);
    duk_push_string(ctx, s);

    return 1;
}

//dir(obj)      DUK_ENUM_OWN_PROPERTIES_ONLY
//dir(obj, 1)   DUK_ENUM_INCLUDE_INTERNAL
//dir(obj, 2)   DUK_ENUM_INCLUDE_INTERNAL|DUK_ENUM_INCLUDE_NONENUMERABLE;
//
int _dir(duk_context* ctx)
{
    int depth;
    int obj_id = 0;
    int enum_level = 0;
    duk_uint_t enum_flags;

    depth = duk_get_top(ctx);
    if (depth == 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "need one object!");
    }
    if (duk_get_type(ctx, 0) != DUK_TYPE_OBJECT) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "just accept object!");
    }

    if (depth == 2) {
        enum_level = duk_get_int(ctx, 1);
    }

    if (enum_level == 1) {
        enum_flags = 0;
    } else if (enum_level == 2) {
        enum_flags = 0;
    } else {
        enum_flags = 0;
    }

    obj_id = duk_push_array(ctx);
    duk_enum(ctx, 0, enum_flags);

    // [o] [array] [enum]
    while (duk_next(ctx, -1/*enumid*/, 1/*get value*/)) {
        // [o] [array] [enum] key value
        _helper_add_dollar_prefix(ctx, -2);
        duk_put_prop(ctx, obj_id);
    }

    duk_pop(ctx);//pop [enum]

    return 1;
}

int _globals(duk_context* ctx)
{
    int depth = 0;

    depth = duk_get_top(ctx);
    if (depth > 0) {
        duk_pop_n(ctx, depth);
    }

    duk_push_global_object(ctx);
    if (depth > 0) {
        duk_push_int(ctx, 2);
    }
    _dir(ctx);

    return 1;
}

int _include(duk_context* ctx)
{
    const char* fn;
    duk_size_t n;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "need stript file name");
    }
    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept string");
    }
    fn = duk_get_lstring(ctx, 0, &n);
    if (n <= 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "string is empty");
    }

    ////////////////////////////////////////////////////////
    //push '__file__' to 'traces'
    duk_push_global_object(ctx);
    duk_get_prop_string(ctx, -1, "__file__");

    duk_get_prop_string(ctx, -2, "Modules");
    duk_get_prop_string(ctx, -1, "traces");
    duk_remove(ctx, -2);

    if (duk_is_undefined(ctx, -1)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "can't find 'traces'");
    }
    duk_push_string(ctx, "push");
    duk_dup(ctx, -3);
    duk_call_prop(ctx, -3, 1);
    duk_pop(ctx);

    //cleanup stack
    duk_pop(ctx);//pop 'traces'
    duk_remove(ctx, -2);//pop [global]

    ////////////////////////////////////////////////////////
    //stack: fn,__file__
    fn = duk_get_lstring(ctx, 0, &n);
    if ((n >= 2) && (fn[0] == '.') && ((fn[1] == '/') || (fn[1] == '\\'))) {
        duk_pop(ctx);

    } else if (duk_is_undefined(ctx, 1)) {
        duk_pop(ctx);

    } else {
        //tryfn = os.path.join(os.path.dirname(__file__), fn);
        //if os.path.exist(tryfn):
        //    fn = tryfn
        duk_push_c_function(ctx, _ospath_dirname, 1);
        duk_dup(ctx, -2);
        duk_call(ctx, 1);
        duk_remove(ctx, -2);

        duk_push_c_function(ctx, _ospath_join, 2);
        duk_dup(ctx, -2);
        duk_dup(ctx, -4);
        duk_call(ctx, 2);
        duk_remove(ctx, -2);

        duk_push_c_function(ctx, _ospath_exists, 1);
        duk_dup(ctx, -2);
        duk_call(ctx, 1);
        if (duk_get_boolean(ctx, -1)) {
            duk_pop(ctx);//pop result
            duk_remove(ctx, -2);//pop original string
        } else {
            duk_pop(ctx);//pop result
            duk_pop(ctx);//pop __file__
        }
    }

    ////////////////////////////////////////////////////////
    //stack: fn
    duk_push_c_function(ctx, _ospath_abspath, 1);
    duk_dup(ctx, -2);
    duk_call(ctx, 1);
    duk_remove(ctx, -2);

    //update '__file__'
    duk_push_global_object(ctx);
    duk_dup(ctx, -2);
    duk_put_prop_string(ctx, -2, "__file__");
    duk_pop(ctx);


    fn = duk_get_string(ctx, 0);
    if (duk_peval_file(ctx, fn) != 0) {
        duk_throw(ctx);
    }
    duk_remove(ctx, 0);//pop fn
    duk_gc(ctx, 0);

    ////////////////////////////////////////////////////////
    //restore '__file__'
    duk_push_global_object(ctx);

    duk_get_prop_string(ctx, -1, "Modules");
    duk_get_prop_string(ctx, -1, "traces");
    duk_remove(ctx, -2);

    duk_push_string(ctx, "pop");
    duk_call_prop(ctx, -2, 0);
    duk_remove(ctx, -2);//pop 'traces'

    duk_put_prop_string(ctx, -2, "__file__");

    duk_pop(ctx);//pop [global]

    return 1;
}

//copy method of $0 to $1
//
//equal:
//  var m = dir($0);
//  for (var k in m) {
//      $1[k.substring(1)] = m[k];
//  }
//
static int _deepcopy1(duk_context* ctx)
{
    int from_id = 0;
    int to_id = 1;

    if (duk_get_top(ctx) == 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "accept 1 arguments at least");
    }
    if (duk_get_top(ctx) == 1) {
        duk_push_object(ctx);
    }

    duk_enum(ctx, from_id, DUK_ENUM_OWN_PROPERTIES_ONLY);

    while (duk_next(ctx, -1/*enumid*/, 1/*get value*/)) {
        duk_put_prop(ctx, to_id);
    }

    duk_pop(ctx);//pop [enum]

    return 1;
}

// fs.open(fn, mode);
// fs.open(fn);         --default read mode
int _fs_open(duk_context* ctx)
{
    FILE* fp;
    const char* fn;
    const char* mode;

    //check parameters
    if (duk_get_top(ctx) == 2) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }
        if (!duk_is_string(ctx, 1)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file mode must be string");
        }
        mode = duk_get_string(ctx, 1);

    } else if (duk_get_top(ctx) == 1) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }
        mode = "r";

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }

    duk_dup(ctx, 0);//copy to top(-1)
    fn = duk_get_string(ctx, -1);

    //open file
    if ((fp = fopen(fn, mode)) == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "fopen error.");
    }

    ////////////////////////////////////////////////////////
    //generate return object
    duk_push_object(ctx);

    duk_push_string(ctx, "__cobject_file__");
    duk_put_prop_string(ctx, -2, "__type__");

    //remember parameters
    fn = duk_get_string(ctx, 0);
    duk_push_string(ctx, fn);
    duk_put_prop_string(ctx, -2, "__file__");

    duk_push_string(ctx, mode);
    duk_put_prop_string(ctx, -2, "__mode__");

    duk_push_pointer(ctx, fp);
    duk_put_prop_string(ctx, -2, "__handler__");

    //registers c function
    gs_put_c_method(ctx, "close", _fileobj_close);
    gs_put_c_method(ctx, "read",  _fileobj_read);
    gs_put_c_method(ctx, "write", _fileobj_write);

    return 1;
}

// file_put_content(fn, data)
int _fs_file_put_content(duk_context* ctx)
{
    FILE* fp;
    const char* fn;
    const char* s;
    size_t len;
    int bytes_wrote;

    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
    }
    if (!duk_is_string(ctx, 1) && !duk_is_buffer(ctx, 1)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string or buffer");
    }

    fn = duk_get_string(ctx, 0);

    if (duk_is_string(ctx, 1)) {
        s = duk_get_lstring(ctx, 1, &len);
    } else {
        s = (const char*)duk_get_buffer(ctx, 1, &len);
    }

    if ((fp = fopen(fn, "wb")) == NULL) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "can't open file");
    }

    bytes_wrote = fwrite(s, 1, len, fp);
    fclose(fp);
    fp = NULL;

    duk_push_int(ctx, bytes_wrote);

    return 1;
}

// file_get_content(fn)
int _fs_file_get_content(duk_context* ctx)
{
    FILE* fp;
    const char* fn;
    int len;
    char* p = NULL;

    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
    }

    fn = duk_get_string(ctx, 0);

    if ((fp = fopen(fn, "rb")) != NULL) {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        p = (char*)duk_alloc_raw(ctx, len + 1);
        memset(p, 0, len + 1);

        fread(p, 1, len, fp);

        fclose(fp);
        fp = NULL;
    }

    if (p != NULL) {
        duk_push_lstring(ctx, p, len);
        duk_free_raw(ctx, p);
    } else {
        duk_push_null(ctx);
    }

    return 1;//one string
}

static int _ps_open(duk_context* ctx)
{
    subprocess_t* ps;
    int length;
    char** args;
    int i;
    const char* s_ptr;
    duk_size_t s_len;

    if (duk_get_top(ctx) == 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "one parameter at least!");
    }

    if (duk_is_array(ctx, 0)) {
        duk_get_prop_string(ctx, -1, "length");
        length = duk_get_int(ctx, -1);
        if ((duk_is_undefined(ctx, -1)) || (length <= 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "Array.length is zero or invalid!");
        }
        duk_pop(ctx);

        args = (char**)duk_alloc_raw(ctx, sizeof(char*) * (length + 1));
        memset(args, 0, sizeof(char*) * (length + 1));

        for (i = 0;i < length;i++) {
            duk_get_prop_index(ctx, -1, i);
            s_ptr = duk_get_lstring(ctx, -1, &s_len);
            args[i] = (char*)duk_alloc_raw(ctx, sizeof(char) * (s_len + 1));
            memset(args[i], 0, sizeof(char) * (s_len + 1));
            memcpy(args[i], s_ptr, s_len);
            duk_pop(ctx);
        }

    } else {
        length = duk_get_top(ctx);

        args = (char**)duk_alloc_raw(ctx, sizeof(char*) * (length + 1));
        memset(args, 0, sizeof(char*) * (length + 1));

        for (i = 0;i < length;i++) {
            s_ptr = duk_get_lstring(ctx, i, &s_len);
            args[i] = (char*)duk_alloc_raw(ctx, sizeof(char) * (s_len + 1));
            memset(args[i], 0, sizeof(char) * (s_len + 1));
            memcpy(args[i], s_ptr, s_len);
            duk_pop(ctx);
        }
    }

    duk_set_top(ctx, 0);//clean all parameters

    ps = psopen(args[0], args);
    if (ps == NULL) {
        for (i = 0;i < length;i++) {
            duk_free_raw(ctx, args[i]);
        }
        duk_free_raw(ctx, args);

        duk_error(ctx, DUK_ERR_TYPE_ERROR, "native psopen fail!");
    }

    ////////////////////////////////////////////////////////
    //build return object
    duk_push_object(ctx);

    duk_push_pointer(ctx, ps);
    duk_put_prop_string(ctx, -2, "__handler__");

    duk_push_int(ctx, ps->pid);
    duk_put_prop_string(ctx, -2, "pid");

    duk_push_undefined(ctx);
    duk_put_prop_string(ctx, -2, "returncode");

    duk_push_object(ctx);
    duk_push_pointer(ctx, (void*)ps->stdin_fileno);
    duk_put_prop_string(ctx, -2, "__handler__");
    gs_put_c_method(ctx, "write", _psobj_stdin_write);
    duk_put_prop_string(ctx, -2, "stdin");

    duk_push_object(ctx);
    duk_push_pointer(ctx, (void*)ps->stdout_fileno);
    duk_put_prop_string(ctx, -2, "__handler__");
    gs_put_c_method(ctx, "read", _psobj_stdout_read);
    duk_put_prop_string(ctx, -2, "stdout");

    gs_put_c_method(ctx, "wait", _psobj_wait);
    gs_put_c_method(ctx, "close", _psobj_close);

    duk_push_c_function(ctx, _psobj_finalizer, 1);
    duk_set_finalizer(ctx, -2);

    duk_push_array(ctx);
    for (i = 0;i < length;i++) {
        duk_push_string(ctx, args[i]);
        duk_put_prop_index(ctx, -2, i);
    }
    duk_put_prop_string(ctx, -2, "cmd");

    for (i = 0;i < length;i++) {
        duk_free_raw(ctx, args[i]);
    }
    duk_free_raw(ctx, args);

    return 1;
}

int _os_getcwd(duk_context* ctx)
{
    char* currdir;

    currdir = getcwd(NULL, 0);
    if (currdir == NULL) {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_string(ctx, currdir);


    free(currdir);

    return 1;
}

int _os_getdatadir(duk_context* ctx)
{
    static std::string currdir = GetDataDir().string();

    duk_push_string(ctx, currdir.c_str());

    return 1;
}

int _os_getmoduledir(duk_context* ctx)
{
    static std::string dir = GetModuleDir().string();

    duk_push_string(ctx, dir.c_str());

    return 1;
}

int _os_getworkspacedir(duk_context* ctx)
{
    static std::string dir = GetWorkspaceDir().string();

    duk_push_string(ctx, dir.c_str());

    return 1;
}

int _ospath_isdir(duk_context* ctx)
{
    if (duk_get_top(ctx) == 1) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }


    fs::path p = duk_get_string(ctx, 0);
    if (!fs::exists(p)) {
        duk_push_false(ctx);
        return 1;
    }

    if (!fs::is_directory(p)) {
        duk_push_true(ctx);
    } else {
        duk_push_false(ctx);
    }

    return 1;
}

int _ospath_isfile(duk_context* ctx)
{
    if (duk_get_top(ctx) == 1) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }

    fs::path p = duk_get_string(ctx, 0);

    if (!fs::exists(p)) {
        duk_push_false(ctx);
        return 1;
    }

    if (!fs::is_regular_file(p)) {
        duk_push_false(ctx);
    } else {
        duk_push_true(ctx);
    }

    return 1;
}

int _ospath_exists(duk_context* ctx)
{


    if (duk_get_top(ctx) == 1) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }


    fs::path p = duk_get_string(ctx, 0);

    if (!fs::exists(p)) {
        duk_push_false(ctx);
    } else {
        duk_push_true(ctx);
    }

    return 1;
}

int _ospath_join(duk_context* ctx)
{
    int n;
    int i;
    int total_len = 0;
    duk_size_t s_len;
    const char* s;
    char* buf;
    int len;

#ifdef DUK_F_WINDOWS
    char split_char = '\\';
#endif
#ifdef DUK_F_LINUX
    char split_char = '/';
#endif

    n = duk_get_top(ctx);
    for (i = 0;i < n;i++) {
        duk_get_lstring(ctx, i, &s_len);
        total_len += s_len + 1;
    }

    if (total_len <= 0) {
        duk_push_undefined(ctx);
        return 1;
    }

    len = 0;
    buf = (char*)duk_alloc_raw(ctx, total_len+n+1);
    memset(buf, 0, total_len+n+1);

    for (i = 0;i < n;i++) {
        s = duk_get_lstring(ctx, i, &s_len);
        if (s_len <= 0) {
            continue;
        }
        //first variable
        if (len == 0) {
            memcpy(buf, s, s_len);
            len += s_len;
            continue;
        }
        //overwrite previous variables.
        if ((s[0] == '/') || (s[0] == '\\')) {
            memcpy(buf, s, s_len);
            len += s_len;
            continue;
        }

        if ((buf[len-1] != '/') && (buf[len-1] != '\\')) {
            buf[len++] = split_char;
        }
        memcpy(buf+len, s, s_len);
        len += s_len;
    }

    duk_push_string(ctx, buf);
    duk_free_raw(ctx, buf);
    return 1;
}

int _ospath_dirname(duk_context* ctx)
{
    int i;
    duk_size_t n;
    int len_1th;
    const char* fn;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }

    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
    }

    fn = duk_get_lstring(ctx, 0, &n);
    if (n <= 0) {
        duk_push_string(ctx, "");
        return 1;
    }

    for (i = n-1;i >= 0;i--) {
        if ((fn[i] == '/') || (fn[i] == '\\')) {
            break;
        }
    }

    if (i < 0) {
        len_1th = n;
    } else {
        len_1th = i;
    }

    if (len_1th > 0) {
        duk_push_lstring(ctx, fn, len_1th);
    } else {
        duk_push_string(ctx, "");
    }

    return 1;
}

int _ospath_split(duk_context* ctx)
{
    int i;
    duk_size_t n;
    int len_1th;
    int len_2nd;
    const char* fn;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }

    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
    }

    fn = duk_get_lstring(ctx, 0, &n);
    if (n <= 0) {
        duk_push_array(ctx);
        duk_push_string(ctx, "");
        duk_put_prop_index(ctx, -2, 0);
        duk_push_string(ctx, "");
        duk_put_prop_index(ctx, -2, 0);
        return 1;
    }

    for (i = n-1;i >= 0;i--) {
        if ((fn[i] == '/') || (fn[i] == '\\')) {
            break;
        }
    }

    if (i < 0) {
        len_1th = n;
        len_2nd = 0;
    } else {
        len_1th = i;
        len_2nd = n-i-1;
    }

    duk_push_array(ctx);

    if (len_1th > 0) {
        duk_push_lstring(ctx, fn, len_1th);
    } else {
        duk_push_string(ctx, "");
    }
    duk_put_prop_index(ctx, -2, 0);

    if (len_2nd > 0) {
        duk_push_lstring(ctx, fn + len_1th + 1, len_2nd);
    } else {
        duk_push_string(ctx, "");
    }
    duk_put_prop_index(ctx, -2, 1);

    return 1;
}

int _ospath_splitext(duk_context* ctx)
{
    int i;
    duk_size_t n;
    int len_1th;
    int len_2nd;
    const char* fn;

    if (duk_get_top(ctx) == 1) {
        if (!duk_is_string(ctx, 0)) {
            duk_error(ctx, DUK_ERR_TYPE_ERROR, "file name must be string");
        }
        fn = duk_get_string(ctx, 0);

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing parameters");
    }

    fn = duk_get_lstring(ctx, 0, &n);
    if (n <= 0) {
        duk_push_array(ctx);
        duk_push_string(ctx, "");
        duk_put_prop_index(ctx, -2, 0);
        duk_push_string(ctx, "");
        duk_put_prop_index(ctx, -2, 0);
        return 1;
    }

    for (i = n-1;i >= 0;i--) {
        if (fn[i] == '.') {
            break;
        }
    }

    if (i < 0) {
        len_1th = n;
        len_2nd = 0;
    } else {
        len_1th = i;
        len_2nd = n-i-1;
    }

    duk_push_array(ctx);

    if (len_1th > 0) {
        duk_push_lstring(ctx, fn, len_1th);
    } else {
        duk_push_string(ctx, "");
    }
    duk_put_prop_index(ctx, -2, 0);

    if (len_2nd > 0) {
        duk_push_lstring(ctx, fn + len_1th + 1, len_2nd);
    } else {
        duk_push_string(ctx, "");
    }
    duk_put_prop_index(ctx, -2, 1);

    return 1;
}

int _ospath_normpath(duk_context* ctx)
{
    const char* s;
    char* p;
    duk_size_t n;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept one string");
    }
    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept string");
    }

    s = duk_get_lstring(ctx, 0, &n);
    p = (char*)duk_alloc_raw(ctx, n);
    memcpy(p, s, n);

    n = _helper_path_normpath(ctx, p, n);
    duk_push_lstring(ctx, p, n);
    duk_free_raw(ctx, p);

    return 1;
}

int _ospath_abspath(duk_context* ctx)
{
    const char* s;
    duk_size_t len;

    if (duk_get_top(ctx) != 1) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept one string");
    }
    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept string");
    }

    s = duk_get_lstring(ctx, 0, &len);
    if ((s[0] == '/') || (s[0] == '\\') ||
        ((len >= 2) && isalpha(s[0]) && (s[1] == ':')))
    {//absolute path already, just need normal path format.

    } else {
        duk_push_c_function(ctx, _os_getcwd, 0);
        duk_call(ctx, 0);
        if (duk_is_undefined(ctx, -1)) {
            return 1;
        }

        duk_push_c_function(ctx, _ospath_join, 2);
        duk_dup(ctx, -2);
        duk_dup(ctx, 0);
        duk_call(ctx, 2);

        duk_replace(ctx, 0);
        duk_pop(ctx);
    }

    duk_push_c_function(ctx, _ospath_normpath, 1);
    duk_dup(ctx, 0);
    duk_call(ctx, 1);

    return 1;
}

int _time_time(duk_context* ctx)
{
    time_t t;

    time(&t);

    duk_push_uint(ctx, (unsigned int)t);

    return 1;
}

int _time_localtime(duk_context* ctx)
{
    time_t t;
    struct tm ts;

    if ((duk_get_top(ctx) == 1) && !duk_is_number(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept integer");
    }

    if (duk_get_top(ctx) == 1) {
        t = duk_to_uint(ctx, 0);
    } else {
        time(&t);
    }

    ts = *localtime(&t);

    duk_push_object(ctx);

    duk_push_string(ctx, "struct_time");
    duk_put_prop_string(ctx, -2, "name");

    gs_put_c_method(ctx, "toString", _timeobj_tostring);

    _helper_pack_timeobj(ctx, &ts, -1);

    return 1;
} 

int _time_gmtime(duk_context* ctx)
{
    time_t t;
    struct tm ts;

    if ((duk_get_top(ctx) == 1) && !duk_is_number(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept integer");
    }

    if (duk_get_top(ctx) == 1) {
        t = duk_to_uint(ctx, 0);
    } else {
        time(&t);
    }

    ts = *gmtime(&t);

    duk_push_object(ctx);

    duk_push_string(ctx, "struct_time");
    duk_put_prop_string(ctx, -2, "name");

    gs_put_c_method(ctx, "toString", _timeobj_tostring);

    _helper_pack_timeobj(ctx, &ts, -1);

    return 1;
} 

int _time_asctime(duk_context* ctx)
{
    time_t t;
    struct tm ts;
    const char* s;
    char buf[100];

    if (duk_get_top(ctx) == 0) {
        time(&t);
        ts = *localtime(&t);

    } else if ((duk_get_top(ctx) == 1) && duk_is_object(ctx, 0)) {
        duk_get_prop_string(ctx, 0, "name");
        s = duk_to_string(ctx, -1);
        if (strcmp(s, "struct_time") == 0) {
            _helper_unpack_timeobj(ctx, &ts, 0);
            duk_pop(ctx);
        } else {
            duk_error(ctx, DUK_ERR_TYPE_ERROR,
                    "second parameter only accept time.struct_time");
        }

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "parameter error");
    }

    //Sat May 20 15:21:51 2000
    strftime(buf, 100, "%a %b %d %H:%M:%S %Y", &ts);

    duk_push_string(ctx, buf);

    return 1;
} 

int _time_ctime(duk_context* ctx)
{
    time_t t;
    struct tm ts;
    char buf[100];

    if ((duk_get_top(ctx) == 1) && !duk_is_number(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept integer");
    }

    if (duk_get_top(ctx) == 1) {
        t = duk_to_uint(ctx, 0);
    } else {
        time(&t);
    }

    ts = *localtime(&t);
    //Sat May 20 15:21:51 2000
    strftime(buf, 100, "%a %b %d %H:%M:%S %Y", &ts);

    duk_push_string(ctx, buf);

    return 1;
} 

int _time_strftime(duk_context* ctx)
{
    time_t t;
    struct tm ts;

    const char* s;
    const char* fmt;
    int len;
    char* out;

    int success = 0;
    int ntries = 3;

    if (duk_get_top(ctx) == 0) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "missing format string");

    } else if (duk_get_top(ctx) == 1) {
        time(&t);
        ts = *localtime(&t);

    } else if (duk_get_top(ctx) == 2) {
        if (duk_is_number(ctx, 1)) {
            t = duk_to_uint(ctx, 1);
            ts = *localtime(&t);
        } else {
            duk_get_prop_string(ctx, 1, "name");
            s = duk_to_string(ctx, -1);
            if (strcmp(s, "struct_time") == 0) {
                _helper_unpack_timeobj(ctx, &ts, 1);
                duk_pop(ctx);
            } else {
                duk_error(ctx, DUK_ERR_TYPE_ERROR,
                        "second parameter only accept time or time.struct_time");
            }
        }

    } else {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "parameter only accept time or time.struct_time");
    }

    if (!duk_is_string(ctx, 0)) {
        duk_error(ctx, DUK_ERR_TYPE_ERROR, "only accept string");
    }

    fmt = duk_to_string(ctx, 0);
    len = strlen(fmt) + 100;
    out = (char*)duk_alloc_raw(ctx, len);

    while (ntries--) {
        success = strftime(out, len, fmt, &ts);
        if (success) {
            break;
        }

        len = len * 2;
        out = (char*)duk_realloc_raw(ctx, out, len);
    }

    duk_push_lstring(ctx, out, strlen(out));
    duk_free_raw(ctx, out);

    return 1;
}


//Tips: encoding of fn must convert before used!
//make sure is DUKLIB_DEFAULT_SYSENCODING
int gs_include(duk_context* ctx, const char* fn)
{
    duk_push_c_function(ctx, _include, 1);
    duk_push_string(ctx, fn);


    if (duk_pcall(ctx, 1) != 0) {
        duk_safe_call(ctx, _helper_get_stack_raw, nullptr, 1 /*nargs*/, 1 /*nrets*/);
        fprintf(stderr, "%s\n", duk_safe_to_string(ctx, -1));
        fflush(stderr);
        duk_pop(ctx);

        return 0;
    }
    duk_pop(ctx);

    return 1;
}

int gs_eval_string(duk_context* ctx, const char* s)
{
    if (duk_peval_string(ctx, s) != 0) {
        duk_safe_call(ctx, _helper_get_stack_raw, nullptr, 1 /*nargs*/, 1 /*nrets*/);

        fprintf(stderr, "%s\n", duk_safe_to_string(ctx, -1));
        fflush(stderr);

        return 0;
    }

    return 1;
}

int gs_put_args(duk_context* ctx, int argc, char* argv[])
{
    int obj_id = 0;
    int i = 0;
    int idx = 0;

    duk_push_global_object(ctx);
    duk_get_prop_string(ctx, -1, "Modules");
    if (duk_is_undefined(ctx, -1)) {
        return 0;
    }

    duk_get_prop_string(ctx, -1, "sys");
    if (duk_is_undefined(ctx, -1)) {
        return 0;
    }

    obj_id = duk_push_array(ctx);
    for (i = 1;i < argc;i++) {
        duk_push_lstring(ctx, argv[i], strlen(argv[i]));
        duk_put_prop_index(ctx, obj_id, idx++);
    }
    duk_put_prop_string(ctx, -2, "args");

    duk_pop(ctx);//pop 'sys'
    duk_pop(ctx);//pop 'Modules'
    duk_pop(ctx);//pop 'global'

    return argc-1;
}

//2 step:
//
//first : set function_entry.name  = function_name
//second: set global.function_name = function_entry
//must push object to stack first!
int gs_put_c_method(duk_context* ctx,
        const char* function_name,
        duk_c_function function_entry)
{
    char* p;
    int n;

    duk_push_c_function(ctx, function_entry, DUK_VARARGS);

    n = strlen(function_name);
    p = (char *) duk_alloc_raw(ctx, n + 10 + 1);
    memset(p, 0, n + 10 + 1);
    memcpy(p, "__stdlib__", 10);
    memcpy(p+10, function_name, n);
    duk_push_string(ctx, p);
    duk_free_raw(ctx, p);
    duk_put_prop_string(ctx, -2, "name");

    duk_put_prop_string(ctx, -2, function_name);

    return 0;
}

int gs_put_c_function(duk_context* ctx,
        const char* function_name,
        duk_c_function function_entry)
{
    duk_push_global_object(ctx);
    gs_put_c_method(ctx, function_name, function_entry);
    duk_pop(ctx);

    return 0;
}

const char* gs_type_name(duk_context* ctx, duk_idx_t index)
{
    int t;

    t = duk_get_type(ctx, index);

    switch(t) {
        case DUK_TYPE_NONE:
            return "none";
        case DUK_TYPE_UNDEFINED:
            return "undefined";
        case DUK_TYPE_NULL:
            return "null";
        case DUK_TYPE_BOOLEAN:
            return "boolean";
        case DUK_TYPE_NUMBER:
            return "number";
        case DUK_TYPE_STRING:
            return "string";
        case DUK_TYPE_OBJECT:
            return "object";
        case DUK_TYPE_BUFFER:
            return "buffer";
        case DUK_TYPE_POINTER:
            return "pointer";
        default:
            return "error";
    }
}


void _dukopen_buildin_extend(duk_context* ctx)
{
    duk_push_global_object(ctx);

    gs_put_c_method(ctx, "ord",                 _ord);
    gs_put_c_method(ctx, "chr",                 _chr);
    gs_put_c_method(ctx, "hex",                 _hex);
    gs_put_c_method(ctx, "globals",             _globals);
    gs_put_c_method(ctx, "dir",                 _dir);
    gs_put_c_method(ctx, "include",             _include);
    gs_put_c_method(ctx, "deepcopy1",           _deepcopy1);

    duk_pop(ctx);
}

void _push_traces_obj(duk_context* ctx)
{
    duk_push_global_object(ctx);
    duk_push_undefined(ctx);
    duk_put_prop_string(ctx, -2, "__file__");
    duk_pop(ctx);

    duk_push_array(ctx);
}

void _push_fs_obj(duk_context* ctx)
{
    duk_push_object(ctx);
    gs_put_c_method(ctx, "open",                _fs_open);
    gs_put_c_method(ctx, "file_get_content",    _fs_file_get_content);
    gs_put_c_method(ctx, "file_put_content",    _fs_file_put_content);
}

void _push_os_path_obj(duk_context* ctx)
{
    duk_push_object(ctx);
    gs_put_c_method(ctx, "isdir",               _ospath_isdir);
    gs_put_c_method(ctx, "isfile",              _ospath_isfile);
    gs_put_c_method(ctx, "exists",              _ospath_exists);
    gs_put_c_method(ctx, "join",                _ospath_join);
    gs_put_c_method(ctx, "dirname",             _ospath_dirname);
    gs_put_c_method(ctx, "split",               _ospath_split);
    gs_put_c_method(ctx, "splitext",            _ospath_splitext);
    gs_put_c_method(ctx, "normpath",            _ospath_normpath);
    gs_put_c_method(ctx, "abspath",             _ospath_abspath);
}

void _push_os_obj(duk_context* ctx)
{
    duk_push_object(ctx);

    gs_put_c_method(ctx, "getcwd",              _os_getcwd);
    gs_put_c_method(ctx, "data",              _os_getdatadir);
    gs_put_c_method(ctx, "modules",              _os_getmoduledir);
    gs_put_c_method(ctx, "workspace",              _os_getworkspacedir);
#ifdef DUK_F_WINDOWS
    duk_push_string(ctx, "nt");
#else
    duk_push_string(ctx, "posix");
#endif
    duk_put_prop_string(ctx, -2, "name");
}

void _push_time_obj(duk_context* ctx)
{
    duk_push_object(ctx);
    gs_put_c_method(ctx, "time",                _time_time);
    gs_put_c_method(ctx, "localtime",           _time_localtime);
    gs_put_c_method(ctx, "gmtime",              _time_gmtime);
    gs_put_c_method(ctx, "asctime",             _time_asctime);
    gs_put_c_method(ctx, "ctime",               _time_ctime);
    gs_put_c_method(ctx, "strftime",            _time_strftime);
}

void _push_sys_obj(duk_context* ctx)
{
    duk_push_object(ctx);
    duk_push_undefined(ctx);
    duk_put_prop_string(ctx, -2, "args");
}

void _push_subprocess_obj(duk_context* ctx)
{
    duk_push_object(ctx);
    gs_put_c_method(ctx, "open", _ps_open);
}

void _set_modsearch(duk_context* ctx)
{
    const char script[] = 
        "Duktape.modSearch = function (id, include, exports, module) {\r\n"
        "    var obj = Modules[id];\r\n"
        "    if (obj) {\r\n"
        "        deepcopy1(obj, exports);\r\n"
        "        return;\r\n"
        "\r\n"
        "    } else {\r\n"
        "        //try load script\r\n"
        "        var os         = Modules.os;\r\n"
        "        var fs         = Modules.fs;\r\n"
        "        var path       = os.path;\r\n"
        "        var dirname    = path.dirname(__file__);\r\n"
        "        var fn         = path.join(dirname, id);\r\n"
        "        var absfn      = path.abspath(fn);\r\n"
        "        if (!path.isfile(absfn)) {\r\n"
        "            dirname    = os.getcwd();\r\n"
        "            fn         = path.join(dirname, id);\r\n"
        "            absfn      = path.abspath(fn);\r\n"
        "            if (!path.isfile(absfn)) {\r\n"
        "                throw new Error('module not found: ' + id);\r\n"
        "            }\r\n"
        "        }\r\n"
        "\r\n"
        "        return fs.file_get_content(absfn);\r\n"
        "    }\r\n"
        "\r\n"
        "    throw new Error('module not found: ' + id);\r\n"
        "}\r\n";

    duk_eval_string_noresult(ctx, script);
}

int dukopen_gs(duk_context* ctx)
{
    _dukopen_buildin_extend(ctx);

    ////////////////////////////////////////////////////////
    duk_push_global_object(ctx);
    duk_push_object(ctx);


    _push_traces_obj(ctx);
    duk_put_prop_string(ctx, -2, "traces");

    _push_fs_obj(ctx);
    duk_put_prop_string(ctx, -2, "fs");

    _push_os_obj(ctx);
    _push_os_path_obj(ctx);
    duk_put_prop_string(ctx, -2, "path");
    duk_put_prop_string(ctx, -2, "os");

    _push_os_path_obj(ctx);
    duk_put_prop_string(ctx, -2, "os.path");

    _push_time_obj(ctx);
    duk_put_prop_string(ctx, -2, "time");

    _push_sys_obj(ctx);
    duk_put_prop_string(ctx, -2, "sys");

    _push_subprocess_obj(ctx);
    duk_put_prop_string(ctx, -2, "_subprocess");


    duk_put_prop_string(ctx, -2, "Modules");
    duk_pop(ctx);//pop [global]

    ////////////////////////////////////////////////////////
    _set_modsearch(ctx);

    return 0;
}


static duk_ret_t compile_module(duk_context *ctx) {
	const char *path = (const char *) duk_require_pointer(ctx, -3);
    const char *name = (const char *) duk_require_pointer(ctx, -2);
        
    fs::path src(path);
    FILE *fp = fsbridge::fopen(src, "r");

    std::string s;
    if (fp) {
        while (int c = fgetc(fp)) {
            s += (char) c;
        }
        fclose(fp);
    }
    s = std::string("(function(module, exports) {") + std::string(s) + std::string("})");

	duk_uint_t flags = DUK_COMPILE_SHEBANG;
	duk_compile_lstring_filename(ctx, flags, s.c_str(), s.length());

    duk_dup_top(ctx);
	duk_dump_function(ctx);

    duk_size_t bc_len = 0;
	void *bc = duk_require_buffer_data(ctx, -1, &bc_len);
        
    fs::path dir = GetDefaultDataDir() / "modules/";
    TryCreateDirectories(dir);
    fs::path mod = dir / (std::string(name) + ".module");

    fp = fsbridge::fopen(mod, "wb");
    if (fp) {
        fwrite(bc, 1, bc_len, fp);
        fclose(fp);
    }

    return 0;
}

static duk_ret_t load_file(duk_context *ctx) {
	const char *path = (const char *) duk_require_pointer(ctx, -3);

    fs::path src(path);
    FILE *fp = fsbridge::fopen(src, "r");

    std::string s;
    if (fp) {
        while (int c = fgetc(fp)) {
            s += (char) c;
        }
        fclose(fp);
    }
    s = std::string("(function(module, exports) {") + std::string(s) + std::string("})");

	duk_uint_t flags = DUK_COMPILE_SHEBANG;
	duk_compile_lstring_filename(ctx, flags, s.c_str(), s.length());

    return 0;
}

static duk_ret_t require(duk_context *ctx) {
    const char *name = (const char *) duk_require_pointer(ctx, -2);

    fs::path dir = GetDefaultDataDir() / "modules/";
    TryCreateDirectories(dir);
    fs::path mod = dir / (std::string(name) + ".module");

    size_t size = 0; void *code = nullptr;

    FILE *fp = fsbridge::fopen(mod, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        code = malloc(size);
        fread(code, 1, size, fp);
        fclose(fp);


        void *buf = duk_push_fixed_buffer(ctx, size);
	    memcpy(buf, code, size);
	    duk_load_function(ctx);

        return 1;
    }
        	
    return 0;
}



bool GSInit() {
    ctx = duk_create_heap_default();
    if (!ctx) return false;

    duk_console_init(ctx, false);

	/*duk_push_c_function(ctx, fileio_read_file, 1);
	duk_put_global_string(ctx, "readFile");

	duk_push_c_function(ctx, fileio_write_file, 2);
	duk_put_global_string(ctx, "writeFile");

    dukopen_gs(ctx);*/

    return true;
}

void GSShutdown() {
    if (ctx) duk_destroy_heap(ctx);
}

bool GSExec(const std::string &code) {
    if (code.empty()) return false;
    duk_peval_string_noresult(ctx, code.c_str());
	return true;
}
