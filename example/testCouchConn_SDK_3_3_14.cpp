#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/util.h>
#include <libcouchbase/couchbase.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <queue>
#include <string>
#include <ctime>
#include <sstream>
#include <atomic>
#include <sys/time.h>
using namespace std;

#define JSON_ENCODING_CMD_FLAG ((0x02 << 24) | (0x00))
/* mutex for protection of libcouchbase internal structures
   and IO loop */
pthread_mutex_t iolock = PTHREAD_MUTEX_INITIALIZER;
pthread_t iothread;

lcb_INSTANCE **instance;

/* mutex for implementing thread-safe container */
pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
std::queue<std::string> msg_queue;

#define NUM_OF_REQ 1

std::atomic_bool running{true};

int MAX_DB_GET_REQUEST = 1;
int MAX_DB_INSERT_DELETE_REQUEST = 1;
int MAX_THREAD_COUNT = 2;
int SLEEP_TIME = 1000;
int includeSubDoc = 0;
bool isConnected = false;
bool isWait = false;
int insertLatency = 0;
int getLatency = 0;
int delLatency = 0;
int totalReq = 0;
int totalResp = 0;

// char connStr [100] = "couchbase://10.10.223.192,10.10.223.138,10.10.223.139/poc";
// char dbUserName [100] = "poc";
// char dbPassword [100] = "abcxyz";
char *connStr;
char *dbUserName;
char *dbPassword;
int maxLps = 1;

lcb_INSTANCE *clientHandleInstance2 = NULL;
int currentThread = 1;
#define lcb_logprocs MyLogprocs

struct MyLogprocs {
    MyLogprocs()
    {
        base = NULL;
    }
    lcb_LOGGER *base;
    lcb_LOG_SEVERITY min_level;
};

lcb_logprocs logProcs;

lcb_INSTANCE **mClientHandlePrimarySiteInstance;

char *getLocalTime()
{
    time_t timetoday;
    struct tm *timeinfo;

    time(&timetoday);
    timeinfo = localtime(&timetoday);
    return asctime(timeinfo);
}

const char *level_to_string(lcb_LOG_SEVERITY severity)
{
    switch (severity) {
        case LCB_LOG_TRACE:
            return "TRACE";
        case LCB_LOG_DEBUG:
            return "DEBUG";
        case LCB_LOG_INFO:
            return "INFO";
        case LCB_LOG_WARN:
            return "WARN";
        case LCB_LOG_ERROR:
            return "ERROR";
        case LCB_LOG_FATAL:
            return "FATAL";
        default:
            return "";
    }
}

void logger(const lcb_LOGGER *logger, uint64_t param2, const char *subsys, lcb_LOG_SEVERITY severity,
            const char *srcfile, int, const char *fmt, va_list ap)
{
    char buf[4096];
    vsnprintf(buf, 4096, fmt, ap);
    fprintf(stderr, "[couchbase SDK %s::] [%s]\n", level_to_string(severity), buf);
}

typedef struct {
    long int startTime;
    long int endTime;
} corId;

time_t getTime()
{
    time_t currentTime;
    time(&currentTime);
    return currentTime;
}

long int getTime2()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
}

static void operation_callback(lcb_INSTANCE *mClientHandleInstance, int cbtype, const lcb_RESPBASE *rb)
{
    lcb_STATUS rc;
    void *pCorId;

    const char *value;
    const char *key;
    size_t nvalue = 0, nkey = 0;
    uint64_t cas = 0;
    uint32_t itmflags = 0;

    corId *pC = NULL;

    if (cbtype == LCB_CALLBACK_STORE) {
        const lcb_RESPSTORE *resp = (const lcb_RESPSTORE *)rb;
        lcb_respstore_cookie(resp, &pCorId);
        pC = reinterpret_cast<corId *>(pCorId);
        rc = lcb_respstore_status(resp);
        lcb_respstore_key(resp, &key, &nkey);
        insertLatency = insertLatency + (getTime2() - pC->startTime);
    }
    if (cbtype == LCB_CALLBACK_GET) {
        const lcb_RESPGET *resp = (const lcb_RESPGET *)rb;
        lcb_respget_cookie(resp, &pCorId);
        pC = reinterpret_cast<corId *>(pCorId);
        rc = lcb_respget_status(resp);
        lcb_respget_key(resp, &key, &nkey);
        getLatency = getLatency + (getTime2() - pC->startTime);
    }
    if (cbtype == LCB_CALLBACK_REMOVE) {
        const lcb_RESPREMOVE *resp = (const lcb_RESPREMOVE *)rb;
        lcb_respremove_cookie(resp, &pCorId);
        pC = reinterpret_cast<corId *>(pCorId);
        rc = lcb_respremove_status(resp);
        lcb_respremove_key(resp, &key, &nkey);
        delLatency = delLatency + (getTime2() - pC->startTime);
    }
    if (cbtype == LCB_CALLBACK_SDLOOKUP) {
        const lcb_RESPSUBDOC *resp = (const lcb_RESPSUBDOC *)rb;
        lcb_respsubdoc_cookie(resp, &pCorId);
        rc = lcb_respsubdoc_status(resp);
        lcb_respsubdoc_key(resp, &key, &nkey);
    }
    if (cbtype == LCB_CALLBACK_SDMUTATE) {
        const lcb_RESPSUBDOC *resp = (const lcb_RESPSUBDOC *)rb;
        lcb_respsubdoc_cookie(resp, &pCorId);
        rc = lcb_respsubdoc_status(resp);
        lcb_respsubdoc_key(resp, &key, &nkey);
    }

    if (rc == LCB_SUCCESS) {

        if (cbtype == LCB_CALLBACK_GET) {
            const lcb_RESPGET *resp = (const lcb_RESPGET *)rb;
            lcb_respget_key(resp, &key, &nkey);
            lcb_respget_value(resp, &value, &nvalue);
            lcb_respget_cas(resp, &cas);
            lcb_respget_flags(resp, &itmflags);
            fprintf(stderr, "cbType = [%s], KEY = [%.*s], VALUE: [%.*s], time[%d]\n", lcb_strcbtype(cbtype), (int)nkey,
                    key, (int)nvalue, value, (int)getTime());
            // printf("cbType = [%s], KEY = [%.*s], VALUE: [%.*s], time[%d]\n", lcb_strcbtype(cbtype), nkey, key,
            // nvalue, value, getTime());
        } else if (cbtype == LCB_CALLBACK_SDLOOKUP) {
            const lcb_RESPSUBDOC *resp = (const lcb_RESPSUBDOC *)rb;
            size_t resSize = lcb_respsubdoc_result_size(resp);
            lcb_STATUS resStatus = lcb_respsubdoc_result_status(resp, 0);
            fprintf(stderr, "LCB_CALLBACK_SDLOOKUP result status [%s], result size [%d]\n",
                    lcb_strerror_short(resStatus), (int)resSize);
            if (LCB_SUCCESS == resStatus) {
                resStatus = lcb_respsubdoc_result_value(resp, 0, &value, &nvalue);
                fprintf(stderr, "LCB_CALLBACK_SDLOOKUP result Value status [%s], result size [%d]\n",
                        lcb_strerror_short(resStatus), (int)nvalue);
                if (LCB_SUCCESS == resStatus && nvalue > 0) {
                    fprintf(stderr, "cbType = [%s], KEY = [%.*s], VALUE: [%.*s], time[%d]\n", lcb_strcbtype(cbtype),
                            (int)nkey, key, (int)nvalue, value, (int)getTime());
                }
            }
        } else {
            fprintf(stderr, "cbType = [%s], KEY = [%.*s], time[%d]\n", lcb_strcbtype(cbtype), (int)nkey, key,
                    (int)getTime());
            // printf("cbType = [%s], KEY = [%.*s], time[%d]\n", lcb_strcbtype(cbtype), nkey, key, getTime());
        }

    } else {

        fprintf(stderr, "cbType = [%s], KEY = [%.*s], errorString = [%s], time[%d]\n", lcb_strcbtype(cbtype), (int)nkey,
                key, lcb_strerror_long(rc), (int)getTime());
        // printf("cbType = [%s], KEY = [%.*s], errorString = [%s], time[%d]\n", lcb_strcbtype(cbtype), nkey, key,
        // lcb_strerror_long(rc), getTime());
    }

    delete pC;
    totalResp++;
}

static void bootstrap_callback(lcb_INSTANCE *instance, lcb_STATUS err)
{
    // printf("Bootstrapped\n");
    if (err != LCB_SUCCESS)
        fprintf(stderr, "Bootstrap Failed, [%s]\n", lcb_strerror_long(err));
    else {
        fprintf(stderr, "Bootstrap Success\n");
        isConnected = true;
    }
    // lcb_set_cookie(instance, evbase);
}

static void *io_runner(void *arg)
{
#ifdef __linux__
    pthread_setname_np(pthread_self(), "io_runner");
#endif
    int count = 0;

    struct event_base *evbase = (struct event_base *)arg;
    while (true) {
        /* get the IO mutex to protect libcouchbase structures
           and operation callbacks which might modify lcb_INSTANCE instances
         */
        pthread_mutex_lock(&iolock);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        pthread_mutex_unlock(&iolock);
        if (count < 10) {
            fprintf(stderr, "----> event_base_loop\n");
            count++;
        }

        /* give other threads chance to execute and schedule some work */
        usleep(10);
    }
    printf("io_runner Exit \n");
    return NULL;
}

/**
 creates common IO structure, which abstracts all networking functions
 and runs event loop
*/
static lcb_io_opt_t create_libevent_io_ops(struct event_base *evbase)
{
    struct lcb_create_io_ops_st ciops;
    lcb_io_opt_t ioops;
    lcb_STATUS error;

    ciops.version = 0;
    ciops.v.v0.type = LCB_IO_OPS_LIBEVENT;
    ciops.v.v0.cookie = evbase;

    error = lcb_create_io_ops(&ioops, &ciops);
    if (error != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create an IOOPS structure for libevent: %s\n", lcb_strerror_long(error));
        exit(EXIT_FAILURE);
    }

    return ioops;
}

bool initSubdocReq(int i, lcb_CMDSUBDOC *&rcmd, lcb_SUBDOCSPECS *&specs)
{

    lcb_STATUS rc;
    rc = lcb_cmdsubdoc_create(&rcmd);
    std::stringstream key;
    key << i << "subdoc_simpleTest";
    std::string ssKey = key.str();
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Failed lcb_cmdsubdoc_key: %s\n", lcb_strerror_short(rc));
        return false;
    }

    rc = lcb_cmdsubdoc_key(rcmd, ssKey.c_str(), ssKey.length());
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Failed lcb_cmdsubdoc_key: %s\n", lcb_strerror_short(rc));
        lcb_cmdsubdoc_destroy(rcmd);
        return false;
    }

    rc = lcb_subdocspecs_create(&specs, 1);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Failed lcb_subdocspecs_create: %s\n", lcb_strerror_short(rc));
        lcb_cmdsubdoc_destroy(rcmd);
        lcb_subdocspecs_destroy(specs);
        return false;
    }
    return true;
}

void executeSubDoc(lcb_INSTANCE *clientHandleInstance)
{

    for (int i = 1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++) {
        // pthread_mutex_unlock(&qlock);
        lcb_STATUS err;
        lcb_STATUS rc;
        lcb_CMDSTORE *cmd = NULL;
        rc = lcb_cmdstore_create(&cmd, LCB_STORE_INSERT);
        if (rc != LCB_SUCCESS) {
            printf("lcb_cmdstore_create failed: %s\n", lcb_strerror_short(rc));
            return;
        }
        lcb_cmdstore_flags(cmd, JSON_ENCODING_CMD_FLAG);
        std::string val("{\"doc\":\"subdoc_simpleTest\",\"val\":1}");
        corId *cookie = new corId;
        cookie->startTime = getTime2();

        std::stringstream key;
        key << i << "subdoc_simpleTest";
        std::string ssKey = key.str();
        fprintf(stderr, "Start InsertDoc Key[%s], value[%s], time[%d]\n", ssKey.c_str(), val.c_str(), (int)getTime());
        err = lcb_cmdstore_key(cmd, ssKey.c_str(), ssKey.length());

        err = lcb_cmdstore_value(cmd, val.c_str(), val.length());
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        err = lcb_store(clientHandleInstance, cookie, cmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_cmdstore_destroy(cmd);
        if (err != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule Insert request: %s\n", lcb_strerror_long(err));
        }
        usleep(SLEEP_TIME);
    }
    for (int i = 1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++) {
        lcb_CMDSUBDOC *rcmd;
        lcb_SUBDOCSPECS *specs;
        lcb_STATUS rc;
        corId *cookie = new corId;
        cookie->startTime = getTime2();
        int flags = 0;
        if (initSubdocReq(i, rcmd, specs) == false) {
            return;
        }
        std::string path = "path1";
        std::string value = "123";

        flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
        lcb_subdocspecs_dict_add(specs, 0, flags, path.c_str(), path.length(), value.c_str(), value.length());
        lcb_cmdsubdoc_specs(rcmd, specs);
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        rc = lcb_subdoc(clientHandleInstance, cookie, rcmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_subdocspecs_destroy(specs);
        lcb_cmdsubdoc_destroy(rcmd);
        if (rc != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule subdoc insert request: %s\n", lcb_strerror_short(rc));
            return;
        }
        usleep(SLEEP_TIME);
    }
    for (int i = 1; i <= MAX_DB_GET_REQUEST; i++) {
        // pthread_mutex_unlock(&qlock);
        lcb_STATUS rc;
        lcb_CMDGET *gcmd;
        rc = lcb_cmdget_create(&gcmd);
        if (rc != LCB_SUCCESS) {
            printf("lcb_cmdget_create failed: %s\n", lcb_strerror_short(rc));
            return;
        }
        corId *cookie = new corId;
        cookie->startTime = getTime2();
        std::stringstream key;
        key << i << "subdoc_simpleTest";
        std::string ssKey = key.str();

        fprintf(stderr, "Start GetDoc Key[%s], time[%d]\n", ssKey.c_str(), (int)getTime());
        lcb_cmdget_key(gcmd, ssKey.c_str(), ssKey.length());
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        rc = lcb_get(clientHandleInstance, cookie, gcmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_cmdget_destroy(gcmd);
        if (rc != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule Get request: %s\n", lcb_strerror_long(rc));
        }
        usleep(SLEEP_TIME);
    }
    for (int i = 1; i <= MAX_DB_GET_REQUEST; i++) {
        lcb_CMDSUBDOC *rcmd;
        lcb_SUBDOCSPECS *specs;
        lcb_STATUS rc;
        int flags = 0;
        corId *cookie = new corId;
        cookie->startTime = getTime2();
        if (initSubdocReq(i, rcmd, specs) == false) {
            return;
        }
        std::string path = "path1";
        lcb_subdocspecs_get(specs, 0, flags, path.c_str(), path.length());
        lcb_cmdsubdoc_specs(rcmd, specs);
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        rc = lcb_subdoc(clientHandleInstance, cookie, rcmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_subdocspecs_destroy(specs);
        lcb_cmdsubdoc_destroy(rcmd);
        if (rc != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule subdoc get: %s\n", lcb_strerror_short(rc));
            return;
        }
    }
    /*for (int i=1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++)
    {
        lcb_CMDSUBDOC* rcmd;
        lcb_SUBDOCSPECS* specs;
        lcb_STATUS rc;
        corId *cookie = new corId;
        cookie->startTime=getTime2();
        int flags = 0;
        if (initSubdocReq(i,rcmd,specs) == false) {
            return;
        }
        std::string path = "path1";
        std::string value = "value1";
        lcb_subdocspecs_remove(specs, 0, flags, path.c_str(),path.length());
    }*/
    for (int i = 1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++) {
        // pthread_mutex_unlock(&qlock);
        lcb_STATUS rc;
        lcb_CMDREMOVE *rcmd;
        rc = lcb_cmdremove_create(&rcmd);
        if (rc != LCB_SUCCESS) {
            printf("lcb_cmdremove_create failed: %s\n", lcb_strerror_short(rc));
            return;
        }
        corId *cookie = new corId;
        cookie->startTime = getTime2();
        lcb_STATUS err;
        std::stringstream key;
        key << i << "subdoc_simpleTest";
        std::string ssKey = key.str();

        fprintf(stderr, "Start DeleteDoc Key[%s], time[%d]\n", ssKey.c_str(), (int)getTime());
        lcb_cmdremove_key(rcmd, ssKey.c_str(), ssKey.length());
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        err = lcb_remove(clientHandleInstance, cookie, rcmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_cmdremove_destroy(rcmd);
        if (err != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule Delete request: %s\n", lcb_strerror_long(err));
        }
        usleep(SLEEP_TIME);
    }
    return;
}

void ping_handler(lcb_INSTANCE *currenClientHandleInstance)
{
    lcb_STATUS rc;
    lcb_CMDPING *cmd;
    // select services to ping
    rc = lcb_cmdping_create(&cmd);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Failed lcb_cmdping_create: %s", lcb_strerror_short(rc));
        return;
    }
    lcb_cmdping_kv(cmd, true);
    lcb_cmdping_encode_json(cmd, true, false, false);
    lcb_sched_enter(currenClientHandleInstance);
    corId *cookie = new corId;
    cookie->startTime = getTime2();
    rc = lcb_ping(currenClientHandleInstance, cookie, cmd);
    lcb_sched_leave(currenClientHandleInstance);
    lcb_cmdping_destroy(cmd);
}

void ping_callback(lcb_INSTANCE *mClientHandleInstance, int cbtype, const lcb_RESPBASE *rb)
{
    lcb_STATUS rc;
    void *pCorId;
    const lcb_RESPPING *resp = (const lcb_RESPPING *)rb;
    size_t njson = 0;
    const char *json = NULL;
    corId *pC = NULL;
    lcb_respping_cookie(resp, &pCorId);
    pC = reinterpret_cast<corId *>(pCorId);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "ping failed: %s", lcb_strerror_short(rc));
    } else {
        rc = lcb_respping_value(resp, &json, &njson);
        if (rc != LCB_SUCCESS) {
            fprintf(stderr, "ping_callback lcb_respping_value Error:%s", lcb_strerror_short(rc));
        }
        if (njson) {
            fprintf(stderr, "[ping_callback]%.*s", (int)njson, json);
        }
    }
    delete pC;
}

void *couchbaseConnectAndExecutePing(void *)
{
    printf("couchbaseConnectAndExecutePing tid[%d]\n", (int)pthread_self());
    lcb_INSTANCE *clientHandleInstance = NULL;
    struct event_base *evbase = event_base_new();
    lcb_io_opt_t ioops = create_libevent_io_ops(evbase);
    lcb_STATUS err;
    lcb_STATUS error;
    lcb_CREATEOPTS *options;

    // memset(&options, 0, sizeof(options));
    err = lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_create [%s]\n", lcb_strerror_long(err));
        return 0;
    }
    err = lcb_createopts_connstr(options, connStr, strlen(connStr));
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_connstr [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    err = lcb_createopts_credentials(options, dbUserName, strlen(dbUserName), dbPassword, strlen(dbPassword));
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_credentials [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    clientHandleInstance = mClientHandlePrimarySiteInstance[currentThread];
    currentThread++;
    lcb_createopts_io(options, ioops);

    lcb_logprocs &logprocs = logProcs;
    lcb_logger_create(&logprocs.base, &logprocs);
    lcb_logger_callback(logprocs.base, logger);

    logprocs.min_level = (lcb_LOG_SEVERITY)1;

    err = lcb_createopts_logger(options, logprocs.base);
    if ((err != LCB_SUCCESS)) {
        printf("Couldn't lcb_createopts_logger [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    err = lcb_create(&clientHandleInstance, options);
    if (err != LCB_SUCCESS) {
        printf("Couldn't create couchbase handle [%s]\n", lcb_strerror_long(err));
        return 0;
    }
    lcb_set_bootstrap_callback(clientHandleInstance, bootstrap_callback);
    lcb_cntl_string(clientHandleInstance, "operation_metrics_enabled", "0");
    // lcb_cntl_string(clientHandleInstance, "tracing_enabled", "0");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_kv", "0.03");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_query", "0.3");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_queue_flush_interval", "1");

    lcb_createopts_destroy(options);
    err = lcb_connect(clientHandleInstance);
    if ((err != LCB_SUCCESS)) {
        printf("Couldn't schedule connection [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    lcb_set_cookie(clientHandleInstance, evbase);
    fprintf(stderr, "----> connected\n");
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_PING, ping_callback);

    pthread_t threadId;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&threadId, &attr, io_runner, evbase);
    // pthread_create(&iothread, NULL, io_runner, evbase);

    while (atomic_load(&running)) {
        pthread_mutex_lock(&iolock);
        ping_handler(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        usleep(2000000);
    }

    return 0;
}

void *couchbaseConnectAndExecute(void *)
{
    printf("couchbaseConnectAndExecute tid[%d]\n", (int)pthread_self());
    lcb_INSTANCE *clientHandleInstance = NULL;
    struct event_base *evbase = event_base_new();
    lcb_io_opt_t ioops = create_libevent_io_ops(evbase);
    lcb_STATUS err;
    lcb_STATUS error;
    lcb_CREATEOPTS *options;

    // memset(&options, 0, sizeof(options));
    err = lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_create [%s]\n", lcb_strerror_long(err));
        return 0;
    }
    err = lcb_createopts_connstr(options, connStr, strlen(connStr));
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_connstr [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    err = lcb_createopts_credentials(options, dbUserName, strlen(dbUserName), dbPassword, strlen(dbPassword));
    if (err != LCB_SUCCESS) {
        printf("Couldn't lcb_createopts_credentials [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    clientHandleInstance = mClientHandlePrimarySiteInstance[currentThread];
    currentThread++;
    lcb_createopts_io(options, ioops);

    lcb_logprocs &logprocs = logProcs;
    lcb_logger_create(&logprocs.base, &logprocs);
    lcb_logger_callback(logprocs.base, logger);

    logprocs.min_level = (lcb_LOG_SEVERITY)1;

    err = lcb_createopts_logger(options, logprocs.base);
    if ((err != LCB_SUCCESS)) {
        printf("Couldn't lcb_createopts_logger [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    err = lcb_create(&clientHandleInstance, options);
    if (err != LCB_SUCCESS) {
        printf("Couldn't create couchbase handle [%s]\n", lcb_strerror_long(err));
        return 0;
    }
    lcb_set_bootstrap_callback(clientHandleInstance, bootstrap_callback);
    lcb_cntl_string(clientHandleInstance, "operation_metrics_enabled", "0");
    // lcb_cntl_string(clientHandleInstance, "tracing_enabled", "0");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_kv", "0.03");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_query", "0.3");
    // lcb_cntl_string(clientHandleInstance, "tracing_threshold_queue_flush_interval", "1");

    lcb_createopts_destroy(options);
    err = lcb_connect(clientHandleInstance);
    if ((err != LCB_SUCCESS)) {
        printf("Couldn't schedule connection [%s]\n", lcb_strerror_long(err));
        return 0;
    }

    lcb_set_cookie(clientHandleInstance, evbase);
    fprintf(stderr, "----> connected\n");
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_STORE, operation_callback);
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_GET, operation_callback);
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_REMOVE, operation_callback);
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_SDLOOKUP, operation_callback);
    lcb_install_callback(clientHandleInstance, LCB_CALLBACK_SDMUTATE, operation_callback);

    pthread_t threadId;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&threadId, &attr, io_runner, evbase);
    // pthread_create(&iothread, NULL, io_runner, evbase);

    while (isConnected == false && atomic_load(&running)) {
        fprintf(stderr, "Not Connected\n");
        usleep(100000);
    }
#define INFINITE_LOOP 1
#ifdef INFINITE_LOOP
    int i = 0;
    while (atomic_load(&running)) {
        lcb_STATUS err;
        lcb_STATUS rc;
        lcb_CMDSTORE *cmd = NULL;
        rc = lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
        if (rc != LCB_SUCCESS) {
            printf("lcb_cmdstore_create failed: %s\n", lcb_strerror_short(rc));
            return 0;
        }
        lcb_cmdstore_flags(cmd, JSON_ENCODING_CMD_FLAG);
        std::string val("{\"doc\":\"simpleTest\",\"val\":1}");
        corId *cookie = new corId;
        cookie->startTime = getTime2();

        std::stringstream key;
        key << i++ << "simpleTest";
        std::string ssKey = key.str();
        fprintf(stderr, "Start InsertDoc Key[%s], value[%s], time[%d]\n", ssKey.c_str(), val.c_str(), (int)getTime());
        lcb_cmdstore_key(cmd, ssKey.c_str(), ssKey.length());
        lcb_cmdstore_value(cmd, val.c_str(), val.length());
        pthread_mutex_lock(&iolock);
        lcb_sched_enter(clientHandleInstance);
        err = lcb_store(clientHandleInstance, cookie, cmd);
        lcb_sched_leave(clientHandleInstance);
        pthread_mutex_unlock(&iolock);
        lcb_cmdstore_destroy(cmd);
        if (err != LCB_SUCCESS) {
            fprintf(stderr, "Failed to schedule Insert request: %s\n", lcb_strerror_long(err));
        }
        usleep(SLEEP_TIME);
    }
#else
    for (int lps = 0; lps < maxLps; lps++) {
        time_t startTime, endTime;
        startTime = getTime();

        for (int i = 1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++) {
            // pthread_mutex_unlock(&qlock);
            lcb_STATUS err;
            lcb_STATUS rc;
            lcb_CMDSTORE *cmd = NULL;
            rc = lcb_cmdstore_create(&cmd, LCB_STORE_INSERT);
            if (rc != LCB_SUCCESS) {
                printf("lcb_cmdstore_create failed: %s\n", lcb_strerror_short(rc));
                return 0;
            }
            lcb_cmdstore_flags(cmd, JSON_ENCODING_CMD_FLAG);
            std::string val("{\"doc\":\"simpleTest\",\"val\":1}");
            corId *cookie = new corId;
            cookie->startTime = getTime2();

            std::stringstream key;
            key << i << "simpleTest";
            std::string ssKey = key.str();
            fprintf(stderr, "Start InsertDoc Key[%s], value[%s], time[%d]\n", ssKey.c_str(), val.c_str(),
                    (int)getTime());
            err = lcb_cmdstore_key(cmd, ssKey.c_str(), ssKey.length());

            err = lcb_cmdstore_value(cmd, val.c_str(), val.length());
            pthread_mutex_lock(&iolock);
            lcb_sched_enter(clientHandleInstance);
            err = lcb_store(clientHandleInstance, cookie, cmd);
            lcb_sched_leave(clientHandleInstance);
            pthread_mutex_unlock(&iolock);
            lcb_cmdstore_destroy(cmd);
            if (err != LCB_SUCCESS) {
                fprintf(stderr, "Failed to schedule Insert request: %s\n", lcb_strerror_long(err));
            }
            usleep(SLEEP_TIME);
        }

        endTime = getTime();
        // fprintf(stderr,"InsertDoc startTime[%d], endTime[%d], Latency[%.6f]\n", startTime, endTime, (float)(endTime-
        // startTime)/MAX_DB_INSERT_DELETE_REQUEST);
        fflush(stderr);
        startTime = getTime();

        for (int i = 1; i <= MAX_DB_GET_REQUEST; i++) {
            // pthread_mutex_unlock(&qlock);
            lcb_STATUS rc;
            lcb_CMDGET *gcmd;
            rc = lcb_cmdget_create(&gcmd);
            if (rc != LCB_SUCCESS) {
                printf("lcb_cmdget_create failed: %s\n", lcb_strerror_short(rc));
                return 0;
            }
            corId *cookie = new corId;
            cookie->startTime = getTime2();
            std::stringstream key;
            key << i << "simpleTest";
            std::string ssKey = key.str();

            fprintf(stderr, "Start GetDoc Key[%s], time[%d]\n", ssKey.c_str(), (int)getTime());
            lcb_cmdget_key(gcmd, ssKey.c_str(), ssKey.length());
            pthread_mutex_lock(&iolock);
            lcb_sched_enter(clientHandleInstance);
            err = lcb_get(clientHandleInstance, cookie, gcmd);
            lcb_sched_leave(clientHandleInstance);
            pthread_mutex_unlock(&iolock);
            lcb_cmdget_destroy(gcmd);
            if (err != LCB_SUCCESS) {
                fprintf(stderr, "Failed to schedule Get request: %s\n", lcb_strerror_long(err));
            }
            usleep(SLEEP_TIME);
        }

        endTime = getTime();
        // fprintf(stderr,"GetDoc startTime[%d], endTime[%d], Latency[%.6f]\n", startTime, endTime, (float)(endTime-
        // startTime)/MAX_DB_GET_REQUEST);
        fflush(stderr);
        startTime = getTime();

        for (int i = 1; i <= MAX_DB_INSERT_DELETE_REQUEST; i++) {
            // pthread_mutex_unlock(&qlock);
            lcb_STATUS rc;
            lcb_CMDREMOVE *rcmd;
            rc = lcb_cmdremove_create(&rcmd);
            if (rc != LCB_SUCCESS) {
                printf("lcb_cmdremove_create failed: %s\n", lcb_strerror_short(rc));
                return 0;
            }
            corId *cookie = new corId;
            cookie->startTime = getTime2();
            lcb_STATUS err;
            std::stringstream key;
            key << i << "simpleTest";
            std::string ssKey = key.str();

            fprintf(stderr, "Start DeleteDoc Key[%s], time[%d]\n", ssKey.c_str(), (int)getTime());
            lcb_cmdremove_key(rcmd, ssKey.c_str(), ssKey.length());
            pthread_mutex_lock(&iolock);
            lcb_sched_enter(clientHandleInstance);
            err = lcb_remove(clientHandleInstance, cookie, rcmd);
            lcb_sched_leave(clientHandleInstance);
            pthread_mutex_unlock(&iolock);
            lcb_cmdremove_destroy(rcmd);
            if (err != LCB_SUCCESS) {
                fprintf(stderr, "Failed to schedule Delete request: %s\n", lcb_strerror_long(err));
            }
            usleep(SLEEP_TIME);
        }
        executeSubDoc(clientHandleInstance);

        std::string inputarg;
        std::cout << "Enter 1 to continue another run:\n";
        std::cin >> inputarg;
        if (inputarg == "1") {
            executeSubDoc(clientHandleInstance);
        }
        endTime = getTime();
        // fprintf(stderr,"DeleteDoc startTime[%d], endTime[%d], Latency[%.6f]\n", startTime, endTime, (float)(endTime-
        // startTime)/MAX_DB_INSERT_DELETE_REQUEST);
    }
    while (totalResp < totalReq * maxLps) {
        fprintf(stderr, "totalResp[%d], totalReq[%d]\n", totalResp, totalReq);
        usleep(100);
    }
    fprintf(stderr, "totalResp[%d], totalReq[%d]\n", totalResp, totalReq);
    fprintf(stderr, "InsertDoc Avg Latency[%d]\n", (insertLatency) / MAX_DB_INSERT_DELETE_REQUEST);
    fprintf(stderr, "GetDoc Avg Latency[%d]\n", (getLatency) / MAX_DB_GET_REQUEST);
    fprintf(stderr, "DeleteDoc Avg Latency[%d]\n", (delLatency) / MAX_DB_INSERT_DELETE_REQUEST);
    fflush(stderr);
    // pthread_join(iothread, NULL);

    // lcb_destroy_io_ops(ioops);
    // for (int j = 0; j < 1; j++) {
    //    lcb_destroy(mClientHandlePrimarySiteInstance[j]);
    //}
#endif

    return 0;
}

static void sigint_handler(int)
{
    fprintf(stderr, "\nSIGINT\n");
    running = false;
}

static void setup_sigint_handler()
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = sigint_handler;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf(
            "call main, with arguments, first argument is db ip, second argument username, third argument password\n");
        return 0;
    }

    /*

    ./build/bin/examples/testCouchConn_SDK_3_3_14 $(cbdinocluster connstr $(cbdinocluster ps --json | jq -r
    .[0].id))/default  \ Administrator password 100000 100000 10

    */

    connStr = argv[1];
    dbUserName = argv[2];
    dbPassword = argv[3];
    if (argc > 4) {
        char *p;
        MAX_DB_INSERT_DELETE_REQUEST = strtol(argv[4], &p, 10);
    }
    if (argc > 5) {
        char *p;
        MAX_DB_GET_REQUEST = strtol(argv[5], &p, 10);
    }
    if (argc > 6) {
        char *p;
        SLEEP_TIME = strtol(argv[6], &p, 10);
    }

    totalReq = MAX_DB_INSERT_DELETE_REQUEST + MAX_DB_INSERT_DELETE_REQUEST + MAX_DB_GET_REQUEST;
    freopen("testCouchConn.log", "a", stderr);
    setup_sigint_handler();
    mClientHandlePrimarySiteInstance = new lcb_INSTANCE *[MAX_THREAD_COUNT];
    pthread_t tids[MAX_THREAD_COUNT];
    for (int i = 0; i <= MAX_THREAD_COUNT - 2; i++) {
        pthread_t tid1;
        printf("connStr[%s], dbUserName[%s], dbPassword[%s]\n", connStr, dbUserName, dbPassword);
        fprintf(stderr, "connStr[%s], dbUserName[%s], dbPassword[%s]\n", connStr, dbUserName, dbPassword);
        printf("MAX_DB_INSERT_DELETE_REQUEST[%d], MAX_DB_GET_REQUEST[%d], SLEEP_TIME[%d]\n",
               MAX_DB_INSERT_DELETE_REQUEST, MAX_DB_GET_REQUEST, SLEEP_TIME);
        fprintf(stderr, "MAX_DB_INSERT_DELETE_REQUEST[%d], MAX_DB_GET_REQUEST[%d], SLEEP_TIME[%d]\n",
                MAX_DB_INSERT_DELETE_REQUEST, MAX_DB_GET_REQUEST, SLEEP_TIME);
        pthread_create(&tid1, NULL, couchbaseConnectAndExecute, NULL);
        tids[i] = tid1;
        pthread_mutex_init(&iolock, NULL);

        usleep(1000000);
    }
    {
        pthread_t tid1;
        pthread_create(&tid1, NULL, couchbaseConnectAndExecutePing, NULL);
        pthread_mutex_init(&iolock, NULL);
        tids[MAX_THREAD_COUNT - 1] = tid1;
    }
    for (int i = 0; i <= MAX_THREAD_COUNT - 1; i++) {
        pthread_join(tids[i], NULL);
    }
    return 0;
}
