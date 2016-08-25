#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ts/ts.h"
#include "ts/remap.h"
#include "ts/ink_defs.h"

/**
 * Authors:王锋
　* Email:oxwangfeng@qq.com
 * company：京东
 *
 */

#define PLUGIN_NAME "cache_range_requests"
#define DEBUG_LOG(fmt, ...) TSDebug(PLUGIN_NAME, "[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) TSError("[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)
#define TS_NULL_MUTEX      NULL
#define STATE_BUFFER_DATA   0
#define STATE_OUTPUT_DATA   1


struct txndata {
  char *range_value;
  long int content_length;
  long int range_start;
  long int range_end;
  bool valid_range;
};

typedef struct
{
  int state;
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  char *range_value;
  long int range_start;
  long int range_end;
} TransfromData;

static void handle_read_request_header(TSCont, TSEvent, void *);
static void range_header_check(TSHttpTxn txnp);
static void handle_send_origin_request(TSCont, TSHttpTxn, struct txndata *);
static void handle_client_send_response(TSHttpTxn, struct txndata *);
static void handle_server_read_response(TSHttpTxn, struct txndata *);
static int remove_header(TSMBuffer, TSMLoc, const char *, int);
static bool set_header(TSMBuffer, TSMLoc, const char *, int, const char *, int);
static void transaction_handler(TSCont, TSEvent, void *);

static bool get_content_length(TSHttpTxn txnp, struct txndata *data);
static bool get_range_content(TSHttpTxn txnp, struct txndata *data);


static TransfromData *
transfrom_data_alloc()
{
  TransfromData *data;
  data = (TransfromData *) TSmalloc(sizeof(TransfromData));
  data->state = STATE_BUFFER_DATA;
  data->output_vio = NULL;
  data->output_buffer = NULL;
  data->output_reader = NULL;

  data->range_start = 0;
  data->range_end=0;
  data->range_value = NULL;

  return data;
}

static void
transfrom_data_destroy(TransfromData * data)
{
  if (data) {
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }
    TSfree(data);
  }
}

/**
 * Entry point when used as a global plugin.
 *
 */
static void
handle_read_request_header(TSCont txn_contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  range_header_check(txnp);

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}

/**
 * Reads the client request header and if this is a range request:
 *
 * 1. creates a new cache key url using the range request information.
 * 2. Saves the range request information and then removes the range
 *    header so that the response retrieved from the origin will
 *    be written to cache.
 * 3. Schedules TS_HTTP_SEND_REQUEST_HDR_HOOK, TS_HTTP_SEND_RESPONSE_HDR_HOOK,
 *    and TS_HTTP_TXN_CLOSE_HOOK for further processing.
 */
static void
range_header_check(TSHttpTxn txnp)
{
  int length;
  struct txndata *txn_state;
  TSMBuffer hdr_bufp;
  TSMLoc req_hdrs = NULL;
  TSMLoc loc      = NULL;

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &hdr_bufp, &req_hdrs)) {
    loc = TSMimeHdrFieldFind(hdr_bufp, req_hdrs, TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);
    if (TS_NULL_MLOC != loc) {
      const char *hdr_value = TSMimeHdrFieldValueStringGet(hdr_bufp, req_hdrs, loc, 0, &length);
      if (!hdr_value || length <= 0) {
        DEBUG_LOG("Not a range request.");
      } else {
        char cache_key_url[8192];
        TSCont txn_contp;
        int url_length;
        char *req_url = NULL;

        if (NULL == (txn_contp = TSContCreate((TSEventFunc)transaction_handler, NULL))) {
          ERROR_LOG("failed to create the transaction handler continuation.");
        } else {
          txn_state              = (struct txndata *)TSmalloc(sizeof(struct txndata));
          txn_state->range_value = TSstrndup(hdr_value, length);
          //DEBUG_LOG("length: %d, txn_state->range_value: %s", length, txn_state->range_value);
          txn_state->range_value[length] = '\0'; // workaround for bug in core
          txn_state->valid_range = true;

          if(get_range_content(txnp, txn_state) == false){
              txn_state->valid_range=false;
          }

          req_url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_length);
          snprintf(cache_key_url, 8192, "%s-%s", req_url, txn_state->range_value);
          DEBUG_LOG("Rewriting cache URL for %s to %s", req_url, cache_key_url);
          if (req_url != NULL) {
            TSfree(req_url);
          }

          // set the cache key.
          if (TS_SUCCESS != TSCacheUrlSet(txnp, cache_key_url, strlen(cache_key_url))) {
            DEBUG_LOG("failed to change the cache url to %s.", cache_key_url);
          }
          // remove the range request header.
          if (remove_header(hdr_bufp, req_hdrs, TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE) > 0) {
            DEBUG_LOG("Removed the Range: header from the request.");
          }

          TSContDataSet(txn_contp, txn_state);
          TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_REQUEST_HDR_HOOK, txn_contp);
          TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, txn_contp);
          TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);
          DEBUG_LOG("Added TS_HTTP_SEND_REQUEST_HDR_HOOK, TS_HTTP_SEND_RESPONSE_HDR_HOOK, and TS_HTTP_TXN_CLOSE_HOOK");
        }
      }
      TSHandleMLocRelease(hdr_bufp, req_hdrs, loc);
    } else {
      DEBUG_LOG("no range request header.");
    }
    TSHandleMLocRelease(hdr_bufp, req_hdrs, NULL);
  } else {
    DEBUG_LOG("failed to retrieve the server request");
  }
}

/**
 * Restores the range request header if the request must be
 * satisfied from the origin and schedules the TS_READ_RESPONSE_HDR_HOOK.
 */

static void
handle_send_origin_request(TSCont contp, TSHttpTxn txnp, struct txndata *txn_state)
{

  TSMBuffer hdr_bufp;
  TSMLoc req_hdrs = NULL;
  if (TS_SUCCESS == TSHttpTxnServerReqGet(txnp, &hdr_bufp, &req_hdrs) && txn_state->range_value != NULL) {
    if (set_header(hdr_bufp, req_hdrs, TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, txn_state->range_value,
                   strlen(txn_state->range_value))) {
      DEBUG_LOG("Added range header: %s", txn_state->range_value);
      TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    }
  }
  TSHandleMLocRelease(hdr_bufp, req_hdrs, NULL);
}


/**
 * Changes the response code back to a 206 Partial content before
 * replying to the client that requested a range.
 */
static void
handle_client_send_response(TSHttpTxn txnp, struct txndata *txn_state)
{
  bool partial_content_reason = false;
  char *p;
  int length;
  TSMBuffer response;
  TSMLoc resp_hdr;

  TSReturnCode result = TSHttpTxnClientRespGet(txnp, &response, &resp_hdr);
  if (TS_SUCCESS == result) {
    TSHttpStatus status = TSHttpHdrStatusGet(response, resp_hdr);

    // a cached result will have a TS_HTTP_OK with a 'Partial Content' reason
    if ((p = (char *)TSHttpHdrReasonGet(response, resp_hdr, &length)) != NULL) {
      if ((length == 15) && (0 == strncasecmp(p, "Partial Content", length))) {
        partial_content_reason = true;
      }else if ((length == 2) && (0 == strncasecmp(p, "OK", length))) {
        partial_content_reason = true;
      }else if  ((length == 10) && (0 == strncasecmp(p, "oxwangfeng", length))) {
        DEBUG_LOG("trunked, Set response header to TS_HTTP_STATUS_OK.");
        TSHttpHdrStatusSet(response, resp_hdr, TS_HTTP_STATUS_OK);
      	TSHttpHdrReasonSet(response, resp_hdr, TSHttpHdrReasonLookup(TS_HTTP_STATUS_OK),
              strlen(TSHttpHdrReasonLookup(TS_HTTP_STATUS_OK)));

        TSHandleMLocRelease(response, resp_hdr, NULL);   
      }
    }
    if (TS_HTTP_STATUS_OK == status && partial_content_reason) {
      TSHttpHdrStatusSet(response, resp_hdr, TS_HTTP_STATUS_PARTIAL_CONTENT);
      TSHttpHdrReasonSet(response, resp_hdr, TSHttpHdrReasonLookup(TS_HTTP_STATUS_PARTIAL_CONTENT),
              strlen(TSHttpHdrReasonLookup(TS_HTTP_STATUS_PARTIAL_CONTENT)));
      DEBUG_LOG("Set response header to TS_HTTP_STATUS_PARTIAL_CONTENT.");
    }
  }
  TSHandleMLocRelease(response, resp_hdr, NULL);
}

static bool
get_content_length(TSHttpTxn txnp, struct txndata *data)
{
   TSMBuffer resp_bufp;
    TSMLoc resp_loc;
    TSMLoc field_loc;
    const char *value;
    int val_length;
    if (TSHttpTxnServerRespGet(txnp, &resp_bufp, &resp_loc) != TS_SUCCESS) {
        ERROR_LOG("couldn't retrieve server response header");
        return false;
    }

    field_loc = TSMimeHdrFieldFind(resp_bufp, resp_loc, TS_MIME_FIELD_CONTENT_LENGTH, TS_MIME_LEN_CACHE_CONTROL);
    if (field_loc == TS_NULL_MLOC) {
      DEBUG_LOG("cannot find content_length, return failed");
      ASSERT_SUCCESS(TSHandleMLocRelease(resp_bufp, TS_NULL_MLOC, resp_loc));
      return false;
    }else{
        value = TSMimeHdrFieldValueStringGet(resp_bufp, resp_loc, field_loc, -1, &val_length);
        if (value) {
           data->content_length= atol(value);
        }
    }
    ASSERT_SUCCESS(TSHandleMLocRelease(resp_bufp, resp_loc, field_loc));
    ASSERT_SUCCESS(TSHandleMLocRelease(resp_bufp, TS_NULL_MLOC, resp_loc));
    return true;
}


static bool
get_range_content(TSHttpTxn txnp, struct txndata *txn_state)
{
      int len = strlen("bytes=");
      if(strncasecmp(txn_state->range_value, "bytes=", len) == 0){
          txn_state->range_start = 0;
          txn_state->range_end = 0;
          char *p= txn_state->range_value + len;

          while (*p == ' ') { p++; }

          if (*p < '0' || *p > '9') {
              return false;
          }
 
          while (*p >= '0' && *p <= '9') {
              txn_state->range_start = txn_state->range_start * 10 + *p++ - '0';
          }

          while (*p == ' ') { p++; }

          if (*p++ != '-') {
              return false;
          }

          while (*p == ' ') { p++; }

          //for Range:bytes="100-",the range end is null
          if (*p == '\0') {
              txn_state->range_end = -1;
              return true;
          }

          if (*p < '0' || *p > '9') {
              return false;
          }

          while (*p >= '0' && *p <= '9') {
              txn_state->range_end = txn_state->range_end * 10 + *p++ - '0';
          }
      }
      return true;
}

static int
handle_buffering(TSCont contp, TransfromData * data)
{
  TSVIO write_vio;
  int towrite;
  int avail;

  /* Get the write VIO for the write operation that was performed on
     ourself. This VIO contains the buffer that we are to read from
     as well as the continuation we are to call when the buffer is
     empty. */
  write_vio = TSVConnWriteVIOGet(contp);

  /* Create the output buffer and its associated reader */
  if (!data->output_buffer) {
    data->output_buffer = TSIOBufferCreate();
    TSAssert(data->output_buffer);
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    TSAssert(data->output_reader);
  }

  /* We also check to see if the write VIO's buffer is non-NULL. A
     NULL buffer indicates that the write operation has been
     shutdown and that the continuation does not want us to send any
     more WRITE_READY or WRITE_COMPLETE events. For this buffered
     transformation that means we're done buffering data. */

  if (!TSVIOBufferGet(write_vio)) {
    data->state = STATE_OUTPUT_DATA;
    return 0;
  }

  /* Determine how much data we have left to read. For this bnull
     transform plugin this is also the amount of data we have left
     to write to the output connection. */

  towrite = TSVIONTodoGet(write_vio);
  if (towrite > 0) {
    /* The amount of data left to read needs to be truncated by
       the amount of data actually in the read buffer. */

    avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
    if (towrite > avail) {
      towrite = avail;
    }

    if (towrite > 0) {
      /* Copy the data from the read buffer to the input buffer. */
      TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), data->range_end - data->range_start+1, data->range_start);

      /* Tell the read buffer that we have read the data and are no
         longer interested in it. */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

      /* Modify the write VIO to reflect how much data we've
         completed. */
      TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
    }
  }

  /* Now we check the write VIO to see if there is data left to read. */
  if (TSVIONTodoGet(write_vio) > 0) {
    if (towrite > 0) {
      /* Call back the write VIO continuation to let it know that we
         are ready for more data. */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
    }
  } else {
    data->state = STATE_OUTPUT_DATA;

    /* Call back the write VIO continuation to let it know that we
       have completed the write operation. */
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  }

  return 1;

  /* If we are in this code path then something is seriously wrong. */
  TSError("[range-transform] Fatal error in plugin");
  TSReleaseAssert(!"[range-transform] Fatal error in plugin\n");
  return 0;
}

static int
handle_output(TSCont contp, TransfromData * data)
{
  /* Check to see if we need to initiate the output operation. */
  if (!data->output_vio) {
    TSVConn output_conn;

    /* Get the output connection where we'll write data to. */
    output_conn = TSTransformOutputVConnGet(contp);

    data->output_vio =
      TSVConnWrite(output_conn, contp, data->output_reader, TSIOBufferReaderAvail(data->output_reader));

    TSAssert(data->output_vio);
  }
  return 1;
}

static void
handle_transform(TSCont contp)
{
  TransfromData *data;
  int done;

  /* Get our data structure for this operation. The private data
     structure contains the output VIO and output buffer. If the
     private data structure pointer is NULL, then we'll create it
     and initialize its internals. */
  data = (TransfromData*)TSContDataGet(contp);
  if (!data) {
    data = transfrom_data_alloc();
    TSContDataSet(contp, data);
  }

  do {
    switch (data->state) {
    case STATE_BUFFER_DATA:
      done = handle_buffering(contp, data);
      break;
    case STATE_OUTPUT_DATA:
      done = handle_output(contp, data);
      break;
    default:
      done = 1;
      break;
    }
  } while (!done);
}

static int
range_transform(TSCont contp, TSEvent event, void *edata ATS_UNUSED)
{
  /* Check to see if the transformation has been closed by a
     call to TSVConnClose. */

  if (TSVConnClosedGet(contp)) {
    transfrom_data_destroy((TransfromData*)TSContDataGet(contp));
    TSContDestroy(contp);
  } else {
    switch (event) {
    case TS_EVENT_ERROR:{
        TSVIO write_vio;

        /* Get the write VIO for the write operation that was
           performed on ourself. This VIO contains the continuation of
           our parent transformation. */
        write_vio = TSVConnWriteVIOGet(contp);

        /* Call back the write VIO continuation to let it know that we
           have completed the write operation. */
        TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
        break;
      }

    case TS_EVENT_VCONN_WRITE_COMPLETE:
      /* When our output connection says that it has finished
         reading all the data we've written to it then we should
         shutdown the write portion of its connection to
         indicate that we don't want to hear about it anymore. */

      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;

    case TS_EVENT_VCONN_WRITE_READY:
    default:
      /* If we get a WRITE_READY event or any other type of event
         (sent, perhaps, because we were reenabled) then we'll attempt
         to transform more data. */
      handle_transform(contp);
      break;
    }
  }

  return 0;
}

static void
transform_add(TSHttpTxn txnp, struct txndata *txn_state)
{
  TSVConn connp;

  connp = TSTransformCreate(range_transform, txnp);
 
  TransfromData *data;
  data = transfrom_data_alloc();
  data->range_value= txn_state->range_value;
  data->range_start = txn_state->range_start;
  data->range_end = txn_state->range_end;

  TSContDataSet(connp, data);
  
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
  return;
}

/**
 * After receiving a range request response from the origin, change
 * the response code from a 206 Partial content to a 200 OK so that
 * the response will be written to cache.
 */
static void
handle_server_read_response(TSHttpTxn txnp, struct txndata *txn_state)
{
  TSMBuffer response;
  TSMLoc resp_hdr;
  TSHttpStatus status;

  if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &response, &resp_hdr)) {
    //add by wangfeng
    if(get_content_length(txnp, txn_state) == false){

      DEBUG_LOG("warnning. response is not include content_length, attempting to disable cache write.");

      TSHttpHdrReasonSet(response, resp_hdr, "oxwangfeng",10);

      TSHandleMLocRelease(response, resp_hdr, NULL);
      return;
    }

    status = TSHttpHdrStatusGet(response, resp_hdr);
    if (TS_HTTP_STATUS_PARTIAL_CONTENT == status) {

      TSHttpHdrStatusSet(response, resp_hdr, TS_HTTP_STATUS_OK);
      DEBUG_LOG("Set response header to TS_HTTP_STATUS_OK.");
    } else if (TS_HTTP_STATUS_OK == status) {
        char *temp = (char *) TSmalloc(255 * sizeof (char));
        if (NULL == temp) {
          DEBUG_LOG("TSmalloc failed");
          TSHandleMLocRelease(response, resp_hdr, NULL);
          return;
        }

        //for range end > content length
        if(txn_state->content_length != 0 && txn_state->range_end >= txn_state->content_length){
          txn_state->range_end = txn_state->content_length - 1;
        }

        //when range:bytes=xxx-,the end is null,so set range_end=content_length-1
        if(txn_state->content_length != 0 && (txn_state->range_end < 0)){
          txn_state->range_end = txn_state->content_length - 1;
        }
        /*
        1.whether range start or end is negative, valid_range is false,then all return 416;
        2.if invalid range request, valid_range is false, and return 416;
        3.if range start > end, then all return 416;
        4.if start > content_length, then all return 416;
        */
        if(txn_state->valid_range == false || txn_state->range_start > txn_state->range_end || txn_state->range_start>txn_state->content_length){
          //DEBUG_LOG("print log:%ld %ld %ld", txn_state->range_start, txn_state->range_end, txn_state->content_length);
          TSHttpHdrStatusSet(response, resp_hdr, TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
          TSHttpHdrReasonSet(response, resp_hdr, TSHttpHdrReasonLookup(TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE),
              strlen(TSHttpHdrReasonLookup(TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE)));

          int len = snprintf(temp, 255 * sizeof (char), "bytes */%ld", txn_state->content_length);
          if (set_header(response, resp_hdr, TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE, temp,len)) {
            DEBUG_LOG("add content range header: %s", temp);
          }

          TSfree(temp);
          TSHandleMLocRelease(response, resp_hdr, NULL);
          return;
        }
        else{
          int len = snprintf(temp, 255 * sizeof (char), "bytes %ld-%ld/%ld", txn_state->range_start,txn_state->range_end, txn_state->content_length);
          if (set_header(response, resp_hdr, TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE, temp, len)) {
            DEBUG_LOG("add content range header: %s", temp);
          } 
          TSfree(temp);
        }
        transform_add(txnp, txn_state);
    }
  }
  TSHandleMLocRelease(response, resp_hdr, NULL);
}

/**
 * Remove a header (fully) from an TSMLoc / TSMBuffer. Return the number
 * of fields (header values) we removed.
 *
 * From background_fetch.cc
 */

static int
remove_header(TSMBuffer bufp, TSMLoc hdr_loc, const char *header, int len)
{
  TSMLoc field = TSMimeHdrFieldFind(bufp, hdr_loc, header, len);
  int cnt      = 0;

  while (field) {
    TSMLoc tmp = TSMimeHdrFieldNextDup(bufp, hdr_loc, field);

    ++cnt;
    TSMimeHdrFieldDestroy(bufp, hdr_loc, field);
    TSHandleMLocRelease(bufp, hdr_loc, field);
    field = tmp;
  }

  return cnt;
}


/**
 * Set a header to a specific value. This will avoid going to through a
 * remove / add sequence in case of an existing header.
 * but clean.
 *
 * From background_fetch.cc
 */
static bool
set_header(TSMBuffer bufp, TSMLoc hdr_loc, const char *header, int len, const char *val, int val_len)
{
  if (!bufp || !hdr_loc || !header || len <= 0 || !val || val_len <= 0) {
    return false;
  }

  bool ret         = false;
  TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, header, len);

  if (!field_loc) { 
    // No existing header, so create one
    if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(bufp, hdr_loc, header, len, &field_loc)) {
      if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, val, val_len)) {
        TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
        ret = true;
      }
      TSHandleMLocRelease(bufp, hdr_loc, field_loc);
    }
  } else {
    TSMLoc tmp = NULL;
    bool first = true;

    while (field_loc) {
      if (first) {
        first = false;
        if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, val, val_len)) {
          ret = true;
        }
      } else {
        TSMimeHdrFieldDestroy(bufp, hdr_loc, field_loc);
      }
      tmp = TSMimeHdrFieldNextDup(bufp, hdr_loc, field_loc);
      TSHandleMLocRelease(bufp, hdr_loc, field_loc);
      field_loc = tmp;
    }
  }

  return ret;
}

/**
 * Global plugin initialization.
 */
void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  TSCont txnp_cont;

  info.plugin_name   = (char *)PLUGIN_NAME;
  info.vendor_name   = (char *)"wangfeng";
  info.support_email = (char *)"yfwangfeng@jd.com";

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    ERROR_LOG("Plugin registration failed.\n");
    ERROR_LOG("Unable to initialize plugin (disabled).");
    return;
  }

  if (NULL == (txnp_cont = TSContCreate((TSEventFunc)handle_read_request_header, NULL))) {
    ERROR_LOG("failed to create the transaction continuation handler.");
    return;
  } else {
    TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, txnp_cont);
  }
}

/**
 * Transaction event handler.
 */
static void
transaction_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp            = static_cast<TSHttpTxn>(edata);
  struct txndata *txn_state = (struct txndata *)TSContDataGet(contp);

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    handle_server_read_response(txnp, txn_state);
    break;
  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
      handle_send_origin_request(contp, txnp, txn_state);
      break;
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    handle_client_send_response(txnp, txn_state);
    break;
  case TS_EVENT_HTTP_TXN_CLOSE:
    if (txn_state != NULL && txn_state->range_value != NULL) {
      TSfree(txn_state->range_value);
    }
    if (txn_state != NULL) {
      TSfree(txn_state);
    }
    TSContDestroy(contp);
    break;
  default:
    TSAssert(!"Unexpected event");
    break;
  }
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}
