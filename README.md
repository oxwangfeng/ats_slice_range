# ats_slice_range

1.Txndata贯穿到整个range session。当一个http range请求到来时，就会产生生成一个txndata实例；当range session结束时，这个txndata就会被销毁；

2. 源站不支持range（可以通过设置max_ranges指令为0来表示源站不支持range）：
当一个range请求访问不支持range的源站时，会返回整个内容，状态码是200（非206）；
这时，需要对源站内容进行进行修剪（只需要返回range需要的内容，而不是整个内容）；

3.本slice_range插件在官方提供的cache_range_requests插件基础上进行了修改。cache_range_requests插件主要是将range url进行rewrite，生成新的cache key（range范围不同cache key也不一样）；当发送到源站的url是带有range的；源站返回206状态码，由于206是ats是不缓存的，所以我们将206修改成200，这样就能cache了（按照以前设计的cache key保存）;

而本slice_range插件主要是添加了源站不支持range的情况以及处理了trunked的情况；

4.本插件和nginx slice插件配合使用，则更佳；
 
 
Slice_range的程序框架：
 
1. 当一个range请求到来时，根据请求头部range:bytes=start-end，提取出range的start和end；
1.1 start和end如果都存在的话，必须是数字，如果不是数字，则range不合法；range不合法，则可以发送给客户端416；
1.2 end可以是不存在的；
2. 设置新的url cache key； cache key url的设计规则为：比如http range请求是http://www.jd.com/vidio.swf  --H "range:bytes=100-200"，那么cache key url设计为http://www.jd.com/vidio.html-bytes=100-200，并且去掉range头部（去掉range头部主要是为了以后查找cache使用）；
3. 根据新的cache key url查找cache，第一次肯定是没有的；第二次才会有；
4. 如果查找不到cache，则将原始的url，再添加上range头部，发送到源站；
4.1 如果源站支持range，则源站返回206状态码，由于206是ats是不缓存的，所以我们将206修改成200，这样就能cache了（按照以前设计的cache key保存）；返回给client端的http请求是添加range头部的，并且返回状态码是206；
5.如果源站不支持range，则会返回给200状态码，内容是整个文档内容，所以我们需要修剪；
5.1.修剪过程：添加TS_HTTP_RESPONSE_TRANSFORM_HOOK，建立一个Transformation Vconnection，用于从一个buffer的部分内容copy到另外一个buffer中（实际上是指针的copy），当读取结束的时候，状态切换到VCONN_WRITE_COMPLETE，然后将数据写入到output connection;
6. trunked的处理：
6.1 只有第一次回源才返回trunked（下一次回源并且源站有修改时，也可能返回trunked），由于响应头中不包含content-length（trunked与content-length是互斥的），所以无法采用transformation的办法处理；
6.2 虽然是range请求，但是由于响应是trunked，并且响应状态码是200，所以缓存存储的是整个文档，而不是一个片段；所以每次返回给客户端必须是200状态码，不能是206，因为返回的是整个文档；
7.发送响应头阶段：如果cache中状态码是200，那么修改成206返回给client；是自己写的ats的插件，用于解决ats的range 分片存储，相比官方提供的range插件功能更多，也更全面。
