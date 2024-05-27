package nginx.unit;

import javax.servlet.DispatcherType;
import javax.servlet.MultipartConfigElement;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletRequest;

public class IncludeRequestWrapper implements DynamicPathRequest
{
    private final Request request_;

    private final Object orig_servlet_path_attr;
    private final Object orig_path_info_attr;
    private final Object orig_uri_attr;
    private final Object orig_context_path_attr;
    private final Object orig_query_string_attr;

    private final MultipartConfigElement orig_multipart_config;

    private final DispatcherType orig_dtype;

    private String filter_path_;

    public IncludeRequestWrapper(ServletRequest request)
    {
        if (request instanceof Request) {
            request_ = (Request) request;
        } else {
            request_ = (Request) request.getAttribute(Request.BARE);
        }

        orig_servlet_path_attr = request_.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
        orig_path_info_attr = request_.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
        orig_uri_attr = request_.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI);
        orig_context_path_attr = request_.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH);
        orig_query_string_attr = request_.getAttribute(RequestDispatcher.INCLUDE_QUERY_STRING);

        orig_multipart_config = request_.getMultipartConfig();

        orig_dtype = request_.getDispatcherType();

        request_.setAttribute_(RequestDispatcher.INCLUDE_CONTEXT_PATH, request_.getContextPath());
    }

    @Override
    public void setDispatcherType(DispatcherType type)
    {
        request_.setDispatcherType(type);
    }

    @Override
    public void setServletPath(String servlet_path, String path_info)
    {
        setServletPath(servlet_path, servlet_path, path_info);
    }

    @Override
    public void setServletPath(String filter_path, String servlet_path, String path_info)
    {
        request_.setAttribute_(RequestDispatcher.INCLUDE_SERVLET_PATH, servlet_path);
        request_.setAttribute_(RequestDispatcher.INCLUDE_PATH_INFO, path_info);
        filter_path_ = filter_path;
    }

    @Override
    public void setRequestURI(String uri)
    {
        request_.setAttribute_(RequestDispatcher.INCLUDE_REQUEST_URI, uri);
    }

    @Override
    public void setQueryString(String query)
    {
        request_.setAttribute_(RequestDispatcher.INCLUDE_QUERY_STRING, query);
    }

    @Override
    public String getFilterPath()
    {
        return filter_path_;
    }

    public void setMultipartConfig(MultipartConfigElement mce)
    {
        request_.setMultipartConfig(mce);
    }

    public void close()
    {
        request_.setDispatcherType(orig_dtype);

        request_.setAttribute_(RequestDispatcher.INCLUDE_SERVLET_PATH, orig_servlet_path_attr);
        request_.setAttribute_(RequestDispatcher.INCLUDE_PATH_INFO, orig_path_info_attr);
        request_.setAttribute_(RequestDispatcher.INCLUDE_REQUEST_URI, orig_uri_attr);
        request_.setAttribute_(RequestDispatcher.INCLUDE_CONTEXT_PATH, orig_context_path_attr);
        request_.setAttribute_(RequestDispatcher.INCLUDE_QUERY_STRING, orig_query_string_attr);

        request_.setMultipartConfig(orig_multipart_config);
    }
}
