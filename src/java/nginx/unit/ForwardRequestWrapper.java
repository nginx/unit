package nginx.unit;

import java.util.List;
import java.util.Map;

import javax.servlet.DispatcherType;
import javax.servlet.MultipartConfigElement;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.eclipse.jetty.util.MultiMap;
import org.eclipse.jetty.util.UrlEncoded;

public class ForwardRequestWrapper implements DynamicPathRequest
{
    private final Request request_;

    private final boolean keep_attrs;

    private final String orig_filter_path;
    private final String orig_servlet_path;
    private final String orig_path_info;
    private final String orig_uri;
    private final String orig_context_path;
    private final String orig_query;

    private final MultipartConfigElement orig_multipart_config;

    private final DispatcherType orig_dtype;

    private MultiMap<String> orig_parameters;

    public ForwardRequestWrapper(ServletRequest request)
    {
        if (request instanceof Request) {
            request_ = (Request) request;
        } else {
            request_ = (Request) request.getAttribute(Request.BARE);
        }

        keep_attrs = request_.getAttribute(RequestDispatcher.FORWARD_REQUEST_URI) != null;

        orig_dtype = request_.getDispatcherType();

        orig_filter_path = request_.getFilterPath();
        orig_servlet_path = request_.getServletPath();
        orig_path_info = request_.getPathInfo();
        orig_uri = request_.getRequestURI();
        orig_context_path = request_.getContextPath();
        orig_query = request_.getQueryString();

        orig_multipart_config = request_.getMultipartConfig();
    }

    @Override
    public void setDispatcherType(DispatcherType type)
    {
        request_.setDispatcherType(type);

        /*
            9.4.2 Forwarded Request Parameters
            ...
            Note that these attributes must always reflect the information in
            the original request even under the situation that multiple
            forwards and subsequent includes are called.
         */

        if (keep_attrs) {
            return;
        }

        /*
            9.4.2 Forwarded Request Parameters
            ...
            The values of these attributes must be equal to the return values
            of the HttpServletRequest methods getRequestURI, getContextPath,
            getServletPath, getPathInfo, getQueryString respectively, invoked
            on the request object passed to the first servlet object in the
            call chain that received the request from the client.
         */

        request_.setAttribute_(RequestDispatcher.FORWARD_SERVLET_PATH, orig_servlet_path);
        request_.setAttribute_(RequestDispatcher.FORWARD_PATH_INFO, orig_path_info);
        request_.setAttribute_(RequestDispatcher.FORWARD_REQUEST_URI, orig_uri);
        request_.setAttribute_(RequestDispatcher.FORWARD_CONTEXT_PATH, orig_context_path);
        request_.setAttribute_(RequestDispatcher.FORWARD_QUERY_STRING, orig_query);
    }

    @Override
    public void setServletPath(String servlet_path, String path_info)
    {
        request_.setServletPath(servlet_path, path_info);
    }

    @Override
    public void setServletPath(String filter_path, String servlet_path, String path_info)
    {
        request_.setServletPath(filter_path, servlet_path, path_info);
    }

    @Override
    public void setRequestURI(String uri)
    {
        request_.setRequestURI(uri);
    }

    @Override
    public void setQueryString(String query)
    {
        if (query != null) {
            orig_parameters = request_.getParameters();

            MultiMap<String> parameters = new MultiMap<>();
            UrlEncoded.decodeUtf8To(query, parameters);

            for (Map.Entry<String, List<String>> e: orig_parameters.entrySet()) {
                parameters.addValues(e.getKey(), e.getValue());
            }

            request_.setParameters(parameters);

            request_.setQueryString(query);
        }
    }

    @Override
    public String getFilterPath()
    {
        return request_.getFilterPath();
    }

    public void setMultipartConfig(MultipartConfigElement mce)
    {
        request_.setMultipartConfig(mce);
    }

    public void close()
    {
        request_.setDispatcherType(orig_dtype);

        request_.setRequestURI(orig_uri);
        request_.setServletPath(orig_filter_path, orig_servlet_path, orig_path_info);
        request_.setQueryString(orig_query);

        if (orig_parameters != null) {
            request_.setParameters(orig_parameters);
        }

        request_.setMultipartConfig(orig_multipart_config);

        if (keep_attrs) {
            return;
        }

        request_.setAttribute_(RequestDispatcher.FORWARD_SERVLET_PATH, null);
        request_.setAttribute_(RequestDispatcher.FORWARD_PATH_INFO, null);
        request_.setAttribute_(RequestDispatcher.FORWARD_REQUEST_URI, null);
        request_.setAttribute_(RequestDispatcher.FORWARD_CONTEXT_PATH, null);
        request_.setAttribute_(RequestDispatcher.FORWARD_QUERY_STRING, null);
    }
}
