
import java.io.IOException;
import java.io.PrintWriter;

import java.util.Map;

import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class app extends HttpServlet
{
    private String id;

    private class RequestWrapper extends HttpServletRequestWrapper
    {
        public RequestWrapper(HttpServletRequest r)
        {
            super(r);
        }
    }

    private class ResponseWrapper extends HttpServletResponseWrapper
    {
        public ResponseWrapper(HttpServletResponse r)
        {
            super(r);
        }
    }

    @Override
    public void init(ServletConfig sc)
        throws ServletException
    {
        id = sc.getInitParameter("id");
    }

    private RequestDispatcher getRequestDispatcher(HttpServletRequest request, String str)
    {
        String disp = request.getParameter("disp");

        if (disp != null && disp.equals("ctx")) {
            return request.getServletContext().getRequestDispatcher(str);
        }

        if (disp != null && disp.equals("name")) {
            return request.getServletContext().getNamedDispatcher(str);
        }

        if (disp == null || disp.equals("req")) {
            return request.getRequestDispatcher(str);
        }

        return null;
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        String dtype = "" + request.getDispatcherType();

        response.addHeader("X-" + dtype + "-Id", id);
        response.addHeader("X-" + dtype + "-Request-URI", "" + request.getRequestURI());
        response.addHeader("X-" + dtype + "-Servlet-Path", "" + request.getServletPath());
        response.addHeader("X-" + dtype + "-Path-Info", "" + request.getPathInfo());
        response.addHeader("X-" + dtype + "-Query-String", "" + request.getQueryString());
        response.addHeader("X-" + dtype + "-Dispatcher-Type", "" + request.getDispatcherType());

        response.setContentType("text/plain; charset=utf-8");

        PrintWriter out = response.getWriter();

        if (id.equals("inc")) {
            String uri = request.getParameter("uri");

            if (uri != null && request.getDispatcherType() != DispatcherType.INCLUDE) {
                response.addHeader("X-Include", "" + uri);

                out.println("Before include.");

                RequestDispatcher d = getRequestDispatcher(request, uri);

                if (d == null) {
                    out.println("Dispatcher is null");
                    return;
                }

                try {
                    d.include(new RequestWrapper(request), new ResponseWrapper(response));
                } catch(Exception e) {
                    response.addHeader("X-Exception", "" + e);
                    out.println("Exception: " + e);
                }

                response.addHeader("X-After-Include", "you-should-see-this");

                out.println("After include.");

                return;
            }
        }

        if (id.equals("data")) {
            out.println("app.doGet(): #" + this + ", " + id);
            out.println("RequestURI:  " + request.getRequestURI());
            out.println("ServletPath: " + request.getServletPath());
            out.println("PathInfo:    " + request.getPathInfo());
            out.println("DispType:    " + request.getDispatcherType());
            out.println("QueryString: " + request.getQueryString());

            Map<String, String[]> pmap = request.getParameterMap();

            for (Map.Entry<String,String[]> p : pmap.entrySet()) {
                out.println("- " + p.getKey() + "=" + String.join(",", p.getValue()));
            }

            out.println(RequestDispatcher.INCLUDE_REQUEST_URI + ":  " + request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI));
            out.println(RequestDispatcher.INCLUDE_CONTEXT_PATH + ": " + request.getAttribute(RequestDispatcher.INCLUDE_CONTEXT_PATH));
            out.println(RequestDispatcher.INCLUDE_SERVLET_PATH + ": " + request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH));
            out.println(RequestDispatcher.INCLUDE_PATH_INFO + ":    " + request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO));
            out.println(RequestDispatcher.INCLUDE_QUERY_STRING + ": " + request.getAttribute(RequestDispatcher.INCLUDE_QUERY_STRING));

            return;
        }

        response.sendError(404);
    }
}
