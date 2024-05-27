
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class app extends HttpServlet
{
    private String id;

    @Override
    public void init(ServletConfig sc)
        throws ServletException
    {
        id = sc.getInitParameter("id");
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.addHeader("X-Id", id);
        response.addHeader("X-Request-URI", "" + request.getRequestURI());
        response.addHeader("X-Servlet-Path", "" + request.getServletPath());
        response.setHeader("X-Path-Info", "" + request.getPathInfo());

        response.setContentType("text/plain; charset=utf-8");

        PrintWriter out = response.getWriter();
        out.println("app.doGet(): #" + this + ", " + id);
        out.println("RequestURI:  " + request.getRequestURI());
        out.println("ServletPath: " + request.getServletPath());
        out.println("PathInfo:    " + request.getPathInfo());
    }
}
