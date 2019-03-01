
import java.io.IOException;
import java.io.PrintWriter;
import java.io.InputStream;

import java.util.Set;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet( urlPatterns = { "/", "/pt/*" } )
public class app extends HttpServlet
{
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.addHeader("X-Request-URI", "" + request.getRequestURI());
        response.addHeader("X-Servlet-Path", "" + request.getServletPath());
        response.addHeader("X-Path-Info", "" + request.getPathInfo());
        response.addHeader("X-Query-String", "" + request.getQueryString());
        response.addHeader("X-Path-Translated", "" + request.getPathTranslated());

        response.setContentType("text/plain; charset=utf-8");

        PrintWriter out = response.getWriter();
        ServletContext ctx = request.getServletContext();

        String path = request.getParameter("path");

        if (path != null) {
            response.addHeader("X-Real-Path", "" + ctx.getRealPath(path));
            response.addHeader("X-Resource", "" + ctx.getResource(path));

            Set<String> paths = ctx.getResourcePaths(path);

            response.addHeader("X-Resource-Paths", "" + paths);

            InputStream is = ctx.getResourceAsStream(path);

            response.addHeader("X-Resource-As-Stream", "" + is);

            if (is != null) {
                final byte[] buf = new byte[1024];
                int r = is.read(buf);

                out.println(new String(buf, 0, r, "utf-8"));
            }
        }
    }
}
