
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

@WebServlet(urlPatterns = "/")
public class app extends HttpServlet
{
    @WebFilter(urlPatterns = "")
    public static class filter implements Filter
    {
        @Override
        public void init(FilterConfig filterConfig)
        {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
        {
            response.getOutputStream().println("Extra Info");
            response.setCharacterEncoding("utf-8");

            ((HttpServletResponse) response).addHeader("X-Filter-Before", "1");

            chain.doFilter(request, response);

            ((HttpServletResponse) response).setHeader("X-Filter-After", "1");
        }

        @Override
        public void destroy()
        {
        }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.getOutputStream().println("This is servlet response");
        response.setHeader("X-Filter-After", "0");
    }
}
