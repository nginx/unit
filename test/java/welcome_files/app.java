
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.annotation.WebFilter;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class app extends HttpServlet
{
    @WebFilter(urlPatterns = "*.jsp")
    public static class jsp_filter implements Filter
    {
        @Override
        public void init(FilterConfig filterConfig) { }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
        {
            ((HttpServletResponse) response).addHeader("X-JSP-Filter", "1");

            chain.doFilter(request, response);
        }

        @Override
        public void destroy() { }
    }

    @WebFilter(urlPatterns = "*.txt")
    public static class txt_filter implements Filter
    {
        @Override
        public void init(FilterConfig filterConfig) { }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
        {
            ((HttpServletResponse) response).addHeader("X-TXT-Filter", "1");

            chain.doFilter(request, response);
        }

        @Override
        public void destroy() { }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.addHeader("X-App-Servlet", "1");
        response.setContentType("text/plain; charset=utf-8");

        PrintWriter out = response.getWriter();
        out.println("App Servlet");
    }
}
