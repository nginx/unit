
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.ServletRequestAttributeEvent;
import javax.servlet.ServletRequestAttributeListener;
import javax.servlet.annotation.WebServlet;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebListener
@WebServlet(urlPatterns = "/")
public class app extends HttpServlet implements
    ServletRequestListener,
    ServletRequestAttributeListener
{
    private static String request_initialized = "";
    private static String request_destroyed = "";
    private static String attribute_added = "";
    private static String attribute_removed = "";
    private static String attribute_replaced = "";

    @Override
    public void requestInitialized(ServletRequestEvent sre)
    {
        HttpServletRequest r = (HttpServletRequest) sre.getServletRequest();

        request_initialized = r.getRequestURI();
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre)
    {
        HttpServletRequest r = (HttpServletRequest) sre.getServletRequest();

        request_destroyed = r.getRequestURI();

        attribute_added = "";
        attribute_removed = "";
        attribute_replaced = "";
    }

    @Override
    public void attributeAdded(ServletRequestAttributeEvent event)
    {
        attribute_added += event.getName() + "=" + event.getValue() + ";";
    }

    @Override
    public void attributeRemoved(ServletRequestAttributeEvent event)
    {
        attribute_removed += event.getName() + "=" + event.getValue() + ";";
    }

    @Override
    public void attributeReplaced(ServletRequestAttributeEvent event)
    {
        attribute_replaced += event.getName() + "=" + event.getValue() + ";";
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        request.setAttribute("var", request.getParameter("var1"));
        request.setAttribute("var", request.getParameter("var2"));
        request.setAttribute("var", request.getParameter("var3"));

        response.addHeader("X-Request-Initialized", request_initialized);
        response.addHeader("X-Request-Destroyed", request_destroyed);
        response.addHeader("X-Attr-Added", attribute_added);
        response.addHeader("X-Attr-Removed", attribute_removed);
        response.addHeader("X-Attr-Replaced", attribute_replaced);
    }
}
