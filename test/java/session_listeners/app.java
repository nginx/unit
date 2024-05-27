
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionIdListener;
import javax.servlet.http.HttpSessionListener;

@WebServlet(urlPatterns = "/")
public class app extends HttpServlet implements
    HttpSessionListener,
    HttpSessionIdListener,
    HttpSessionAttributeListener
{
    private static String session_created = "";
    private static String session_destroyed = "";
    private static String session_id_changed = "";
    private static String attribute_added = "";
    private static String attribute_removed = "";
    private static String attribute_replaced = "";

    @Override
    public void sessionCreated(HttpSessionEvent se)
    {
        session_created += se.getSession().getId();
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se)
    {
        session_destroyed += se.getSession().getId();
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldId)
    {
        session_id_changed += " " + oldId + "->" + event.getSession().getId();
    }

    @Override
    public void attributeAdded(HttpSessionBindingEvent event)
    {
        attribute_added += event.getName() + "=" + event.getValue();
    }

    @Override
    public void attributeRemoved(HttpSessionBindingEvent event)
    {
        attribute_removed += event.getName() + "=" + event.getValue();
    }

    @Override
    public void attributeReplaced(HttpSessionBindingEvent event)
    {
        attribute_replaced += event.getName() + "=" + event.getValue();
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        HttpSession s = request.getSession();
        s.setAttribute("var1", request.getParameter("var1"));

        response.addHeader("X-Session-Id", s.getId());
        response.addHeader("X-Session-Created", session_created);
        response.addHeader("X-Session-Destroyed", session_destroyed);
        response.addHeader("X-Attr-Added", attribute_added);
        response.addHeader("X-Attr-Removed", attribute_removed);
        response.addHeader("X-Attr-Replaced", attribute_replaced);
    }
}
