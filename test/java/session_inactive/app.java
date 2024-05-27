import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@WebServlet(urlPatterns = "/")
public class app extends HttpServlet
{
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        HttpSession s = request.getSession();

        if (s.isNew()) {
            String interval = request.getHeader("X-Interval");

            if (interval == null) {
                s.setMaxInactiveInterval(0);
            } else {
                s.setMaxInactiveInterval(Integer.parseInt(interval));
            }
        }

        response.addHeader("X-Session-Id", s.getId());
        response.addDateHeader("X-Session-Last-Access-Time", s.getLastAccessedTime());
        response.addIntHeader("X-Session-Interval", s.getMaxInactiveInterval());
    }
}
