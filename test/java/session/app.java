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
        String old_var1 = (String) s.getAttribute("var1");
        s.setAttribute("var1", request.getParameter("var1"));

        if (old_var1 == null) {
            response.addHeader("X-Var-1", "null");
        } else {
            response.addHeader("X-Var-1", old_var1);
        }

        response.addHeader("X-Session-Id", s.getId());
        response.addHeader("X-Session-New", "" + s.isNew());
    }
}
