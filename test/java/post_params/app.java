
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(urlPatterns = "/")
public class app extends HttpServlet
{
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.addHeader("X-Var-1", request.getParameter("var1"));
        response.addHeader("X-Var-2", "" + (request.getParameter("var2") != null));
        response.addHeader("X-Var-3", "" + (request.getParameter("var3") != null));
    }
}
