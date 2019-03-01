
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/")
public class app extends HttpServlet
{
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        Enumeration<String> header_names = request.getHeaderNames();

        for (int i = 0; header_names.hasMoreElements(); i++) {
            response.addHeader("X-Reply-" + Integer.toString(i),
                header_names.nextElement());
        }
    }
}
