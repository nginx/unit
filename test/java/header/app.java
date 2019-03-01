
import java.io.IOException;
import java.io.PrintWriter;

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
        response.setHeader("X-Set-Utf8-Value", "тест");
        response.setHeader("X-Set-Utf8-Name-Имя", "x");

        response.addHeader("X-Add-Utf8-Value", "тест");
        response.addHeader("X-Add-Utf8-Name-Имя", "y");

        response.addHeader("X-Add-Test", "v1");
        response.addHeader("X-Add-Test", null);

        response.setHeader("X-Set-Test1", "v1");
        response.setHeader("X-Set-Test1", null);

        response.setHeader("X-Set-Test2", "v1");
        response.setHeader("X-Set-Test2", "");
    }
}
