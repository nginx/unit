
import java.io.*;

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
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        StringBuilder buffer = new StringBuilder();
        BufferedReader reader = request.getReader();
        String line;

        while ((line = reader.readLine()) != null) {
            buffer.append(line);
        }

        String data = buffer.toString();

        String dataLength = Integer.toString(data.length());
        response.setHeader("Content-Length", dataLength);

        response.setContentType("text/html");

        PrintWriter out = response.getWriter();
        out.print(data);
        out.flush();
    }
}
