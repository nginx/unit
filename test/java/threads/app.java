
import java.io.IOException;

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
        int delay = 0;

        String x_delay = request.getHeader("X-Delay");
        if (x_delay != null) {
            delay = Integer.parseInt(x_delay);
        }

        try {
            Thread.sleep(delay * 1000);
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }

        response.addHeader("X-Thread", "" + Thread.currentThread().getId());
    }
}
