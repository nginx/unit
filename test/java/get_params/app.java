
import java.io.IOException;

import java.util.Enumeration;
import java.util.Map;

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
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        response.addHeader("X-Var-1", request.getParameter("var1"));
        response.addHeader("X-Var-2", "" + (request.getParameter("var2") != null));
        response.addHeader("X-Var-3", "" + (request.getParameter("var3") != null));
        response.addHeader("X-Var-4", request.getParameter("var4"));

        Enumeration<String> parameter_names = request.getParameterNames();

        String names = "";
        for (int i = 0; parameter_names.hasMoreElements(); i++) {
            names = names.concat(parameter_names.nextElement() + " ");
        }
        response.addHeader("X-Param-Names", names);

        String[] parameter_values = request.getParameterValues("var4");

        String values = "";
        for (int i = 0; i < parameter_values.length; i++) {
            values = values.concat(parameter_values[i] + " ");
        }
        response.addHeader("X-Param-Values", values);

        Map <String, String[]> parameter_map = request.getParameterMap();

        String map = "";
        for (Map.Entry <String, String[]> p : parameter_map.entrySet()) {
            map = map.concat(p.getKey() + "=" + String.join(",", p.getValue()) + " ");
        }
        response.addHeader("X-Param-Map", map);
    }
}
