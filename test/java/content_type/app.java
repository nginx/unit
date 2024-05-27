
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
        if (request.getServletPath().equals("/1")) {
            response.setContentType("text/plain;charset=utf-8");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/2")) {
            response.setContentType("text/plain");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/3")) {
            response.setContentType("text/plain;charset=utf-8");
            response.setCharacterEncoding("windows-1251");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/4")) {
            response.setCharacterEncoding("windows-1251");
            response.setContentType("text/plain");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/5")) {
            response.setContentType("text/plain;charset=utf-8");
            response.setCharacterEncoding(null);
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/6")) {
            response.setContentType("text/plain;charset=utf-8");
            response.setContentType(null);
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/7")) {
            response.setContentType("text/plain;charset=utf-8");

            PrintWriter out = response.getWriter();

            response.setCharacterEncoding("windows-1251");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        if (request.getServletPath().equals("/8")) {
            response.setContentType("text/plain;charset=utf-8");

            PrintWriter out = response.getWriter();

            response.setContentType("text/html;charset=windows-1251");
            response.setHeader("X-Character-Encoding", response.getCharacterEncoding());
            response.setHeader("X-Content-Type", response.getContentType());
            return;
        }

        response.sendError(404);
    }
}
