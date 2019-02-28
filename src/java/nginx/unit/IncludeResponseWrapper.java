package nginx.unit;

import java.io.IOException;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class IncludeResponseWrapper extends HttpServletResponseWrapper {
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public IncludeResponseWrapper(ServletResponse response)
    {
        super((HttpServletResponse) response);
    }

    @Override
    public void addCookie(Cookie cookie)
    {
        trace("addCookie: " + cookie.getName() + "=" + cookie.getValue());
    }

    @Override
    public void addDateHeader(String name, long date)
    {
        trace("addDateHeader: " + name + ": " + date);
    }

    @Override
    public void addHeader(String name, String value)
    {
        trace("addHeader: " + name + ": " + value);
    }

    @Override
    public void addIntHeader(String name, int value)
    {
        trace("addIntHeader: " + name + ": " + value);
    }

    @Override
    public void sendRedirect(String location) throws IOException
    {
        trace("sendRedirect: " + location);
    }

    @Override
    public void setDateHeader(String name, long date)
    {
        trace("setDateHeader: " + name + ": " + date);
    }

    @Override
    public void setHeader(String name, String value)
    {
        trace("setHeader: " + name + ": " + value);
    }

    @Override
    public void setIntHeader(String name, int value)
    {
        trace("setIntHeader: " + name + ": " + value);
    }

    @Override
    public void setStatus(int sc)
    {
        trace("setStatus: " + sc);
    }

    @Override
    @Deprecated
    public void setStatus(int sc, String sm)
    {
        trace("setStatus: " + sc + "; " + sm);
    }

    @Override
    public void reset()
    {
        trace("reset");
    }

    @Override
    public void setCharacterEncoding(String charset)
    {
        trace("setCharacterEncoding " + charset);
    }

    @Override
    public void setContentLength(int len)
    {
        trace("setContentLength: " + len);
    }

    @Override
    public void setContentLengthLong(long len)
    {
        trace("setContentLengthLong: " + len);
    }

    @Override
    public void setContentType(String type)
    {
        trace("setContentType: " + type);
    }

    private void trace(String msg)
    {
        msg = "IncludeResponse." + msg;
        Response.trace(0, msg.getBytes(UTF_8));
    }
}
