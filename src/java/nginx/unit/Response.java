package nginx.unit;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import java.lang.IllegalArgumentException;
import java.lang.String;

import java.net.URI;
import java.net.URISyntaxException;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import java.text.SimpleDateFormat;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Vector;

import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.util.StringUtil;

public class Response implements HttpServletResponse {

    private long req_info_ptr;

    private static final String defaultCharacterEncoding = "iso-8859-1";
    private String characterEncoding = defaultCharacterEncoding;
    private String contentType = null;
    private String contentTypeHeader = null;
    private Locale locale = null;

    private static final Charset ISO_8859_1 = StandardCharsets.ISO_8859_1;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private static final String CONTENT_TYPE = "Content-Type";
    private static final byte[] CONTENT_LANGUAGE_BYTES = "Content-Language".getBytes(ISO_8859_1);
    private static final byte[] SET_COOKIE_BYTES = "Set-Cookie".getBytes(ISO_8859_1);
    private static final byte[] EXPIRES_BYTES = "Expires".getBytes(ISO_8859_1);

    /**
     * The only date format permitted when generating HTTP headers.
     */
    public static final String RFC1123_DATE =
            "EEE, dd MMM yyyy HH:mm:ss zzz";

    private static final SimpleDateFormat format =
            new SimpleDateFormat(RFC1123_DATE, Locale.US);

    private static final String ZERO_DATE_STRING = dateToString(0);
    private static final byte[] ZERO_DATE_BYTES = ZERO_DATE_STRING.getBytes(ISO_8859_1);

    /**
     * If this string is found within the comment of a cookie added with {@link #addCookie(Cookie)}, then the cookie
     * will be set as HTTP ONLY.
     */
    public final static String HTTP_ONLY_COMMENT = "__HTTP_ONLY__";

    private OutputStream outputStream = null;

    private PrintWriter writer = null;


    public Response(long ptr) {
        req_info_ptr = ptr;
    }

    /**
     * Format a set cookie value by RFC6265
     *
     * @param name the name
     * @param value the value
     * @param domain the domain
     * @param path the path
     * @param maxAge the maximum age
     * @param isSecure true if secure cookie
     * @param isHttpOnly true if for http only
     */
    public void addSetRFC6265Cookie(
            final String name,
            final String value,
            final String domain,
            final String path,
            final long maxAge,
            final boolean isSecure,
            final boolean isHttpOnly)
    {
        // Check arguments
        if (name == null || name.length() == 0) {
            throw new IllegalArgumentException("Bad cookie name");
        }

        // Name is checked for legality by servlet spec, but can also be passed directly so check again for quoting
        // Per RFC6265, Cookie.name follows RFC2616 Section 2.2 token rules
        //Syntax.requireValidRFC2616Token(name, "RFC6265 Cookie name");
        // Ensure that Per RFC6265, Cookie.value follows syntax rules
        //Syntax.requireValidRFC6265CookieValue(value);

        // Format value and params
        StringBuilder buf = new StringBuilder();
        buf.append(name).append('=').append(value == null ? "" : value);

        // Append path
        if (path != null && path.length() > 0) {
            buf.append(";Path=").append(path);
        }

        // Append domain
        if (domain != null && domain.length() > 0) {
            buf.append(";Domain=").append(domain);
        }

        // Handle max-age and/or expires
        if (maxAge >= 0) {
            // Always use expires
            // This is required as some browser (M$ this means you!) don't handle max-age even with v1 cookies
            buf.append(";Expires=");
            if (maxAge == 0)
                buf.append(ZERO_DATE_STRING);
            else
                buf.append(dateToString(System.currentTimeMillis() + 1000L * maxAge));

            buf.append(";Max-Age=");
            buf.append(maxAge);
        }

        // add the other fields
        if (isSecure)
            buf.append(";Secure");
        if (isHttpOnly)
            buf.append(";HttpOnly");

        // add the set cookie
        addHeader(req_info_ptr, SET_COOKIE_BYTES,
            buf.toString().getBytes(ISO_8859_1));

        // Expire responses with set-cookie headers so they do not get cached.
        setHeader(req_info_ptr, EXPIRES_BYTES, ZERO_DATE_BYTES);
    }

    @Override
    public void addCookie(Cookie cookie)
    {
        trace("addCookie: " + cookie.getName() + "=" + cookie.getValue());

        if (StringUtil.isBlank(cookie.getName())) {
            throw new IllegalArgumentException("Cookie.name cannot be blank/null");
        }

        if (isCommitted()) {
            return;
        }

        addCookie_(cookie);
    }

    private void addCookie_(Cookie cookie)
    {
        String comment = cookie.getComment();
        boolean httpOnly = false;

        if (comment != null && comment.contains(HTTP_ONLY_COMMENT)) {
            httpOnly = true;
        }

        addSetRFC6265Cookie(cookie.getName(),
            cookie.getValue(),
            cookie.getDomain(),
            cookie.getPath(),
            cookie.getMaxAge(),
            cookie.getSecure(),
            httpOnly || cookie.isHttpOnly());
    }

    public void addSessionIdCookie(Cookie cookie)
    {
        trace("addSessionIdCookie: " + cookie.getName() + "=" + cookie.getValue());

        if (isCommitted()) {
            /*
                9.3 The Include Method

                ... any call to HttpServletRequest.getSession() or
                HttpServletRequest.getSession(boolean) that would require
                adding a Cookie response header must throw an
                IllegalStateException if the response has been committed.
             */
            throw new IllegalStateException("Response already sent");
        }

        addCookie_(cookie);
    }

    @Override
    public void addDateHeader(String name, long date)
    {
        trace("addDateHeader: " + name + ": " + date);

        if (isCommitted()) {
            return;
        }

        String value = dateToString(date);

        addHeader(req_info_ptr, name.getBytes(ISO_8859_1),
            value.getBytes(ISO_8859_1));
    }

    private static String dateToString(long date)
    {
        Date dateValue = new Date(date);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        return format.format(dateValue);
    }


    @Override
    public void addHeader(String name, String value)
    {
        trace("addHeader: " + name + ": " + value);

        if (value == null) {
            return;
        }

        if (isCommitted()) {
            return;
        }

        if (CONTENT_TYPE.equalsIgnoreCase(name)) {
            setContentType(value);
            return;
        }

        addHeader(req_info_ptr, name.getBytes(ISO_8859_1),
            value.getBytes(ISO_8859_1));
    }

    private static native void addHeader(long req_info_ptr, byte[] name, byte[] value);


    @Override
    public void addIntHeader(String name, int value)
    {
        trace("addIntHeader: " + name + ": " + value);

        if (isCommitted()) {
            return;
        }

        addIntHeader(req_info_ptr, name.getBytes(ISO_8859_1), value);
    }

    private static native void addIntHeader(long req_info_ptr, byte[] name, int value);


    @Override
    public boolean containsHeader(String name)
    {
        trace("containsHeader: " + name);

        return containsHeader(req_info_ptr, name.getBytes(ISO_8859_1));
    }

    private static native boolean containsHeader(long req_info_ptr, byte[] name);


    @Override
    @Deprecated
    public String encodeRedirectUrl(String url)
    {
        return encodeRedirectURL(url);
    }

    @Override
    public String encodeRedirectURL(String url)
    {
        log("encodeRedirectURL: " + url);

        return url;
    }

    @Override
    @Deprecated
    public String encodeUrl(String url)
    {
        return encodeURL(url);
    }

    @Override
    public String encodeURL(String url)
    {
        log("encodeURL: " + url);

        return url;
    }

    @Override
    public String getHeader(String name)
    {
        trace("getHeader: " + name);

        return getHeader(req_info_ptr, name.getBytes(ISO_8859_1));
    }

    private static native String getHeader(long req_info_ptr, byte[] name);


    @Override
    public Collection<String> getHeaderNames()
    {
        trace("getHeaderNames");

        Enumeration<String> e = getHeaderNames(req_info_ptr);
        if (e == null) {
            return Collections.emptyList();
        }

        return Collections.list(e);
    }

    private static native Enumeration<String> getHeaderNames(long req_info_ptr);


    @Override
    public Collection<String> getHeaders(String name)
    {
        trace("getHeaders: " + name);

        Enumeration<String> e = getHeaders(req_info_ptr, name.getBytes(ISO_8859_1));
        if (e == null) {
            return Collections.emptyList();
        }

        return Collections.list(e);
    }

    private static native Enumeration<String> getHeaders(long req_info_ptr, byte[] name);


    @Override
    public int getStatus()
    {
        trace("getStatus");

        return getStatus(req_info_ptr);
    }

    private static native int getStatus(long req_info_ptr);


    @Override
    public void sendError(int sc) throws IOException
    {
        sendError(sc, null);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException
    {
        trace("sendError: " + sc + ", " + msg);

        if (isCommitted()) {
            throw new IllegalStateException("Response already sent");
        }

        setStatus(sc);

        Request request = getRequest(req_info_ptr);

        // If we are allowed to have a body, then produce the error page.
        if (sc != SC_NO_CONTENT && sc != SC_NOT_MODIFIED &&
            sc != SC_PARTIAL_CONTENT && sc >= SC_OK)
        {
            request.setAttribute_(RequestDispatcher.ERROR_STATUS_CODE, sc);
            request.setAttribute_(RequestDispatcher.ERROR_MESSAGE, msg);
            request.setAttribute_(RequestDispatcher.ERROR_REQUEST_URI,
                                  request.getRequestURI());
/*
            request.setAttribute_(RequestDispatcher.ERROR_SERVLET_NAME,
                                  request.getServletName());
*/
        }

/*
        Avoid commit and give chance for error handlers.

        if (!request.isAsyncStarted()) {
            commit();
        }
*/
    }

    private static native Request getRequest(long req_info_ptr);

    private void commit()
    {
        if (writer != null) {
            writer.close();

        } else if (outputStream != null) {
            outputStream.close();

        } else {
            commit(req_info_ptr);
        }
    }

    private static native void commit(long req_info_ptr);


    @Override
    public void sendRedirect(String location) throws IOException
    {
        trace("sendRedirect: " + location);

        if (isCommitted()) {
            return;
        }

        try {
            URI uri = new URI(location);

            if (!uri.isAbsolute()) {
                URI req_uri = new URI(getRequest(req_info_ptr).getRequestURL().toString());
                uri = req_uri.resolve(uri);

                location = uri.toString();
            }
        } catch (URISyntaxException e) {
            log("sendRedirect: failed to send redirect: " + e);
            return;
        }

        sendRedirect(req_info_ptr, location.getBytes(ISO_8859_1));
    }

    private static native void sendRedirect(long req_info_ptr, byte[] location);


    @Override
    public void setDateHeader(String name, long date)
    {
        trace("setDateHeader: " + name + ": " + date);

        if (isCommitted()) {
            return;
        }

        String value = dateToString(date);

        setHeader(req_info_ptr, name.getBytes(ISO_8859_1),
            value.getBytes(ISO_8859_1));
    }


    @Override
    public void setHeader(String name, String value)
    {
        trace("setHeader: " + name + ": " + value);

        if (isCommitted()) {
            return;
        }

        if (CONTENT_TYPE.equalsIgnoreCase(name)) {
            setContentType(value);
            return;
        }

        /*
         * When value is null container behaviour is undefined.
         * - Tomcat ignores setHeader call;
         * - Jetty & Resin acts as removeHeader;
         */
        if (value == null) {
            removeHeader(req_info_ptr, name.getBytes(ISO_8859_1));
            return;
        }

        setHeader(req_info_ptr, name.getBytes(ISO_8859_1),
            value.getBytes(ISO_8859_1));
    }

    private static native void setHeader(long req_info_ptr, byte[] name, byte[] value);

    private static native void removeHeader(long req_info_ptr, byte[] name);

    @Override
    public void setIntHeader(String name, int value)
    {
        trace("setIntHeader: " + name + ": " + value);

        if (isCommitted()) {
            return;
        }

        setIntHeader(req_info_ptr, name.getBytes(ISO_8859_1), value);
    }

    private static native void setIntHeader(long req_info_ptr, byte[] name, int value);


    @Override
    public void setStatus(int sc)
    {
        trace("setStatus: " + sc);

        if (isCommitted()) {
            return;
        }

        setStatus(req_info_ptr, sc);
    }

    private static native void setStatus(long req_info_ptr, int sc);


    @Override
    @Deprecated
    public void setStatus(int sc, String sm)
    {
        trace("setStatus: " + sc + "; " + sm);

        if (isCommitted()) {
            return;
        }

        setStatus(req_info_ptr, sc);
    }


    @Override
    public void flushBuffer() throws IOException
    {
        trace("flushBuffer");

        if (writer != null) {
            writer.flush();
        }

        if (outputStream != null) {
            outputStream.flush();
        }
    }

    @Override
    public int getBufferSize()
    {
        trace("getBufferSize");

        return getBufferSize(req_info_ptr);
    }

    public static native int getBufferSize(long req_info_ptr);


    @Override
    public String getCharacterEncoding()
    {
        trace("getCharacterEncoding");

        return characterEncoding;
    }

    @Override
    public String getContentType()
    {
        /* In JIRA decorator get content type called after commit. */

        String res = contentTypeHeader;

        trace("getContentType: " + res);

        return res;
    }

    private static native String getContentType(long req_info_ptr);

    @Override
    public Locale getLocale()
    {
        trace("getLocale");

        if (locale == null) {
            return Locale.getDefault();
        }

        return locale;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException
    {
        trace("getOutputStream");

        if (writer != null) {
            throw new IllegalStateException("Writer already created");
        }

        if (outputStream == null) {
            outputStream = new OutputStream(req_info_ptr);
        }

        return outputStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException
    {
        trace("getWriter ( characterEncoding = '" + characterEncoding + "' )");

        if (outputStream != null) {
            throw new IllegalStateException("OutputStream already created");
        }

        if (writer == null) {
            ServletOutputStream stream = new OutputStream(req_info_ptr);

            writer = new PrintWriter(
                new OutputStreamWriter(stream, Charset.forName(characterEncoding)),
                false);
        }

        return writer;
    }

    @Override
    public boolean isCommitted()
    {
        trace("isCommitted");

        return isCommitted(req_info_ptr);
    }

    public static native boolean isCommitted(long req_info_ptr);

    @Override
    public void reset()
    {
        trace("reset");

        if (isCommitted()) {
            return;
        }

        reset(req_info_ptr);

        writer = null;
        outputStream = null;
    }

    public static native void reset(long req_info_ptr);

    @Override
    public void resetBuffer()
    {
        trace("resetBuffer");

        resetBuffer(req_info_ptr);

        writer = null;
        outputStream = null;
    }

    public static native void resetBuffer(long req_info_ptr);

    @Override
    public void setBufferSize(int size)
    {
        trace("setBufferSize: " + size);

        setBufferSize(req_info_ptr, size);
    }

    public static native void setBufferSize(long req_info_ptr, int size);

    @Override
    public void setCharacterEncoding(String charset)
    {
        trace("setCharacterEncoding " + charset);

        if (isCommitted()) {
            return;
        }

        if (charset == null) {
            if (writer != null
                && !characterEncoding.equalsIgnoreCase(defaultCharacterEncoding))
            {
                /* TODO throw */
                return;
            }

            characterEncoding = defaultCharacterEncoding;
        } else {
            if (writer != null
                && !characterEncoding.equalsIgnoreCase(charset))
            {
                /* TODO throw */
                return;
            }

            characterEncoding = charset;
        }

        if (contentType != null) {
            String type = contentType + ";charset=" + characterEncoding;

            contentTypeHeader = type;

            setContentType(req_info_ptr, type.getBytes(ISO_8859_1));
        }
    }


    @Override
    public void setContentLength(int len)
    {
        trace("setContentLength: " + len);

        if (isCommitted()) {
            return;
        }

        setContentLength(req_info_ptr, len);
    }

    @Override
    public void setContentLengthLong(long len)
    {
        trace("setContentLengthLong: " + len);

        if (isCommitted()) {
            return;
        }

        setContentLength(req_info_ptr, len);
    }

    private static native void setContentLength(long req_info_ptr, long len);


    @Override
    public void setContentType(String type)
    {
        trace("setContentType: " + type);

        if (isCommitted()) {
            return;
        }

        if (type == null) {
            removeContentType(req_info_ptr);
            contentType = null;
            contentTypeHeader = null;
            return;
        }

        String charset = MimeTypes.getCharsetFromContentType(type);
        String ctype = MimeTypes.getContentTypeWithoutCharset(type);

        if (writer != null
            && charset != null
            && !characterEncoding.equalsIgnoreCase(charset))
        {
            /* To late to change character encoding */
            charset = characterEncoding;
            type = ctype + ";charset=" + characterEncoding;
        }

        if (charset == null) {
            type = type + ";charset=" + characterEncoding;
        } else {
            characterEncoding = charset;
        }

        contentType = ctype;
        contentTypeHeader = type;

        setContentType(req_info_ptr, type.getBytes(ISO_8859_1));
    }

    private static native void setContentType(long req_info_ptr, byte[] type);

    private static native void removeContentType(long req_info_ptr);


    @Override
    public void setLocale(Locale loc)
    {
        trace("setLocale: " + loc);

        if (loc == null || isCommitted()) {
            return;
        }

        locale = loc;
        String lang = locale.toString().replace('_', '-');

        setHeader(req_info_ptr, CONTENT_LANGUAGE_BYTES, lang.getBytes(ISO_8859_1));
    }

    private void log(String msg)
    {
        msg = "Response." + msg;
        log(req_info_ptr, msg.getBytes(UTF_8));
    }

    public static native void log(long req_info_ptr, byte[] msg);


    private void trace(String msg)
    {
        msg = "Response." + msg;
        trace(req_info_ptr, msg.getBytes(UTF_8));
    }

    public static native void trace(long req_info_ptr, byte[] msg);
}
