package nginx.unit;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.lang.IllegalArgumentException;
import java.lang.IllegalStateException;
import java.lang.Object;
import java.lang.String;
import java.lang.StringBuffer;

import java.net.URI;
import java.net.URISyntaxException;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import java.security.Principal;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.MultipartConfigElement;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestAttributeEvent;
import javax.servlet.ServletRequestAttributeListener;
import javax.servlet.ServletResponse;
import javax.servlet.SessionTrackingMode;
import javax.servlet.SessionCookieConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

import org.eclipse.jetty.util.IO;
import org.eclipse.jetty.util.MultiMap;
import org.eclipse.jetty.util.UrlEncoded;
import org.eclipse.jetty.util.StringUtil;

import org.eclipse.jetty.server.CookieCutter;
import org.eclipse.jetty.http.MultiPartFormInputStream;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.MimeTypes;

import nginx.unit.websocket.WsSession;
import nginx.unit.websocket.WsIOException;

public class Request implements HttpServletRequest, DynamicPathRequest
{
    private final Context context;
    private final long req_info_ptr;
    private final long req_ptr;

    protected String authType = null;

    protected boolean cookiesParsed = false;

    protected CookieCutter cookies = null;

    private final Map<String, Object> attributes = new HashMap<>();

    private MultiMap<String> parameters = null;

    private final String context_path;
    private String filter_path = null;
    private String servlet_path = null;
    private String path_info = null;
    private String request_uri = null;
    private String query_string = null;
    private boolean query_string_valid = false;

    private DispatcherType dispatcher_type = DispatcherType.REQUEST;

    private String characterEncoding = null;

    /**
     * The only date format permitted when generating HTTP headers.
     */
    public static final String RFC1123_DATE =
            "EEE, dd MMM yyyy HH:mm:ss zzz";

    private static final SimpleDateFormat formats[] = {
        new SimpleDateFormat(RFC1123_DATE, Locale.US),
        new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US),
        new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US)
    };

    private InputStream inputStream = null;
    private BufferedReader reader = null;

    private boolean request_session_id_parsed = false;
    private String request_session_id = null;
    private boolean request_session_id_from_cookie = false;
    private boolean request_session_id_from_url = false;
    private Session session = null;

    private WsSession wsSession = null;
    private boolean skip_close_ws = false;

    private final ServletRequestAttributeListener attr_listener;

    public static final String BARE = "nginx.unit.request.bare";

    private MultiPartFormInputStream multi_parts;
    private MultipartConfigElement multipart_config;

    public Request(Context ctx, long req_info, long req) {
        context = ctx;
        req_info_ptr = req_info;
        req_ptr = req;

        attr_listener = context.getRequestAttributeListener();
        context_path = context.getContextPath();
    }

    @Override
    public boolean authenticate(HttpServletResponse response)
        throws IOException, ServletException
    {
        log("authenticate");

        if (response.isCommitted()) {
            throw new IllegalStateException();
        }

        return false;
    }

    @Override
    public String getAuthType()
    {
        log("getAuthType");

        return authType;
    }

    @Override
    public String getContextPath()
    {
        trace("getContextPath: " + context_path);

        return context_path;
    }

    @Override
    public Cookie[] getCookies()
    {
        trace("getCookies");

        if (!cookiesParsed) {
            parseCookies();
        }

        //Javadoc for Request.getCookies() stipulates null for no cookies
        if (cookies == null || cookies.getCookies().length == 0) {
            return null;
        }

        return cookies.getCookies();
    }

    protected void parseCookies()
    {
        cookiesParsed = true;

        cookies = new CookieCutter();

        Enumeration<String> cookie_headers = getHeaders("Cookie");

        while (cookie_headers.hasMoreElements()) {
            cookies.addCookieField(cookie_headers.nextElement());
        }
    }

    @Override
    public long getDateHeader(String name)
    {
        trace("getDateHeader: " + name);

        String value = getHeader(name);
        if (value == null) {
            return -1L;
        }

        long res = parseDate(value);
        if (res == -1L) {
            throw new IllegalArgumentException(value);
        }

        return res;
    }

    protected long parseDate(String value)
    {
        Date date = null;
        for (int i = 0; (date == null) && (i < formats.length); i++) {
            try {
                date = formats[i].parse(value);
            } catch (ParseException e) {
                // Ignore
            }
        }
        if (date == null) {
            return -1L;
        }
        return date.getTime();
    }

    @Override
    public String getHeader(String name)
    {
        String res = getHeader(req_ptr, name, name.length());

        trace("getHeader: " + name + " = '" + res + "'");

        return res;
    }

    private static native String getHeader(long req_ptr, String name, int name_len);


    @Override
    public Enumeration<String> getHeaderNames()
    {
        trace("getHeaderNames");

        return getHeaderNames(req_ptr);
    }

    private static native Enumeration<String> getHeaderNames(long req_ptr);


    @Override
    public Enumeration<String> getHeaders(String name)
    {
        trace("getHeaders: " + name);

        return getHeaders(req_ptr, name, name.length());
    }

    private static native Enumeration<String> getHeaders(long req_ptr, String name, int name_len);


    @Override
    public int getIntHeader(String name)
    {
        trace("getIntHeader: " + name);

        return getIntHeader(req_ptr, name, name.length());
    }

    private static native int getIntHeader(long req_ptr, String name, int name_len);


    @Override
    public String getMethod()
    {
        trace("getMethod");

        return getMethod(req_ptr);
    }

    private static native String getMethod(long req_ptr);


    @Override
    public Part getPart(String name) throws IOException, ServletException
    {
        trace("getPart: " + name);

        if (multi_parts == null) {
            parseMultiParts();
        }

        return multi_parts.getPart(name);
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException
    {
        trace("getParts");

        if (multi_parts == null) {
            parseMultiParts();
        }

        return multi_parts.getParts();
    }

    private boolean checkMultiPart(String content_type)
    {
        return content_type != null
               && MimeTypes.Type.MULTIPART_FORM_DATA.is(HttpFields.valueParameters(content_type, null));
    }

    private void parseMultiParts() throws IOException, ServletException, IllegalStateException
    {
        String content_type = getContentType();

        if (!checkMultiPart(content_type)) {
            throw new ServletException("Content-Type != multipart/form-data");
        }

        if (multipart_config == null) {
            throw new IllegalStateException("No multipart config for servlet");
        }

        parseMultiParts(content_type);
    }

    private void parseMultiParts(String content_type) throws IOException
    {
        File tmpDir = (File) context.getAttribute(ServletContext.TEMPDIR);

        multi_parts = new MultiPartFormInputStream(getInputStream(),
            content_type, multipart_config, tmpDir);
    }

    public void setMultipartConfig(MultipartConfigElement mce)
    {
        multipart_config = mce;
    }

    public MultipartConfigElement getMultipartConfig()
    {
        return multipart_config;
    }

    @Override
    public String getPathInfo()
    {
        trace("getPathInfo: " + path_info);

        return path_info;
    }

    @Override
    public String getPathTranslated()
    {
        trace("getPathTranslated");

        if (path_info == null) {
            return null;
        }

        return context.getRealPath(path_info);
    }

    @Override
    public String getQueryString()
    {
        if (!query_string_valid) {
            query_string = getQueryString(req_ptr);
            query_string_valid = true;
        }

        trace("getQueryString: " + query_string);

        return query_string;
    }

    private static native String getQueryString(long req_ptr);

    @Override
    public void setQueryString(String query)
    {
        trace("setQueryString: " + query);

        query_string = query;
        query_string_valid = true;
    }

    @Override
    public String getRemoteUser()
    {
        log("getRemoteUser");

        /* TODO */
        return null;
    }

    @Override
    public String getRequestedSessionId()
    {
        trace("getRequestedSessionId");

        if (!request_session_id_parsed) {
            parseRequestSessionId();
        }

        return request_session_id;
    }

    private void parseRequestSessionId()
    {
        request_session_id_parsed = true;

        Cookie[] cookies = getCookies();
        if (cookies == null) {
            return;
        }

        if (context.getEffectiveSessionTrackingModes().contains(
            SessionTrackingMode.COOKIE))
        {
            final String name = context.getSessionCookieConfig().getName();

            for (Cookie c : cookies) {
                if (c.getName().equals(name)) {
                    request_session_id = c.getValue();
                    request_session_id_from_cookie = true;

                    return;
                }
            }
        }
    }

    @Override
    public String getRequestURI()
    {
        if (request_uri == null) {
            request_uri = getRequestURI(req_ptr);
        }

        trace("getRequestURI: " + request_uri);

        return request_uri;
    }

    private static native String getRequestURI(long req_ptr);


    @Override
    public void setRequestURI(String uri)
    {
        trace("setRequestURI: " + uri);

        request_uri = uri;
    }


    @Override
    public StringBuffer getRequestURL()
    {
        String host = getHeader("Host");
        String uri = getRequestURI();
        StringBuffer res = new StringBuffer("http://" + host + uri);

        trace("getRequestURL: " + res);

        return res;
    }

    @Override
    public String getServletPath()
    {
        trace("getServletPath: " + servlet_path);

        return servlet_path;
    }

    @Override
    public void setServletPath(String servlet_path, String path_info)
    {
        trace("setServletPath: " + servlet_path);

        this.filter_path = servlet_path;
        this.servlet_path = servlet_path;
        this.path_info = path_info;
    }

    @Override
    public void setServletPath(String filter_path, String servlet_path, String path_info)
    {
        trace("setServletPath: " + filter_path + ", " + servlet_path);

        this.filter_path = filter_path;
        this.servlet_path = servlet_path;
        this.path_info = path_info;
    }

    @Override
    public String getFilterPath()
    {
        return filter_path;
    }

    @Override
    public HttpSession getSession()
    {
        return getSession(true);
    }

    @Override
    public HttpSession getSession(boolean create)
    {
        if (session != null) {
            if (context.isSessionIdValid(session.getId())) {
                trace("getSession(" + create + "): " + session.getId());

                return session;
            }

            session = null;
        }

        if (!request_session_id_parsed) {
            parseRequestSessionId();

            session = context.getSession(request_session_id);
        }

        if (session != null || !create) {
            trace("getSession(" + create + "): " + (session != null ? session.getId() : "null"));

            return session;
        }

        session = context.createSession();

        if (context.getEffectiveSessionTrackingModes().contains(
            SessionTrackingMode.COOKIE))
        {
            setSessionIdCookie();
        }

        trace("getSession(" + create + "): " + session.getId());

        return session;
    }

    private void setSessionIdCookie()
    {
        SessionCookieConfig config = context.getSessionCookieConfig();

        Cookie c = new Cookie(config.getName(), session.getId());

        c.setComment(config.getComment());
        if (!StringUtil.isBlank(config.getDomain())) {
            c.setDomain(config.getDomain());
        }

        c.setHttpOnly(config.isHttpOnly());
        if (!StringUtil.isBlank(config.getPath())) {
            c.setPath(config.getPath());
        }

        c.setMaxAge(config.getMaxAge());

        getResponse(req_info_ptr).addSessionIdCookie(c);
    }

    @Override
    public Principal getUserPrincipal()
    {
        log("getUserPrincipal");

        return null;
    }

    @Override
    public boolean isRequestedSessionIdFromCookie()
    {
        trace("isRequestedSessionIdFromCookie");

        if (!request_session_id_parsed) {
            parseRequestSessionId();
        }

        return request_session_id_from_cookie;
    }

    @Override
    @Deprecated
    public boolean isRequestedSessionIdFromUrl()
    {
        trace("isRequestedSessionIdFromUrl");

        if (!request_session_id_parsed) {
            parseRequestSessionId();
        }

        return request_session_id_from_url;
    }

    @Override
    public boolean isRequestedSessionIdFromURL()
    {
        trace("isRequestedSessionIdFromURL");

        if (!request_session_id_parsed) {
            parseRequestSessionId();
        }

        return request_session_id_from_url;
    }

    @Override
    public boolean isRequestedSessionIdValid()
    {
        trace("isRequestedSessionIdValid");

        if (!request_session_id_parsed) {
            parseRequestSessionId();
        }

        return context.isSessionIdValid(request_session_id);
    }

    @Override
    public boolean isUserInRole(String role)
    {
        log("isUserInRole: " + role);

        return false;
    }

    @Override
    public void login(String username, String password) throws ServletException
    {
        log("login: " + username + "," + password);
    }

    @Override
    public void logout() throws ServletException
    {
        log("logout");
    }


    @Override
    public AsyncContext getAsyncContext()
    {
        log("getAsyncContext");

        return null;
    }

    @Override
    public Object getAttribute(String name)
    {
        if (BARE.equals(name)) {
            return this;
        }

        Object o = attributes.get(name);

        trace("getAttribute: " + name + " = " + o);

        return o;
    }

    @Override
    public Enumeration<String> getAttributeNames()
    {
        trace("getAttributeNames");

        Set<String> names = attributes.keySet();
        return Collections.enumeration(names);
    }

    @Override
    public String getCharacterEncoding()
    {
        trace("getCharacterEncoding");

        if (characterEncoding != null) {
            return characterEncoding;
        }

        getContentType();

        return characterEncoding;
    }

    @Override
    public int getContentLength()
    {
        trace("getContentLength");

        return (int) getContentLength(req_ptr);
    }

    private static native long getContentLength(long req_ptr);

    @Override
    public long getContentLengthLong()
    {
        trace("getContentLengthLong");

        return getContentLength(req_ptr);
    }

    @Override
    public String getContentType()
    {
        trace("getContentType");

        String content_type = getContentType(req_ptr);

        if (characterEncoding == null && content_type != null) {
            MimeTypes.Type mime = MimeTypes.CACHE.get(content_type);
            String charset = (mime == null || mime.getCharset() == null) ? MimeTypes.getCharsetFromContentType(content_type) : mime.getCharset().toString();
            if (charset != null) {
                characterEncoding = charset;
            }
        }

        return content_type;
    }

    private static native String getContentType(long req_ptr);


    @Override
    public DispatcherType getDispatcherType()
    {
        trace("getDispatcherType: " + dispatcher_type);

        return dispatcher_type;
    }

    @Override
    public void setDispatcherType(DispatcherType type)
    {
        trace("setDispatcherType: " + type);

        dispatcher_type = type;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException
    {
        trace("getInputStream");

        if (reader != null) {
            throw new IllegalStateException("getInputStream: getReader() already used");
        }

        if (inputStream == null) {
            inputStream = new InputStream(req_info_ptr);
        }

        return inputStream;
    }

    @Override
    public String getLocalAddr()
    {
        trace("getLocalAddr");

        return getLocalAddr(req_ptr);
    }

    private static native String getLocalAddr(long req_ptr);


    @Override
    public Locale getLocale()
    {
        log("getLocale");

        return Locale.getDefault();
    }

    @Override
    public Enumeration<Locale> getLocales()
    {
        log("getLocales");

        return Collections.emptyEnumeration();
    }

    @Override
    public String getLocalName()
    {
        trace("getLocalName");

        return getLocalName(req_ptr);
    }

    private static native String getLocalName(long req_ptr);


    @Override
    public int getLocalPort()
    {
        trace("getLocalPort");

        return getLocalPort(req_ptr);
    }

    private static native int getLocalPort(long req_ptr);


    public MultiMap<String> getParameters()
    {
        if (parameters != null) {
            return parameters;
        }

        parameters = new MultiMap<>();

        String query = getQueryString();

        if (query != null) {
            UrlEncoded.decodeUtf8To(query, parameters);
        }

        int content_length = getContentLength();

        if (content_length == 0 || !getMethod().equals("POST")) {
            return parameters;
        }

        String content_type = getContentType();

        try {
            if (content_type.startsWith("application/x-www-form-urlencoded")) {
                UrlEncoded.decodeUtf8To(new InputStream(req_info_ptr),
                    parameters, content_length, -1);
            } else if (checkMultiPart(content_type) && multipart_config != null) {
                if (multi_parts == null) {
                    parseMultiParts(content_type);
                }

                if (multi_parts != null) {
                    Collection<Part> parts = multi_parts.getParts();

                    String _charset_ = null;
                    Part charset_part = multi_parts.getPart("_charset_");
                    if (charset_part != null) {
                        try (java.io.InputStream is = charset_part.getInputStream())
                        {
                            ByteArrayOutputStream os = new ByteArrayOutputStream();
                            IO.copy(is, os);
                            _charset_ = new String(os.toByteArray(),StandardCharsets.UTF_8);
                        }
                    }

                    /*
                    Select Charset to use for this part. (NOTE: charset behavior is for the part value only and not the part header/field names)
                        1. Use the part specific charset as provided in that part's Content-Type header; else
                        2. Use the overall default charset. Determined by:
                            a. if part name _charset_ exists, use that part's value.
                            b. if the request.getCharacterEncoding() returns a value, use that.
                                (note, this can be either from the charset field on the request Content-Type
                                header, or from a manual call to request.setCharacterEncoding())
                            c. use utf-8.
                     */
                    Charset def_charset;
                    if (_charset_ != null) {
                        def_charset = Charset.forName(_charset_);
                    } else if (getCharacterEncoding() != null) {
                        def_charset = Charset.forName(getCharacterEncoding());
                    } else {
                        def_charset = StandardCharsets.UTF_8;
                    }

                    ByteArrayOutputStream os = null;
                    for (Part p : parts) {
                        if (p.getSubmittedFileName() != null) {
                            continue;
                        }

                        // Servlet Spec 3.0 pg 23, parts without filename must be put into params.
                        String charset = null;
                        if (p.getContentType() != null) {
                            charset = MimeTypes.getCharsetFromContentType(p.getContentType());
                        }

                        try (java.io.InputStream is = p.getInputStream())
                        {
                            if (os == null) {
                                os = new ByteArrayOutputStream();
                            }
                            IO.copy(is, os);

                            String content = new String(os.toByteArray(), charset == null ? def_charset : Charset.forName(charset));
                            parameters.add(p.getName(), content);
                        }
                        os.reset();
                    }
                }
            }
        } catch (IOException e) {
            log("Unhandled IOException: " + e);
        }

        return parameters;
    }

    public void setParameters(MultiMap<String> p)
    {
        parameters = p;
    }

    @Override
    public String getParameter(String name)
    {
        trace("getParameter: " + name);

        return getParameters().getValue(name, 0);
    }

    @Override
    public Map<String,String[]> getParameterMap()
    {
        trace("getParameterMap");

        return Collections.unmodifiableMap(getParameters().toStringArrayMap());
    }

    @Override
    public Enumeration<String> getParameterNames()
    {
        trace("getParameterNames");

        return Collections.enumeration(getParameters().keySet());
    }

    @Override
    public String[] getParameterValues(String name)
    {
        trace("getParameterValues: " + name);

        List<String> vals = getParameters().getValues(name);
        if (vals == null)
            return null;
        return vals.toArray(new String[vals.size()]);
    }

    @Override
    public String getProtocol()
    {
        trace("getProtocol");

        return getProtocol(req_ptr);
    }

    private static native String getProtocol(long req_ptr);

    @Override
    public BufferedReader getReader() throws IOException
    {
        trace("getReader");

        if (inputStream != null) {
            throw new IllegalStateException("getReader: getInputStream() already used");
        }

        if (reader == null) {
            reader = new BufferedReader(new InputStreamReader(new InputStream(req_info_ptr)));
        }

        return reader;
    }

    @Override
    @Deprecated
    public String getRealPath(String path)
    {
        trace("getRealPath: " + path);

        return context.getRealPath(path);
    }

    @Override
    public String getRemoteAddr()
    {
        String res = getRemoteAddr(req_ptr);

        trace("getRemoteAddr: " + res);

        return res;
    }

    private static native String getRemoteAddr(long req_ptr);


    @Override
    public String getRemoteHost()
    {
        String res = getRemoteHost(req_ptr);

        trace("getRemoteHost: " + res);

        return res;
    }

    private static native String getRemoteHost(long req_ptr);


    @Override
    public int getRemotePort()
    {
        int res = getRemotePort(req_ptr);

        trace("getRemotePort: " + res);

        return res;
    }

    private static native int getRemotePort(long req_ptr);


    @Override
    public RequestDispatcher getRequestDispatcher(String path)
    {
        trace("getRequestDispatcher: " + path);

        if (path.startsWith("/")) {
            return context.getRequestDispatcher(path);
        }

        try {
            URI uri = new URI(getRequestURI());
            uri = uri.resolve(path);

            return context.getRequestDispatcher(uri);
        } catch (URISyntaxException e) {
            log("getRequestDispatcher: failed to create dispatcher: " + e);
        }

        return null;
    }


    @Override
    public String getScheme()
    {
        trace("getScheme");

        return getScheme(req_ptr);
    }

    private static native String getScheme(long req_ptr);


    @Override
    public String getServerName()
    {
        String res = getServerName(req_ptr);

        trace("getServerName: " + res);

        return res;
    }

    private static native String getServerName(long req_ptr);


    @Override
    public int getServerPort()
    {
        int res = getServerPort(req_ptr);

        trace("getServerPort: " + res);

        return res;
    }

    private static native int getServerPort(long req_ptr);

    @Override
    public ServletContext getServletContext()
    {
        trace("getServletContext");

        return context;
    }

    @Override
    public boolean isAsyncStarted()
    {
        log("isAsyncStarted");

        return false;
    }

    @Override
    public boolean isAsyncSupported()
    {
        log("isAsyncSupported");

        return false;
    }

    @Override
    public boolean isSecure()
    {
        trace("isSecure");

        return isSecure(req_ptr);
    }

    private static native boolean isSecure(long req_ptr);

    @Override
    public void removeAttribute(String name)
    {
        trace("removeAttribute: " + name);

        Object prev = attributes.remove(name);

        if (attr_listener == null || prev == null) {
            return;
        }

        attr_listener.attributeRemoved(
            new ServletRequestAttributeEvent(context, this, name, prev));
    }

    @Override
    public void setAttribute(String name, Object o)
    {
        trace("setAttribute: " + name + ", " + o);

        Object prev;

        if (o != null) {
            prev = attributes.put(name, o);
        } else {
            prev = attributes.remove(name);
        }

        if (attr_listener == null) {
            return;
        }

        if (prev == null) {
            if (o == null) {
                return;
            }

            attr_listener.attributeAdded(new ServletRequestAttributeEvent(
                context, this, name, o));
        } else {
            if (o != null) {
                attr_listener.attributeReplaced(
                    new ServletRequestAttributeEvent(context, this, name, prev));
            } else {
                attr_listener.attributeRemoved(
                    new ServletRequestAttributeEvent(context, this, name, prev));
            }
        }
    }

    public void setAttribute_(String name, Object o)
    {
        trace("setAttribute_: " + name + ", " + o);

        if (o != null) {
            attributes.put(name, o);
        } else {
            attributes.remove(name);
        }
    }

    @Override
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException
    {
        trace("setCharacterEncoding: " + env);

        characterEncoding = env;
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException
    {
        log("startAsync");

        return null;
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException
    {
        log("startAsync(Req, resp)");

        return null;
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(
            Class<T> httpUpgradeHandlerClass) throws java.io.IOException, ServletException
    {
        trace("upgrade: " + httpUpgradeHandlerClass.getName());

        T handler;

        try {
            handler = httpUpgradeHandlerClass.getConstructor().newInstance();
        } catch (Exception e) {
            throw new ServletException(e);
        }

        upgrade(req_info_ptr);

        return handler;
    }

    private static native void upgrade(long req_info_ptr);

    public boolean isUpgrade()
    {
        return isUpgrade(req_info_ptr);
    }

    private static native boolean isUpgrade(long req_info_ptr);

    @Override
    public String changeSessionId()
    {
        trace("changeSessionId");

        getSession(false);

        if (session == null) {
            return null;
        }

        context.changeSessionId(session);

        if (context.getEffectiveSessionTrackingModes().contains(
            SessionTrackingMode.COOKIE))
        {
            setSessionIdCookie();
        }

        return session.getId();
    }

    private void log(String msg)
    {
        msg = "Request." + msg;
        log(req_info_ptr, msg, msg.length());
    }

    public static native void log(long req_info_ptr, String msg, int msg_len);


    private void trace(String msg)
    {
        msg = "Request." + msg;
        trace(req_info_ptr, msg, msg.length());
    }

    public static native void trace(long req_info_ptr, String msg, int msg_len);

    private static native Response getResponse(long req_info_ptr);


    public void setWsSession(WsSession s)
    {
        wsSession = s;
    }

    private void processWsFrame(ByteBuffer buf, byte opCode, boolean last)
        throws IOException
    {
        trace("processWsFrame: " + opCode + ", [" + buf.position() + ", " + buf.limit() + "]");
        try {
            wsSession.processFrame(buf, opCode, last);
        } catch (WsIOException e) {
            wsSession.onClose(e.getCloseReason());
        }
    }

    private void closeWsSession()
    {
        trace("closeWsSession");
        skip_close_ws = true;

        wsSession.onClose();
    }

    public void sendWsFrame(ByteBuffer payload, byte opCode, boolean last,
        long timeoutExpiry) throws IOException
    {
        trace("sendWsFrame: " + opCode + ", [" + payload.position() +
              ", " + payload.limit() + "]");

        if (payload.isDirect()) {
            sendWsFrame(req_info_ptr, payload, payload.position(),
                        payload.limit() - payload.position(), opCode, last);
        } else {
            sendWsFrame(req_info_ptr, payload.array(), payload.position(),
                        payload.limit() - payload.position(), opCode, last);
        }
    }

    private static native void sendWsFrame(long req_info_ptr,
        ByteBuffer buf, int pos, int len, byte opCode, boolean last);

    private static native void sendWsFrame(long req_info_ptr,
        byte[] arr, int pos, int len, byte opCode, boolean last);


    public void closeWs()
    {
        if (skip_close_ws) {
            return;
        }

        trace("closeWs");

        closeWs(req_info_ptr);
    }

    private static native void closeWs(long req_info_ptr);
}

