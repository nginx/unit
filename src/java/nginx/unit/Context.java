package nginx.unit;

import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ScanResult;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import java.lang.ClassLoader;
import java.lang.ClassNotFoundException;
import java.lang.IllegalArgumentException;
import java.lang.IllegalStateException;
import java.lang.reflect.Constructor;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;

import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.FilterRegistration.Dynamic;
import javax.servlet.FilterRegistration;
import javax.servlet.MultipartConfigElement;
import javax.servlet.Registration;
import javax.servlet.RequestDispatcher;
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextAttributeEvent;
import javax.servlet.ServletContextAttributeListener;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRegistration;
import javax.servlet.ServletResponse;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestAttributeEvent;
import javax.servlet.ServletRequestAttributeListener;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.ServletSecurityElement;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import javax.servlet.annotation.HandlesTypes;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebListener;
import javax.servlet.descriptor.JspConfigDescriptor;
import javax.servlet.descriptor.JspPropertyGroupDescriptor;
import javax.servlet.descriptor.TaglibDescriptor;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionIdListener;
import javax.servlet.http.HttpSessionListener;

import javax.websocket.server.ServerEndpoint;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import nginx.unit.websocket.WsSession;

import org.eclipse.jetty.http.MimeTypes;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import org.apache.jasper.servlet.JspServlet;
import org.apache.jasper.servlet.JasperInitializer;


public class Context implements ServletContext, InitParams
{
    public final static int SERVLET_MAJOR_VERSION = 3;
    public final static int SERVLET_MINOR_VERSION = 1;

    private String context_path_ = "";
    private String server_info_ = "unit";
    private String app_version_ = "";
    private MimeTypes mime_types_;
    private boolean metadata_complete_ = false;
    private boolean welcome_files_list_found_ = false;
    private boolean ctx_initialized_ = false;

    private ClassLoader loader_;
    private File webapp_;
    private File extracted_dir_;
    private File temp_dir_;

    private final Map<String, String> init_params_ = new HashMap<>();
    private final Map<String, Object> attributes_ = new HashMap<>();

    private final Map<String, URLPattern> parsed_patterns_ = new HashMap<>();

    private final List<FilterReg> filters_ = new ArrayList<>();
    private final Map<String, FilterReg> name2filter_ = new HashMap<>();
    private final List<FilterMap> filter_maps_ = new ArrayList<>();

    private final List<ServletReg> servlets_ = new ArrayList<>();
    private final Map<String, ServletReg> name2servlet_ = new HashMap<>();
    private final Map<String, ServletReg> pattern2servlet_ = new HashMap<>();
    private final Map<String, ServletReg> exact2servlet_ = new HashMap<>();
    private final List<PrefixPattern> prefix_patterns_ = new ArrayList<>();
    private final Map<String, ServletReg> suffix2servlet_ = new HashMap<>();
    private ServletReg default_servlet_;
    private ServletReg system_default_servlet_;

    private final List<String> welcome_files_ = new ArrayList<>();

    private final Map<String, String> exception2location_ = new HashMap<>();
    private final Map<Integer, String> error2location_ = new HashMap<>();

    public static final Class<?>[] LISTENER_TYPES = new Class[] {
        ServletContextListener.class,
        ServletContextAttributeListener.class,
        ServletRequestListener.class,
        ServletRequestAttributeListener.class,
        HttpSessionAttributeListener.class,
        HttpSessionIdListener.class,
        HttpSessionListener.class
    };

    private final List<String> pending_listener_classnames_ = new ArrayList<>();
    private final Set<String> listener_classnames_ = new HashSet<>();

    private final List<ServletContextListener> ctx_listeners_ = new ArrayList<>();
    private final List<ServletContextListener> destroy_listeners_ = new ArrayList<>();
    private final List<ServletContextAttributeListener> ctx_attr_listeners_ = new ArrayList<>();
    private final List<ServletRequestListener> req_init_listeners_ = new ArrayList<>();
    private final List<ServletRequestListener> req_destroy_listeners_ = new ArrayList<>();
    private final List<ServletRequestAttributeListener> req_attr_listeners_ = new ArrayList<>();

    private ServletRequestAttributeListener req_attr_proxy_ = null;

    private final List<HttpSessionAttributeListener> sess_attr_listeners_ = new ArrayList<>();
    private final List<HttpSessionIdListener> sess_id_listeners_ = new ArrayList<>();
    private final List<HttpSessionListener> sess_listeners_ = new ArrayList<>();

    private HttpSessionAttributeListener sess_attr_proxy_ = null;

    private final SessionCookieConfig session_cookie_config_ = new UnitSessionCookieConfig();
    private final Set<SessionTrackingMode> default_session_tracking_modes_ = new HashSet<>();
    private Set<SessionTrackingMode> session_tracking_modes_ = default_session_tracking_modes_;
    private int session_timeout_ = 60;

    private final Map<String, Session> sessions_ = new HashMap<>();

    private static final String WEB_INF = "WEB-INF/";
    private static final String WEB_INF_CLASSES = WEB_INF + "classes/";
    private static final String WEB_INF_LIB = WEB_INF + "lib/";

    private class PrefixPattern implements Comparable<PrefixPattern>
    {
        public final String pattern;
        public final ServletReg servlet;

        public PrefixPattern(String p, ServletReg s)
        {
            pattern = p;
            servlet = s;
        }

        public boolean match(String url)
        {
            return url.startsWith(pattern) && (
                url.length() == pattern.length()
                || url.charAt(pattern.length()) == '/');
        }

        @Override
        public int compareTo(PrefixPattern p)
        {
            return p.pattern.length() - pattern.length();
        }
    }

    private class StaticServlet extends HttpServlet
    {
        @Override
        public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException
        {
            doGet(request, response);
        }

        @Override
        public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException
        {
            String path = null;

            if (request.getDispatcherType() == DispatcherType.INCLUDE) {
                path = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
            }

            if (path == null) {
                path = request.getServletPath();
            }

            /*
                10.6 Web Application Archive File
                ...
                This directory [META-INF] must not be directly served as
                content by the container in response to a Web client's request,
                though its contents are visible to servlet code via the
                getResource and getResourceAsStream calls on the
                ServletContext. Also, any requests to access the resources in
                META-INF directory must be returned with a SC_NOT_FOUND(404)
                response.
             */
            if (request.getDispatcherType() == DispatcherType.REQUEST
                && (path.equals("/WEB-INF") || path.startsWith("/WEB-INF/")
                    || path.equals("/META-INF") || path.startsWith("/META-INF/")))
            {
                response.sendError(response.SC_NOT_FOUND);
                return;
            }

            if (path.startsWith("/")) {
                path = path.substring(1);
            }

            File f = new File(webapp_, path);
            if (!f.exists()) {
                if (request.getDispatcherType() == DispatcherType.INCLUDE) {
                    /*
                        9.3 The Include Method
                        ...
                        If the default servlet is the target of a
                        RequestDispatch.include() and the requested resource
                        does not exist, then the default servlet MUST throw
                        FileNotFoundException.
                     */

                    throw new FileNotFoundException();
                }

                response.sendError(response.SC_NOT_FOUND);
                return;
            }

            long ims = request.getDateHeader("If-Modified-Since");
            long lm = f.lastModified();

            if (lm < ims) {
                response.sendError(response.SC_NOT_MODIFIED);
                return;
            }

            response.setDateHeader("Last-Modified", f.lastModified());

            if (f.isDirectory()) {
                String url = request.getRequestURL().toString();
                if (!url.endsWith("/")) {
                    response.setHeader("Location", url + "/");
                    response.sendError(response.SC_FOUND);
                    return;
                }

                String[] ls = f.list();

                PrintWriter writer = response.getWriter();

                for (String n : ls) {
                    writer.println("<a href=\"" + n + "\">" + n + "</a><br>");
                }

                writer.close();

            } else {
                response.setContentLengthLong(f.length());
                response.setContentType(getMimeType(f.getName()));

                InputStream is = new FileInputStream(f);
                byte[] buffer = new byte[response.getBufferSize()];
                ServletOutputStream os = response.getOutputStream();
                while (true) {
                    int read = is.read(buffer);
                    if (read == -1) {
                        break;
                    }
                    os.write(buffer, 0, read);
                }

                os.close();
            }
        }
    }

    public static Context start(String webapp, URL[] classpaths)
        throws Exception
    {
        Context ctx = new Context();

        ctx.loadApp(webapp, classpaths);
        ctx.initialized();

        return ctx;
    }

    public Context()
    {
        default_session_tracking_modes_.add(SessionTrackingMode.COOKIE);

        context_path_ = System.getProperty("nginx.unit.context.path", "").trim();

        if (context_path_.endsWith("/")) {
            context_path_ = context_path_.substring(0, context_path_.length() - 1);
        }

        if (!context_path_.isEmpty() && !context_path_.startsWith("/")) {
            context_path_ = "/" + context_path_;
        }

        if (context_path_.isEmpty()) {
            session_cookie_config_.setPath("/");
        } else {
            session_cookie_config_.setPath(context_path_);
        }
    }

    public void loadApp(String webapp, URL[] classpaths)
        throws Exception
    {
        File root = new File(webapp);
        if (!root.exists()) {
            throw new FileNotFoundException(
                "Unable to determine code source archive from " + root);
        }

        ArrayList<URL> url_list = new ArrayList<>();

        for (URL u : classpaths) {
            url_list.add(u);
        }

        if (!root.isDirectory()) {
            root = extractWar(root);
            extracted_dir_ = root;
        }

        webapp_ = root;

        Path tmpDir = Files.createTempDirectory("webapp");
        temp_dir_ = tmpDir.toFile();
        setAttribute(ServletContext.TEMPDIR, temp_dir_);

        File web_inf_classes = new File(root, WEB_INF_CLASSES);
        if (web_inf_classes.exists() && web_inf_classes.isDirectory()) {
            url_list.add(new URL("file:" + root.getAbsolutePath() + "/" + WEB_INF_CLASSES));
        }

        File lib = new File(root, WEB_INF_LIB);
        File[] libs = lib.listFiles();

        if (libs != null) {
            for (File l : libs) {
                url_list.add(new URL("file:" + l.getAbsolutePath()));
            }
        }

        URL[] urls = new URL[url_list.size()];

        for (int i = 0; i < url_list.size(); i++) {
            urls[i] = url_list.get(i);
            trace("archives: " + urls[i]);
        }

        String custom_listener = System.getProperty("nginx.unit.context.listener", "").trim();
        if (!custom_listener.isEmpty()) {
            pending_listener_classnames_.add(custom_listener);
        }

        processWebXml(root);

        loader_ = new UnitClassLoader(urls,
            Context.class.getClassLoader().getParent());

        Class wsSession_class = WsSession.class;
        trace("wsSession.test: " + WsSession.wsSession_test());

        ClassLoader old = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(loader_);

        try {
            for (String listener_classname : pending_listener_classnames_) {
                addListener(listener_classname);
            }

            ClassGraph classgraph = new ClassGraph()
                //.verbose()
                .overrideClassLoaders(loader_)
                .ignoreParentClassLoaders()
                .enableClassInfo()
                .enableAnnotationInfo()
                //.enableSystemPackages()
                .acceptModules("javax.*")
                //.enableAllInfo()
                ;

            String verbose = System.getProperty("nginx.unit.context.classgraph.verbose", "").trim();

            if (verbose.equals("true")) {
                classgraph.verbose();
            }

            ScanResult scan_res = classgraph.scan();

            javax.websocket.server.ServerEndpointConfig.Configurator.setDefault(new nginx.unit.websocket.server.DefaultServerEndpointConfigurator());

            loadInitializer(new nginx.unit.websocket.server.WsSci(), scan_res);

            if (!metadata_complete_) {
                loadInitializers(scan_res);
            }

            if (!metadata_complete_) {
                scanClasses(scan_res);
            }

            /*
                8.1.6 Other annotations / conventions
                ...
                By default all applications will have index.htm(l) and index.jsp
                in the list of welcome-file-list. The descriptor may to be used
                to override these default settings.
             */
            if (!welcome_files_list_found_) {
                welcome_files_.add("index.htm");
                welcome_files_.add("index.html");
                welcome_files_.add("index.jsp");
            }

            ServletReg jsp_servlet = name2servlet_.get("jsp");
            if (jsp_servlet == null) {
                jsp_servlet = new ServletReg("jsp", JspServlet.class);
                jsp_servlet.system_jsp_servlet_ = true;
                servlets_.add(jsp_servlet);
                name2servlet_.put("jsp", jsp_servlet);
            }

            if (jsp_servlet.getClassName() == null) {
                jsp_servlet.setClass(JspServlet.class);
                jsp_servlet.system_jsp_servlet_ = true;
            }

            if (jsp_servlet.patterns_.isEmpty()) {
                parseURLPattern("*.jsp", jsp_servlet);
                parseURLPattern("*.jspx", jsp_servlet);
            }

            ServletReg def_servlet = name2servlet_.get("default");
            if (def_servlet == null) {
                def_servlet = new ServletReg("default", new StaticServlet());
                def_servlet.servlet_ = new StaticServlet();
                servlets_.add(def_servlet);
                name2servlet_.put("default", def_servlet);
            }

            if (def_servlet.getClassName() == null) {
                def_servlet.setClass(StaticServlet.class);
                def_servlet.servlet_ = new StaticServlet();
            }

            system_default_servlet_ = def_servlet;

            for (PrefixPattern p : prefix_patterns_) {
                /*
                    Optimization: add prefix patterns to exact2servlet_ map.
                    This should not affect matching result because full path
                    is the longest matched prefix.
                 */
                if (!exact2servlet_.containsKey(p.pattern)) {
                    trace("adding prefix pattern " + p.pattern + " to exact patterns map");
                    exact2servlet_.put(p.pattern, p.servlet);
                }
            }

            Collections.sort(prefix_patterns_);
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    private static class UnitClassLoader extends URLClassLoader
    {
        static {
            ClassLoader.registerAsParallelCapable();
        }

        private final static String[] system_prefix =
        {
            "java/",     // Java SE classes (per servlet spec v2.5 / SRV.9.7.2)
            "javax/",    // Java SE classes (per servlet spec v2.5 / SRV.9.7.2)
            "org/w3c/",  // needed by javax.xml
            "org/xml/",  // needed by javax.xml
        };

        private ClassLoader system_loader;

        public UnitClassLoader(URL[] urls, ClassLoader parent)
        {
            super(urls, parent);

            ClassLoader j = String.class.getClassLoader();
            if (j == null) {
                j = getSystemClassLoader();
                while (j.getParent() != null) {
                    j = j.getParent();
                }
            }
            system_loader = j;
        }

        private boolean isSystemPath(String path)
        {
            int i = Arrays.binarySearch(system_prefix, path);

            if (i >= 0) {
                return true;
            }

            i = -i - 1;

            if (i > 0) {
                return path.startsWith(system_prefix[i - 1]);
            }

            return false;
        }

        @Override
        public URL getResource(String name)
        {
            URL res;

            String s = "getResource: " + name;
            trace(0, s, s.length());

            /*
                This is a required for compatibility with Tomcat which
                stores all resources prefixed with '/' and application code
                may try to get resource with leading '/' (like Jira). Jetty
                also has such workaround in WebAppClassLoader.getResource().
             */
            if (name.startsWith("/")) {
                name = name.substring(1);
            }

            if (isSystemPath(name)) {
                return super.getResource(name);
            }

            res = system_loader.getResource(name);
            if (res != null) {
                return res;
            }

            res = findResource(name);
            if (res != null) {
                return res;
            }

            return super.getResource(name);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve)
            throws ClassNotFoundException
        {
            synchronized (this) {
                Class<?> res = findLoadedClass(name);
                if (res != null) {
                    return res;
                }

                try {
                    res = system_loader.loadClass(name);

                    if (resolve) {
                        resolveClass(res);
                    }

                    return res;
                } catch (ClassNotFoundException e) {
                }

                String path = name.replace('.', '/').concat(".class");

                if (isSystemPath(path)) {
                    return super.loadClass(name, resolve);
                }

                URL url = findResource(path);

                if (url != null) {
                    res = super.findClass(name);

                    if (resolve) {
                        resolveClass(res);
                    }

                    return res;
                }

                return super.loadClass(name, resolve);
            }

        }
    }

    private File extractWar(File war) throws IOException
    {
        Path tmpDir = Files.createTempDirectory("webapp");

        JarFile jf = new JarFile(war);

        for (Enumeration<JarEntry> en = jf.entries(); en.hasMoreElements();) {
            JarEntry e = en.nextElement();
            long mod_time = e.getTime();
            Path ep = tmpDir.resolve(e.getName());
            Path p;
            if (e.isDirectory()) {
                p = ep;
            } else {
                p = ep.getParent();
            }

            if (!p.toFile().isDirectory()) {
                Files.createDirectories(p);
            }

            if (!e.isDirectory()) {
                Files.copy(jf.getInputStream(e), ep,
                    StandardCopyOption.REPLACE_EXISTING);
            }

            if (mod_time > 0) {
                ep.toFile().setLastModified(mod_time);
            }
        }

        return tmpDir.toFile();
    }

    private class CtxFilterChain implements FilterChain
    {
        private int filter_index_ = 0;
        private final ServletReg servlet_;
        private final List<FilterReg> filters_;

        CtxFilterChain(ServletReg servlet, String path, DispatcherType dtype)
        {
            servlet_ = servlet;

            List<FilterReg> filters = new ArrayList<>();

            for (FilterMap m : filter_maps_) {
                if (filters.indexOf(m.filter_) != -1) {
                    continue;
                }

                if (!m.dtypes_.contains(dtype)) {
                    continue;
                }

                if (m.pattern_.match(path)) {
                    filters.add(m.filter_);

                    trace("add filter (matched): " + m.filter_.getName());
                }
            }

            for (FilterMap m : servlet.filters_) {
                if (filters.indexOf(m.filter_) != -1) {
                    continue;
                }

                if (!m.dtypes_.contains(dtype)) {
                    continue;
                }

                filters.add(m.filter_);

                trace("add filter (servlet): " + m.filter_.getName());
            }

            filters_ = filters;
        }

        @Override
        public void doFilter (ServletRequest request, ServletResponse response)
            throws IOException, ServletException
        {
            if (filter_index_ < filters_.size()) {
                filters_.get(filter_index_++).filter_.doFilter(request, response, this);

                return;
            }

            servlet_.service(request, response);
        }
    }

    private ServletReg findServlet(String path, DynamicPathRequest req)
    {
        /*
            12.1 Use of URL Paths
            ...
            1. The container will try to find an exact match of the path of the
               request to the path of the servlet. A successful match selects
               the servlet.
         */
        ServletReg servlet = exact2servlet_.get(path);
        if (servlet != null) {
            trace("findServlet: '" + path + "' exact matched pattern");
            req.setServletPath(path, null);
            return servlet;
        }

        /*
            2. The container will recursively try to match the longest
               path-prefix. This is done by stepping down the path tree a
               directory at a time, using the '/' character as a path separator.
               The longest match determines the servlet selected.
         */
        for (PrefixPattern p : prefix_patterns_) {
            if (p.match(path)) {
                trace("findServlet: '" + path + "' matched prefix pattern '" + p.pattern + "'");
                if (p.pattern.length() == path.length()) {
                    log("findServlet: WARNING: it is expected '" + path + "' exactly matches " + p.pattern);
                    req.setServletPath(path, p.pattern, null);
                } else {
                    req.setServletPath(path, p.pattern, path.substring(p.pattern.length()));
                }
                return p.servlet;
            }
        }

        /*
            3. If the last segment in the URL path contains an extension
               (e.g. .jsp), the servlet container will try to match a servlet
               that handles requests for the extension. An extension is defined
               as the part of the last segment after the last '.' character.
         */
        int suffix_start = path.lastIndexOf('.');
        if (suffix_start != -1) {
            String suffix = path.substring(suffix_start);
            servlet = suffix2servlet_.get(suffix);
            if (servlet != null) {
                trace("findServlet: '" + path + "' matched suffix pattern");
                req.setServletPath(path, null);
                return servlet;
            }
        }

        /*
            4. If neither of the previous three rules result in a servlet match,
               the container will attempt to serve content appropriate for the
               resource requested. If a "default" servlet is defined for the
               application, it will be used. ...
         */
        if (default_servlet_ != null) {
            trace("findServlet: '" + path + "' matched default servlet");
            req.setServletPath(path, null);
            return default_servlet_;
        }

        trace("findServlet: '" + path + "' no servlet found");

        /*
            10.10 Welcome Files
            ...
            If a Web container receives a valid partial request, the Web
            container must examine the welcome file list defined in the
            deployment descriptor.
            ...
         */
        if (path.endsWith("/")) {

            /*
                The Web server must append each welcome file in the order
                specified in the deployment descriptor to the partial request
                and check whether a static resource in the WAR is mapped to
                that request URI.
             */
            for (String wf : welcome_files_) {
                String wpath = path + wf;

                File f = new File(webapp_, wpath.substring(1));
                if (!f.exists()) {
                    continue;
                }

                trace("findServlet: '" + path + "' found static welcome "
                      + "file '" + wf + "'");

                /*
                    Even if static file found, we should try to find matching
                    servlet for JSP serving etc.
                 */
                servlet = findWelcomeServlet(wpath, true, req);
                if (servlet != null) {
                    return servlet;
                }

                req.setServletPath(wpath, null);

                return system_default_servlet_;
            }

            /*
                If no match is found, the Web server MUST again append each
                welcome file in the order specified in the deployment
                descriptor to the partial request and check if a servlet is
                mapped to that request URI. The Web container must send the
                request to the first resource in the WAR that matches.
             */
            for (String wf : welcome_files_) {
                String wpath = path + wf;

                servlet = findWelcomeServlet(wpath, false, req);
                if (servlet != null) {
                    return servlet;
                }
            }
        }

        trace("findServlet: '" + path + "' fallback to system default servlet");
        req.setServletPath(path, null);

        return system_default_servlet_;
    }

    private ServletReg findWelcomeServlet(String path, boolean exists,
        DynamicPathRequest req)
    {
        ServletReg servlet = exact2servlet_.get(path);
        if (servlet != null) {
            trace("findWelcomeServlet: '" + path + "' exact matched pattern");
            req.setServletPath(path, null);

            return servlet;
        }

        int suffix_start = path.lastIndexOf('.');
        if (suffix_start == -1) {
            return null;
        }

        String suffix = path.substring(suffix_start);
        servlet = suffix2servlet_.get(suffix);
        if (servlet == null) {
            return null;
        }

        trace("findWelcomeServlet: '" + path + "' matched suffix pattern");

        /*
            If we want to show the directory content when
            index.jsp is absent, then we have to check file
            presence here. Otherwise user will get 404.
         */

        if (servlet.system_jsp_servlet_ && !exists) {
            trace("findWelcomeServlet: '" + path + "' not exists");
            return null;
        }

        req.setServletPath(path, null);

        return servlet;
    }

    public void service(Request req, Response resp)
        throws ServletException, IOException
    {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(loader_);

        ServletRequestEvent sre = null;

        try {
            if (!req_init_listeners_.isEmpty()) {
                sre = new ServletRequestEvent(this, req);

                for (ServletRequestListener l : req_init_listeners_) {
                    l.requestInitialized(sre);
                }
            }

            URI uri = new URI(req.getRequestURI());
            String path = uri.getPath();

            if (!path.startsWith(context_path_)
                || (path.length() > context_path_.length()
                    && path.charAt(context_path_.length()) != '/'))
            {
                trace("service: '" + path + "' not started with '" + context_path_ + "'");

                resp.sendError(resp.SC_NOT_FOUND);
                return;
            }

            if (path.equals(context_path_)) {
                String url = req.getRequestURL().toString();
                if (!url.endsWith("/")) {
                    resp.setHeader("Location", url + "/");
                    resp.sendError(resp.SC_FOUND);
                    return;
                }
            }

            path = path.substring(context_path_.length());

            ServletReg servlet = findServlet(path, req);

            req.setMultipartConfig(servlet.multipart_config_);

            FilterChain fc = new CtxFilterChain(servlet, req.getFilterPath(), DispatcherType.REQUEST);

            fc.doFilter(req, resp);

            Object code = req.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
            if (code != null && code instanceof Integer) {
                handleStatusCode((Integer) code, req, resp);
            }
        } catch (Throwable e) {
            trace("service: caught " + e);

            try {
                if (!resp.isCommitted() && !exception2location_.isEmpty()) {
                    handleException(e, req, resp);
                }

                if (!resp.isCommitted()) {
                    resp.reset();
                    resp.setStatus(resp.SC_INTERNAL_SERVER_ERROR);
                    resp.setContentType("text/plain");

                    PrintWriter w = resp.getWriter();
                    w.println("Unhandled exception: " + e);
                    e.printStackTrace(w);

                    w.close();
                }
            } finally {
                throw new ServletException(e);
            }
        } finally {
            resp.flushBuffer();

            try {
                if (!req_destroy_listeners_.isEmpty()) {
                    for (ServletRequestListener l : req_destroy_listeners_) {
                        l.requestDestroyed(sre);
                    }
                }
            } finally {
                Thread.currentThread().setContextClassLoader(old);
            }
        }
    }

    private void handleException(Throwable e, Request req, Response resp)
        throws ServletException, IOException
    {
        String location;

        Class<?> cls = e.getClass();
        while (cls != null && !cls.equals(Throwable.class)) {
            location = exception2location_.get(cls.getName());

            if (location != null) {
                trace("Exception " + e + " matched. Error page location: " + location);

                req.setAttribute_(RequestDispatcher.ERROR_EXCEPTION, e);
                req.setAttribute_(RequestDispatcher.ERROR_EXCEPTION_TYPE, e.getClass());
                req.setAttribute_(RequestDispatcher.ERROR_REQUEST_URI, req.getRequestURI());
                req.setAttribute_(RequestDispatcher.ERROR_STATUS_CODE, resp.SC_INTERNAL_SERVER_ERROR);

                handleError(location, req, resp);

                return;
            }

            cls = cls.getSuperclass();
        }

        if (ServletException.class.isAssignableFrom(e.getClass())) {
            ServletException se = (ServletException) e;

            handleException(se.getRootCause(), req, resp);
        }
    }

    private void handleStatusCode(int code, Request req, Response resp)
        throws ServletException, IOException
    {
        String location;

        location = error2location_.get(code);

        if (location != null) {
            trace("Status " + code + " matched. Error page location: " + location);

            req.setAttribute_(RequestDispatcher.ERROR_REQUEST_URI, req.getRequestURI());

            handleError(location, req, resp);
        }
    }

    public void handleError(String location, Request req, Response resp)
        throws ServletException, IOException
    {
        try {
            log("handleError: " + location);

            String filter_path = req.getFilterPath();
            String servlet_path = req.getServletPath();
            String path_info = req.getPathInfo();
            String req_uri = req.getRequestURI();
            DispatcherType dtype = req.getDispatcherType();

            URI uri;

            if (location.startsWith("/")) {
                uri = new URI(context_path_ + location);
            } else {
                uri = new URI(req_uri).resolve(location);
            }

            req.setRequestURI(uri.getRawPath());
            req.setDispatcherType(DispatcherType.ERROR);

            String path = uri.getPath().substring(context_path_.length());

            ServletReg servlet = findServlet(path, req);

            req.setMultipartConfig(servlet.multipart_config_);

            FilterChain fc = new CtxFilterChain(servlet, req.getFilterPath(), DispatcherType.ERROR);

            fc.doFilter(req, resp);

            req.setServletPath(filter_path, servlet_path, path_info);
            req.setRequestURI(req_uri);
            req.setDispatcherType(dtype);
        } catch (URISyntaxException e) {
            throw new ServletException(e);
        }
    }

    private void processWebXml(File root) throws Exception
    {
        if (root.isDirectory()) {
            File web_xml = new File(root, "WEB-INF/web.xml");
            if (web_xml.exists()) {
                trace("start: web.xml file found");

                InputStream is = new FileInputStream(web_xml);

                processWebXml(is);

                is.close();
            }
        } else {
            JarFile jf = new JarFile(root);
            ZipEntry ze = jf.getEntry("WEB-INF/web.xml");

            if (ze == null) {
                trace("start: web.xml entry NOT found");
            } else {
                trace("start: web.xml entry found");

                processWebXml(jf.getInputStream(ze));
            }

            jf.close();
        }
    }

    private void processWebXml(InputStream is)
        throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document doc = builder.parse(is);

        Element doc_elem = doc.getDocumentElement();
        String doc_elem_name = doc_elem.getNodeName();
        if (!doc_elem_name.equals("web-app")) {
            throw new RuntimeException("Invalid web.xml: 'web-app' element expected, not '" + doc_elem_name + "'");
        }

        metadata_complete_ = doc_elem.getAttribute("metadata-complete").equals("true");
        app_version_ = doc_elem.getAttribute("version");

        NodeList welcome_file_lists = doc_elem.getElementsByTagName("welcome-file-list");

        if (welcome_file_lists.getLength() > 0) {
            welcome_files_list_found_ = true;
        }

        for (int i = 0; i < welcome_file_lists.getLength(); i++) {
            Element list_el = (Element) welcome_file_lists.item(i);
            NodeList files = list_el.getElementsByTagName("welcome-file");
            for (int j = 0; j < files.getLength(); j++) {
                Node node = files.item(j);
                String wf = node.getTextContent().trim();

                /*
                    10.10 Welcome Files
                    ...
                    The welcome file list is an ordered list of partial URLs
                    with no trailing or leading /.
                 */

                if (wf.startsWith("/") || wf.endsWith("/")) {
                    log("invalid welcome file: " + wf);
                    continue;
                }

                welcome_files_.add(wf);
            }
        }

        NodeList context_params = doc_elem.getElementsByTagName("context-param");
        for (int i = 0; i < context_params.getLength(); i++) {
            processXmlInitParam(this, (Element) context_params.item(i));
        }

        NodeList filters = doc_elem.getElementsByTagName("filter");

        for (int i = 0; i < filters.getLength(); i++) {
            Element filter_el = (Element) filters.item(i);
            NodeList names = filter_el.getElementsByTagName("filter-name");
            if (names == null || names.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'filter-name' tag not found");
            }

            String filter_name = names.item(0).getTextContent().trim();
            trace("filter-name=" + filter_name);

            FilterReg reg = new FilterReg(filter_name);

            NodeList child_nodes = filter_el.getChildNodes();
            for(int j = 0; j < child_nodes.getLength(); j++) {
                Node child_node = child_nodes.item(j);
                String tag_name = child_node.getNodeName();

                if (tag_name.equals("filter-class")) {
                    reg.setClassName(child_node.getTextContent().trim());
                    continue;
                }

                if (tag_name.equals("async-supported")) {
                    reg.setAsyncSupported(child_node.getTextContent().trim()
                        .equals("true"));
                    continue;
                }

                if (tag_name.equals("init-param")) {
                    processXmlInitParam(reg, (Element) child_node);
                    continue;
                }

                if (tag_name.equals("filter-name")
                    || tag_name.equals("#text")
                    || tag_name.equals("#comment"))
                {
                    continue;
                }

                log("processWebXml: tag '" + tag_name + "' for filter '"
                    + filter_name + "' is ignored");
            }

            filters_.add(reg);
            name2filter_.put(filter_name, reg);
        }

        NodeList filter_mappings = doc_elem.getElementsByTagName("filter-mapping");

        for(int i = 0; i < filter_mappings.getLength(); i++) {
            Element mapping_el = (Element) filter_mappings.item(i);
            NodeList names = mapping_el.getElementsByTagName("filter-name");
            if (names == null || names.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'filter-name' tag not found");
            }

            String filter_name = names.item(0).getTextContent().trim();
            trace("filter-name=" + filter_name);

            FilterReg reg = name2filter_.get(filter_name);
            if (reg == null) {
                throw new RuntimeException("Invalid web.xml: filter '" + filter_name + "' not found");
            }

            EnumSet<DispatcherType> dtypes = EnumSet.noneOf(DispatcherType.class);
            NodeList dispatchers = mapping_el.getElementsByTagName("dispatcher");
            for (int j = 0; j < dispatchers.getLength(); j++) {
                Node child_node = dispatchers.item(j);
                dtypes.add(DispatcherType.valueOf(child_node.getTextContent().trim()));
            }

            if (dtypes.isEmpty()) {
                dtypes.add(DispatcherType.REQUEST);
            }

            boolean match_after = false;

            NodeList child_nodes = mapping_el.getChildNodes();
            for (int j = 0; j < child_nodes.getLength(); j++) {
                Node child_node = child_nodes.item(j);
                String tag_name = child_node.getNodeName();

                if (tag_name.equals("url-pattern")) {
                    reg.addMappingForUrlPatterns(dtypes, match_after, child_node.getTextContent().trim());
                    continue;
                }

                if (tag_name.equals("servlet-name")) {
                    reg.addMappingForServletNames(dtypes, match_after, child_node.getTextContent().trim());
                    continue;
                }
            }
        }

        NodeList servlets = doc_elem.getElementsByTagName("servlet");

        for (int i = 0; i < servlets.getLength(); i++) {
            Element servlet_el = (Element) servlets.item(i);
            NodeList names = servlet_el.getElementsByTagName("servlet-name");
            if (names == null || names.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'servlet-name' tag not found");
            }

            String servlet_name = names.item(0).getTextContent().trim();
            trace("servlet-name=" + servlet_name);

            ServletReg reg = new ServletReg(servlet_name);

            NodeList child_nodes = servlet_el.getChildNodes();
            for(int j = 0; j < child_nodes.getLength(); j++) {
                Node child_node = child_nodes.item(j);
                String tag_name = child_node.getNodeName();

                if (tag_name.equals("servlet-class")) {
                    reg.setClassName(child_node.getTextContent().trim());
                    continue;
                }

                if (tag_name.equals("async-supported")) {
                    reg.setAsyncSupported(child_node.getTextContent().trim()
                        .equals("true"));
                    continue;
                }

                if (tag_name.equals("init-param")) {
                    processXmlInitParam(reg, (Element) child_node);
                    continue;
                }

                if (tag_name.equals("load-on-startup")) {
                    reg.setLoadOnStartup(Integer.parseInt(child_node.getTextContent().trim()));
                    continue;
                }

                if (tag_name.equals("jsp-file")) {
                    reg.setJspFile(child_node.getTextContent().trim());
                    continue;
                }

                if (tag_name.equals("servlet-name")
                    || tag_name.equals("display-name")
                    || tag_name.equals("#text")
                    || tag_name.equals("#comment"))
                {
                    continue;
                }

                log("processWebXml: tag '" + tag_name + "' for servlet '"
                    + servlet_name + "' is ignored");
            }

            servlets_.add(reg);
            name2servlet_.put(servlet_name, reg);
        }

        NodeList servlet_mappings = doc_elem.getElementsByTagName("servlet-mapping");

        for(int i = 0; i < servlet_mappings.getLength(); i++) {
            Element mapping_el = (Element) servlet_mappings.item(i);
            NodeList names = mapping_el.getElementsByTagName("servlet-name");
            if (names == null || names.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'servlet-name' tag not found");
            }

            String servlet_name = names.item(0).getTextContent().trim();
            trace("servlet-name=" + servlet_name);

            ServletReg reg = name2servlet_.get(servlet_name);
            if (reg == null) {
                throw new RuntimeException("Invalid web.xml: servlet '" + servlet_name + "' not found");
            }

            NodeList child_nodes = mapping_el.getElementsByTagName("url-pattern");
            String patterns[] = new String[child_nodes.getLength()];
            for(int j = 0; j < child_nodes.getLength(); j++) {
                Node child_node = child_nodes.item(j);
                patterns[j] = child_node.getTextContent().trim();
            }

            reg.addMapping(patterns);
        }

        NodeList listeners = doc_elem.getElementsByTagName("listener");

        for (int i = 0; i < listeners.getLength(); i++) {
            Element listener_el = (Element) listeners.item(i);
            NodeList classes = listener_el.getElementsByTagName("listener-class");
            if (classes == null || classes.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'listener-class' tag not found");
            }

            String class_name = classes.item(0).getTextContent().trim();
            trace("listener-class=" + class_name);

            pending_listener_classnames_.add(class_name);
        }

        NodeList error_pages = doc_elem.getElementsByTagName("error-page");

        for (int i = 0; i < error_pages.getLength(); i++) {
            Element error_page_el = (Element) error_pages.item(i);
            NodeList locations = error_page_el.getElementsByTagName("location");
            if (locations == null || locations.getLength() != 1) {
                throw new RuntimeException("Invalid web.xml: 'location' tag not found");
            }

            String location = locations.item(0).getTextContent().trim();

            NodeList child_nodes = error_page_el.getChildNodes();
            for(int j = 0; j < child_nodes.getLength(); j++) {
                Node child_node = child_nodes.item(j);
                String tag_name = child_node.getNodeName();

                if (tag_name.equals("exception-type")) {
                    String ex = child_node.getTextContent().trim();

                    exception2location_.put(ex, location);
                    trace("error-page: exception " + ex + " -> " + location);
                    continue;
                }

                if (tag_name.equals("error-code")) {
                    Integer code = Integer.parseInt(child_node.getTextContent().trim());

                    error2location_.put(code, location);
                    trace("error-page: code " + code + " -> " + location);
                    continue;
                }
            }
        }

        NodeList session_config = doc_elem.getElementsByTagName("session-config");

        for (int i = 0; i < session_config.getLength(); i++) {
            Element session_config_el = (Element) session_config.item(i);
            NodeList session_timeout = session_config_el.getElementsByTagName("session-timeout");
            if (session_timeout != null) {
                String timeout = session_timeout.item(0).getTextContent().trim();

                trace("session_timeout: " + timeout);
                session_timeout_ = Integer.parseInt(timeout);
                break;
            }
        }

        NodeList jsp_configs = doc_elem.getElementsByTagName("jsp-config");

        for (int i = 0; i < jsp_configs.getLength(); i++) {
            Element jsp_config_el = (Element) jsp_configs.item(i);

            NodeList jsp_nodes = jsp_config_el.getChildNodes();

            for(int j = 0; j < jsp_nodes.getLength(); j++) {
                Node jsp_node = jsp_nodes.item(j);
                String tag_name = jsp_node.getNodeName();

                if (tag_name.equals("taglib")) {
                    NodeList tl_nodes = ((Element) jsp_node).getChildNodes();
                    Taglib tl = new Taglib(tl_nodes);

                    trace("add taglib");

                    taglibs_.add(tl);
                    continue;
                }

                if (tag_name.equals("jsp-property-group")) {
                    NodeList jpg_nodes = ((Element) jsp_node).getChildNodes();
                    JspPropertyGroup conf = new JspPropertyGroup(jpg_nodes);

                    trace("add prop group");

                    prop_groups_.add(conf);
                    continue;
                }
            }
        }
    }

    private static int compareVersion(String ver1, String ver2)
    {
        String[] varr1 = ver1.split("\\.");
        String[] varr2 = ver2.split("\\.");

        int max_len = varr1.length > varr2.length ? varr1.length : varr2.length;
        for (int i = 0; i < max_len; i++) {
            int l = i < varr1.length ? Integer.parseInt(varr1[i]) : 0;
            int r = i < varr2.length ? Integer.parseInt(varr2[i]) : 0;

            int res = l - r;

            if (res != 0) {
                return res;
            }
        }

        return 0;
    }

    private void processXmlInitParam(InitParams params, Element elem)
          throws RuntimeException
    {
        NodeList n = elem.getElementsByTagName("param-name");
        if (n == null || n.getLength() != 1) {
            throw new RuntimeException("Invalid web.xml: 'param-name' tag not found");
        }

        NodeList v = elem.getElementsByTagName("param-value");
        if (v == null || v.getLength() != 1) {
            throw new RuntimeException("Invalid web.xml: 'param-value' tag not found");
        }
        params.setInitParameter(n.item(0).getTextContent().trim(),
            v.item(0).getTextContent().trim());
    }

    private void loadInitializers(ScanResult scan_res)
    {
        trace("load initializer(s)");

        ServiceLoader<ServletContainerInitializer> initializers =
            ServiceLoader.load(ServletContainerInitializer.class, loader_);

        for (ServletContainerInitializer sci : initializers) {
            loadInitializer(sci, scan_res);
        }
    }

    private void loadInitializer(ServletContainerInitializer sci, ScanResult scan_res)
    {
        trace("loadInitializer: initializer: " + sci.getClass().getName());

        /*
            Unit WebSocket container is a copy of Tomcat WsSci with own
            transport implementation.  Tomcat implementation will not work in
            Unit and should be ignored here.
         */
        if (sci.getClass().getName()
              .equals("org.apache.tomcat.websocket.server.WsSci"))
        {
            trace("loadInitializer: ignore");
            return;
        }

        HandlesTypes ann = sci.getClass().getAnnotation(HandlesTypes.class);
        if (ann == null) {
            trace("loadInitializer: no HandlesTypes annotation");
            return;
        }

        Class<?>[] classes = ann.value();
        if (classes == null) {
            trace("loadInitializer: no handles classes");
            return;
        }

        Set<Class<?>> handles_classes = new HashSet<>();

        for (Class<?> c : classes) {
            trace("loadInitializer: find handles: " + c.getName());

            ClassInfoList handles =
                c.isAnnotation()
                ? scan_res.getClassesWithAnnotation(c.getName())
                : c.isInterface()
                    ? scan_res.getClassesImplementing(c.getName())
                    : scan_res.getSubclasses(c.getName());

            for (ClassInfo ci : handles) {
                if (ci.isInterface()
                    || ci.isAnnotation()
                    || ci.isAbstract())
                {
                    continue;
                }

                trace("loadInitializer: handles class: " + ci.getName());
                handles_classes.add(ci.loadClass());
            }
        }

        if (handles_classes.isEmpty()) {
            trace("loadInitializer: no handles implementations");
            return;
        }

        try {
            sci.onStartup(handles_classes, this);
        } catch(Exception e) {
            System.err.println("loadInitializer: exception caught: " + e.toString());
        }
    }

    private void scanClasses(ScanResult scan_res)
        throws ReflectiveOperationException
    {
        ClassInfoList filters = scan_res.getClassesWithAnnotation(WebFilter.class.getName());

        for (ClassInfo ci : filters) {
            if (ci.isInterface()
                || ci.isAnnotation()
                || ci.isAbstract()
                || !ci.implementsInterface(Filter.class.getName()))
            {
                trace("scanClasses: ignoring Filter impl: " + ci.getName());
                continue;
            }

            trace("scanClasses: found Filter class: " + ci.getName());

            Class<?> cls = ci.loadClass();
            if (!Filter.class.isAssignableFrom(cls)) {
                trace("scanClasses: " + ci.getName() + " cannot be assigned to Filter");
                continue;
            }

            WebFilter ann = cls.getAnnotation(WebFilter.class);

            if (ann == null) {
                trace("scanClasses: no WebFilter annotation for " + ci.getName());
                continue;
            }

            String filter_name = ann.filterName();

            if (filter_name.isEmpty()) {
                filter_name = ci.getName();
            }

            FilterReg reg = name2filter_.get(filter_name);

            if (reg == null) {
                reg = new FilterReg(filter_name, cls);
                filters_.add(reg);
                name2filter_.put(filter_name, reg);
            } else {
                reg.setClass(cls);
            }

            EnumSet<DispatcherType> dtypes = EnumSet.noneOf(DispatcherType.class);
            DispatcherType[] dispatchers = ann.dispatcherTypes();
            for (DispatcherType d : dispatchers) {
                dtypes.add(d);
            }

            if (dtypes.isEmpty()) {
                dtypes.add(DispatcherType.REQUEST);
            }

            boolean match_after = false;

            reg.addMappingForUrlPatterns(dtypes, match_after, ann.value());
            reg.addMappingForUrlPatterns(dtypes, match_after, ann.urlPatterns());
            reg.addMappingForServletNames(dtypes, match_after, ann.servletNames());

            for (WebInitParam p : ann.initParams()) {
                reg.setInitParameter(p.name(), p.value());
            }

            reg.setAsyncSupported(ann.asyncSupported());
        }

        ClassInfoList servlets = scan_res.getClassesWithAnnotation(WebServlet.class.getName());

        for (ClassInfo ci : servlets) {
            if (ci.isInterface()
                || ci.isAnnotation()
                || ci.isAbstract()
                || !ci.extendsSuperclass(HttpServlet.class.getName()))
            {
                trace("scanClasses: ignoring HttpServlet subclass: " + ci.getName());
                continue;
            }

            trace("scanClasses: found HttpServlet class: " + ci.getName());

            Class<?> cls = ci.loadClass();
            if (!HttpServlet.class.isAssignableFrom(cls)) {
                trace("scanClasses: " + ci.getName() + " cannot be assigned to HttpFilter");
                continue;
            }

            WebServlet ann = cls.getAnnotation(WebServlet.class);

            if (ann == null) {
                trace("scanClasses: no WebServlet annotation");
                continue;
            }

            String servlet_name = ann.name();

            if (servlet_name.isEmpty()) {
                servlet_name = ci.getName();
            }

            ServletReg reg = name2servlet_.get(servlet_name);

            if (reg == null) {
                reg = new ServletReg(servlet_name, cls);
                servlets_.add(reg);
                name2servlet_.put(servlet_name, reg);
            } else {
                reg.setClass(cls);
            }

            reg.addMapping(ann.value());
            reg.addMapping(ann.urlPatterns());

            for (WebInitParam p : ann.initParams()) {
                reg.setInitParameter(p.name(), p.value());
            }

            reg.setAsyncSupported(ann.asyncSupported());
        }


        ClassInfoList lstnrs = scan_res.getClassesWithAnnotation(WebListener.class.getName());

        for (ClassInfo ci : lstnrs) {
            if (ci.isInterface()
                || ci.isAnnotation()
                || ci.isAbstract())
            {
                trace("scanClasses: listener impl: " + ci.getName());
                continue;
            }

            trace("scanClasses: listener class: " + ci.getName());

            if (listener_classnames_.contains(ci.getName())) {
                trace("scanClasses: " + ci.getName() + " already added as listener");
                continue;
            }

            Class<?> cls = ci.loadClass();
            Class<?> lclass = null;
            for (Class<?> c : LISTENER_TYPES) {
                if (c.isAssignableFrom(cls)) {
                    lclass = c;
                    break;
                }
            }

            if (lclass == null) {
                log("scanClasses: " + ci.getName() + " implements none of known listener interfaces");
                continue;
            }

            WebListener ann = cls.getAnnotation(WebListener.class);

            if (ann == null) {
                log("scanClasses: no WebListener annotation");
                continue;
            }

            Constructor<?> ctor = cls.getConstructor();
            EventListener listener = (EventListener) ctor.newInstance();

            addListener(listener);

            listener_classnames_.add(ci.getName());
        }


        ClassInfoList endpoints = scan_res.getClassesWithAnnotation(ServerEndpoint.class.getName());

        for (ClassInfo ci : endpoints) {
            if (ci.isInterface()
                || ci.isAnnotation()
                || ci.isAbstract())
            {
                trace("scanClasses: skip server end point: " + ci.getName());
                continue;
            }

            trace("scanClasses: server end point: " + ci.getName());
        }
    }

    public void stop() throws IOException
    {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(loader_);

        try {
            for (ServletReg s : servlets_) {
                s.destroy();
            }

            for (FilterReg f : filters_) {
                f.destroy();
            }

            if (!destroy_listeners_.isEmpty()) {
                ServletContextEvent event = new ServletContextEvent(this);
                for (ServletContextListener listener : destroy_listeners_) {
                    listener.contextDestroyed(event);
                }
            }

            if (extracted_dir_ != null) {
                removeDir(extracted_dir_);
            }

            if (temp_dir_ != null) {
                removeDir(temp_dir_);
            }
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    private void removeDir(File dir) throws IOException
    {
        Files.walkFileTree(dir.toPath(),
            new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult postVisitDirectory(
                  Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(
                  Path file, BasicFileAttributes attrs)
                  throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }
            });
    }

    private class CtxInitParams implements InitParams
    {
        private final Map<String, String> init_params_ =
            new HashMap<String, String>();

        public boolean setInitParameter(String name, String value)
        {
            trace("CtxInitParams.setInitParameter " + name + " = " + value);

            return init_params_.putIfAbsent(name, value) == null;
        }

        public String getInitParameter(String name)
        {
            trace("CtxInitParams.getInitParameter for " + name);

            return init_params_.get(name);
        }

        public Set<String> setInitParameters(Map<String, String> initParameters)
        {
            // illegalStateIfContextStarted();
            Set<String> clash = null;
            for (Map.Entry<String, String> entry : initParameters.entrySet())
            {
                if (entry.getKey() == null) {
                    throw new IllegalArgumentException("init parameter name required");
                }

                if (entry.getValue() == null) {
                    throw new IllegalArgumentException("non-null value required for init parameter " + entry.getKey());
                }

                if (init_params_.get(entry.getKey()) != null)
                {
                    if (clash == null)
                        clash = new HashSet<String>();
                    clash.add(entry.getKey());
                }

                trace("CtxInitParams.setInitParameters " + entry.getKey() + " = " + entry.getValue());
            }

            if (clash != null) {
                return clash;
            }

            init_params_.putAll(initParameters);
            return Collections.emptySet();
        }

        public Map<String, String> getInitParameters()
        {
            trace("CtxInitParams.getInitParameters");
            return init_params_;
        }

        public Enumeration<String> getInitParameterNames()
        {
            return Collections.enumeration(init_params_.keySet());
        }
    }

    private class NamedReg extends CtxInitParams
        implements Registration
    {
        private final String name_;
        private String class_name_;

        public NamedReg(String name)
        {
            name_ = name;
        }

        public NamedReg(String name, String class_name)
        {
            name_ = name;
            class_name_ = class_name;
        }

        @Override
        public String getName()
        {
            return name_;
        }

        @Override
        public String getClassName()
        {
            return class_name_;
        }

        public void setClassName(String class_name)
        {
            class_name_ = class_name;
        }
    }

    private class ServletReg extends NamedReg
        implements ServletRegistration.Dynamic, ServletConfig
    {
        private Class<?> servlet_class_;
        private Servlet servlet_;
        private String role_;
        private boolean async_supported_ = false;
        private final List<String> patterns_ = new ArrayList<>();
        private int load_on_startup_ = -1;
        private boolean initialized_ = false;
        private final List<FilterMap> filters_ = new ArrayList<>();
        private boolean system_jsp_servlet_ = false;
        private String jsp_file_;
        private MultipartConfigElement multipart_config_;

        public ServletReg(String name, Class<?> servlet_class)
        {
            super(name, servlet_class.getName());
            servlet_class_ = servlet_class;
            getAnnotationMultipartConfig();
        }

        public ServletReg(String name, Servlet servlet)
        {
            super(name, servlet.getClass().getName());
            servlet_ = servlet;
        }

        public ServletReg(String name, String servlet_class_name)
        {
            super(name, servlet_class_name);
        }

        public ServletReg(String name)
        {
            super(name);
        }

        private void init() throws ServletException
        {
            if (initialized_) {
                return;
            }

            trace("ServletReg.init(): " + getName());

            if (jsp_file_ != null) {
                setInitParameter("jspFile", jsp_file_);
                jsp_file_ = null;

                ServletReg jsp_servlet = name2servlet_.get("jsp");

                if (jsp_servlet.servlet_class_ != null) {
                    servlet_class_ = jsp_servlet.servlet_class_;
                } else {
                    setClassName(jsp_servlet.getClassName());
                }

                system_jsp_servlet_ = jsp_servlet.system_jsp_servlet_;
            }

            if (system_jsp_servlet_) {
                JasperInitializer ji = new JasperInitializer();

                ji.onStartup(Collections.emptySet(), Context.this);
            }

            if (servlet_ == null) {
                try {
                    if (servlet_class_ == null) {
                        servlet_class_ = loader_.loadClass(getClassName());
                        getAnnotationMultipartConfig();
                    }

                    Constructor<?> ctor = servlet_class_.getConstructor();
                    servlet_ = (Servlet) ctor.newInstance();
                } catch(Exception e) {
                    log("ServletReg.init() failed " + e);
                    throw new ServletException(e);
                }
            }

            servlet_.init((ServletConfig) this);

            initialized_ = true;
        }

        public void startup() throws ServletException
        {
            if (load_on_startup_ < 0) {
                return;
            }

            init();
        }

        public void destroy()
        {
            if (initialized_) {
                servlet_.destroy();
            }
        }

        public void setClassName(String class_name) throws IllegalStateException
        {
            if (servlet_ != null
                || servlet_class_ != null
                || getClassName() != null)
            {
                throw new IllegalStateException("Class already initialized");
            }

            if (jsp_file_ != null) {
                throw new IllegalStateException("jsp-file already initialized");
            }

            super.setClassName(class_name);
        }

        public void setClass(Class<?> servlet_class)
            throws IllegalStateException
        {
            if (servlet_ != null
                || servlet_class_ != null
                || getClassName() != null)
            {
                throw new IllegalStateException("Class already initialized");
            }

            if (jsp_file_ != null) {
                throw new IllegalStateException("jsp-file already initialized");
            }

            super.setClassName(servlet_class.getName());
            servlet_class_ = servlet_class;
            getAnnotationMultipartConfig();
        }

        public void setJspFile(String jsp_file) throws IllegalStateException
        {
            if (servlet_ != null
                || servlet_class_ != null
                || getClassName() != null)
            {
                throw new IllegalStateException("Class already initialized");
            }

            if (jsp_file_ != null) {
                throw new IllegalStateException("jsp-file already initialized");
            }

            jsp_file_ = jsp_file;
        }

        private void getAnnotationMultipartConfig() {
            if (servlet_class_ == null) {
                return;
            }

            MultipartConfig mpc = servlet_class_.getAnnotation(MultipartConfig.class);
            if (mpc == null) {
                return;
            }

            multipart_config_ = new MultipartConfigElement(mpc);
        }

        public void service(ServletRequest request, ServletResponse response)
            throws ServletException, IOException
        {
            init();

            servlet_.service(request, response);
        }

        public void addFilter(FilterMap fmap)
        {
            filters_.add(fmap);
        }

        @Override
        public Set<String> addMapping(String... urlPatterns)
        {
            checkContextState();

            Set<String> clash = null;
            for (String pattern : urlPatterns) {
                trace("ServletReg.addMapping: " + pattern);

                if (pattern2servlet_.containsKey(pattern)) {
                    if (clash == null) {
                        clash = new HashSet<String>();
                    }
                    clash.add(pattern);
                }
            }

            /* if there were any clashes amongst the urls, return them */
            if (clash != null) {
                return clash;
            }

            for (String pattern : urlPatterns) {
                patterns_.add(pattern);
                pattern2servlet_.put(pattern, this);
                parseURLPattern(pattern, this);
            }

            return Collections.emptySet();
        }

        @Override
        public Collection<String> getMappings()
        {
            trace("ServletReg.getMappings");
            return patterns_;
        }

        @Override
        public String getRunAsRole()
        {
            return role_;
        }

        @Override
        public void setLoadOnStartup(int loadOnStartup)
        {
            checkContextState();

            trace("ServletReg.setLoadOnStartup: " + loadOnStartup);
            load_on_startup_ = loadOnStartup;
        }

        @Override
        public Set<String> setServletSecurity(ServletSecurityElement constraint)
        {
            log("ServletReg.setServletSecurity");
            return Collections.emptySet();
        }

        @Override
        public void setMultipartConfig(
            MultipartConfigElement multipartConfig)
        {
            trace("ServletReg.setMultipartConfig");
            multipart_config_ = multipartConfig;
        }

        @Override
        public void setRunAsRole(String roleName)
        {
            log("ServletReg.setRunAsRole: " + roleName);
            role_ = roleName;
        }

        @Override
        public void setAsyncSupported(boolean isAsyncSupported)
        {
            log("ServletReg.setAsyncSupported: " + isAsyncSupported);
            async_supported_ = isAsyncSupported;
        }

        @Override
        public String getServletName()
        {
            return getName();
        }

        @Override
        public ServletContext getServletContext()
        {
            return (ServletContext) Context.this;
        }
    }

    public void checkContextState() throws IllegalStateException
    {
        if (ctx_initialized_) {
            throw new IllegalStateException("Context already initialized");
        }
    }

    public void parseURLPattern(String p, ServletReg servlet)
        throws IllegalArgumentException
    {
        URLPattern pattern = parseURLPattern(p);

        switch (pattern.type_) {
        case PREFIX:
            prefix_patterns_.add(new PrefixPattern(pattern.pattern_, servlet));
            return;

        case SUFFIX:
            suffix2servlet_.put(pattern.pattern_, servlet);
            return;

        case EXACT:
            exact2servlet_.put(pattern.pattern_, servlet);
            return;

        case DEFAULT:
            default_servlet_ = servlet;
            return;
        }

        /* TODO process other cases, throw IllegalArgumentException */
    }

    public URLPattern parseURLPattern(String p)
        throws IllegalArgumentException
    {
        URLPattern pattern = parsed_patterns_.get(p);
        if (pattern == null) {
            pattern = new URLPattern(p);
            parsed_patterns_.put(p, pattern);
        }

        return pattern;
    }

    private static enum URLPatternType {
        PREFIX,
        SUFFIX,
        DEFAULT,
        EXACT,
    };

    private class URLPattern
    {
        private final String pattern_;
        private final URLPatternType type_;

        public URLPattern(String p)
            throws IllegalArgumentException
        {
            /*
                12.2 Specification of Mappings
                ...
                A string beginning with a '/' character and ending with a '/*'
                suffix is used for path mapping.
             */
            if (p.startsWith("/") && p.endsWith("/*")) {
                trace("URLPattern: '" + p + "' is a prefix pattern");
                pattern_ = p.substring(0, p.length() - 2);
                type_ = URLPatternType.PREFIX;
                return;
            }

            /*
                A string beginning with a '*.' prefix is used as an extension
                mapping.
             */
            if (p.startsWith("*.")) {
                trace("URLPattern: '" + p + "' is a suffix pattern");
                pattern_ = p.substring(1, p.length());
                type_ = URLPatternType.SUFFIX;
                return;
            }

            /*
                The empty string ("") is a special URL pattern that exactly maps to
                the application's context root, i.e., requests of the form
                http://host:port/<context- root>/. In this case the path info is '/'
                and the servlet path and context path is empty string ("").
             */
            if (p.isEmpty()) {
                trace("URLPattern: '" + p + "' is a root");
                pattern_ = "/";
                type_ = URLPatternType.EXACT;
                return;
            }

            /*
                A string containing only the '/' character indicates the "default"
                servlet of the application. In this case the servlet path is the
                request URI minus the context path and the path info is null.
             */
            if (p.equals("/")) {
                trace("URLPattern: '" + p + "' is a default");
                pattern_ = p;
                type_ = URLPatternType.DEFAULT;
                return;
            }

            /*
                All other strings are used for exact matches only.
             */
            trace("URLPattern: '" + p + "' is an exact pattern");
            pattern_ = p;
            type_ = URLPatternType.EXACT;

            /* TODO process other cases, throw IllegalArgumentException */
        }

        public boolean match(String url)
        {
            switch (type_) {
            case PREFIX:
                return url.startsWith(pattern_) && (
                    url.length() == pattern_.length()
                    || url.charAt(pattern_.length()) == '/');

            case SUFFIX:
                return url.endsWith(pattern_);

            case EXACT:
                return url.equals(pattern_);

            case DEFAULT:
                return true;
            }

            return false;
        }
    }

    private class FilterReg extends NamedReg
        implements FilterRegistration.Dynamic, FilterConfig
    {
        private Class<?> filter_class_;
        private Filter filter_;
        private boolean async_supported_ = false;
        private boolean initialized_ = false;

        public FilterReg(String name, Class<?> filter_class)
        {
            super(name, filter_class.getName());
            filter_class_ = filter_class;
        }

        public FilterReg(String name, Filter filter)
        {
            super(name, filter.getClass().getName());
            filter_ = filter;
        }

        public FilterReg(String name, String filter_class_name)
        {
            super(name, filter_class_name);
        }

        public FilterReg(String name)
        {
            super(name);
        }

        public void setClassName(String class_name) throws IllegalStateException
        {
            if (filter_ != null
                || filter_class_ != null
                || getClassName() != null)
            {
                throw new IllegalStateException("Class already initialized");
            }

            super.setClassName(class_name);
        }

        public void setClass(Class<?> filter_class) throws IllegalStateException
        {
            if (filter_ != null
                || filter_class_ != null
                || getClassName() != null)
            {
                throw new IllegalStateException("Class already initialized");
            }

            super.setClassName(filter_class.getName());
            filter_class_ = filter_class;
        }

        public void init() throws ServletException
        {
            if (filter_ == null) {
                try {
                    if (filter_class_ == null) {
                        filter_class_ = loader_.loadClass(getClassName());
                    }

                    Constructor<?> ctor = filter_class_.getConstructor();
                    filter_ = (Filter) ctor.newInstance();
                } catch(Exception e) {
                    log("FilterReg.init() failed " + e);
                    throw new ServletException(e);
                }
            }

            filter_.init((FilterConfig) this);

            initialized_ = true;
        }

        public void destroy()
        {
            if (initialized_) {
                filter_.destroy();
            }
        }

        @Override
        public void addMappingForServletNames(
            EnumSet<DispatcherType> dispatcherTypes, boolean isMatchAfter,
            String... servletNames)
        {
            checkContextState();

            for (String n : servletNames) {
                trace("FilterReg.addMappingForServletNames: ... " + n);

                ServletReg sreg = name2servlet_.get(n);
                if (sreg == null) {
                    sreg = new ServletReg(n);
                    servlets_.add(sreg);
                    name2servlet_.put(n, sreg);
                }

                FilterMap map = new FilterMap(this, sreg, dispatcherTypes,
                    isMatchAfter);

                sreg.addFilter(map);
            }
        }

        @Override
        public Collection<String> getServletNameMappings()
        {
            checkContextState();

            log("FilterReg.getServletNameMappings");
            return Collections.emptySet();
        }

        @Override
        public void addMappingForUrlPatterns(
            EnumSet<DispatcherType> dispatcherTypes, boolean isMatchAfter,
            String... urlPatterns)
        {
            checkContextState();

            for (String u : urlPatterns) {
                trace("FilterReg.addMappingForUrlPatterns: ... " + u);

                URLPattern p = parseURLPattern(u);
                FilterMap map = new FilterMap(this, p, dispatcherTypes,
                    isMatchAfter);

                filter_maps_.add(map);
            }
        }

        @Override
        public Collection<String> getUrlPatternMappings()
        {
            log("FilterReg.getUrlPatternMappings");
            return Collections.emptySet();
        }

        @Override
        public void setAsyncSupported(boolean isAsyncSupported)
        {
            log("FilterReg.setAsyncSupported: " + isAsyncSupported);
            async_supported_ = isAsyncSupported;
        }

        @Override
        public String getFilterName()
        {
            return getName();
        }

        @Override
        public ServletContext getServletContext()
        {
            return (ServletContext) Context.this;
        }
    }

    private class FilterMap
    {
        private final FilterReg filter_;
        private final ServletReg servlet_;
        private final URLPattern pattern_;
        private final EnumSet<DispatcherType> dtypes_;
        private final boolean match_after_;

        public FilterMap(FilterReg filter, ServletReg servlet,
            EnumSet<DispatcherType> dtypes, boolean match_after)
        {
            filter_ = filter;
            servlet_ = servlet;
            pattern_ = null;
            dtypes_ = dtypes;
            match_after_ = match_after;
        }

        public FilterMap(FilterReg filter, URLPattern pattern,
            EnumSet<DispatcherType> dtypes, boolean match_after)
        {
            filter_ = filter;
            servlet_ = null;
            pattern_ = pattern;
            dtypes_ = dtypes;
            match_after_ = match_after;
        }
    }

    private void initialized()
    {
        if (!sess_attr_listeners_.isEmpty()) {
            sess_attr_proxy_ = new SessionAttrProxy(sess_attr_listeners_);
        }

        if (!req_attr_listeners_.isEmpty()) {
            req_attr_proxy_ = new RequestAttrProxy(req_attr_listeners_);
        }

        ClassLoader old = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(loader_);

        try {
            // Call context listeners
            destroy_listeners_.clear();
            if (!ctx_listeners_.isEmpty()) {
                ServletContextEvent event = new ServletContextEvent(this);
                for (ServletContextListener listener : ctx_listeners_)
                {
                    try {
                        listener.contextInitialized(event);
                    } catch(AbstractMethodError e) {
                        log("initialized: AbstractMethodError exception caught: " + e);
                    }
                    destroy_listeners_.add(0, listener);
                }
            }

            for (ServletReg sr : servlets_) {
                try {
                    sr.startup();
                } catch(ServletException e) {
                    log("initialized: exception caught: " + e);
                }
            }

            for (FilterReg fr : filters_) {
                try {
                    fr.init();
                } catch(ServletException e) {
                    log("initialized: exception caught: " + e);
                }
            }

            ctx_initialized_ = true;
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    @Override
    public ServletContext getContext(String uripath)
    {
        trace("getContext for " + uripath);
        return this;
    }

    @Override
    public int getMajorVersion()
    {
        trace("getMajorVersion");
        return SERVLET_MAJOR_VERSION;
    }

    @Override
    public String getMimeType(String file)
    {
        log("getMimeType for " + file);
        if (mime_types_ == null) {
            mime_types_ = new MimeTypes();
        }
        return mime_types_.getMimeByExtension(file);
    }

    @Override
    public int getMinorVersion()
    {
        trace("getMinorVersion");
        return SERVLET_MINOR_VERSION;
    }

    private class URIRequestDispatcher implements RequestDispatcher
    {
        private final URI uri_;

        public URIRequestDispatcher(URI uri)
        {
            uri_ = uri;
        }

        public URIRequestDispatcher(String uri)
            throws URISyntaxException
        {
            uri_ = new URI(uri);
        }

        @Override
        public void forward(ServletRequest request, ServletResponse response)
            throws ServletException, IOException
        {
            /*
                9.4 The Forward Method
                ...
                If the response has been committed, an IllegalStateException
                must be thrown.
             */
            if (response.isCommitted()) {
                throw new IllegalStateException("Response already committed");
            }

            ForwardRequestWrapper req = new ForwardRequestWrapper(request);

            try {
                trace("URIRequestDispatcher.forward");

                String path = uri_.getPath().substring(context_path_.length());

                ServletReg servlet = findServlet(path, req);

                req.setMultipartConfig(servlet.multipart_config_);

                req.setRequestURI(uri_.getRawPath());
                req.setQueryString(uri_.getRawQuery());
                req.setDispatcherType(DispatcherType.FORWARD);

                /*
                    9.4 The Forward Method
                    ...
                    If output data exists in the response buffer that has not
                    been committed, the content must be cleared before the
                    target servlet's service method is called.
                 */
                response.resetBuffer();

                FilterChain fc = new CtxFilterChain(servlet, req.getFilterPath(), DispatcherType.FORWARD);

                fc.doFilter(request, response);

                /*
                    9.4 The Forward Method
                    ...
                    Before the forward method of the RequestDispatcher interface
                    returns without exception, the response content must be sent
                    and committed, and closed by the servlet container, unless
                    the request was put into the asynchronous mode. If an error
                    occurs in the target of the RequestDispatcher.forward() the
                    exception may be propagated back through all the calling
                    filters and servlets and eventually back to the container
                 */
                if (!request.isAsyncStarted()) {
                    response.flushBuffer();
                }

            /*
                9.5 Error Handling

                If the servlet that is the target of a request dispatcher
                throws a runtime exception or a checked exception of type
                ServletException or IOException, it should be propagated
                to the calling servlet. All other exceptions should be
                wrapped as ServletExceptions and the root cause of the
                exception set to the original exception, as it should
                not be propagated.
             */
            } catch (ServletException e) {
                throw e;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new ServletException(e);
            } finally {
                req.close();

                trace("URIRequestDispatcher.forward done");
            }
        }

        @Override
        public void include(ServletRequest request, ServletResponse response)
            throws ServletException, IOException
        {
            IncludeRequestWrapper req = new IncludeRequestWrapper(request);

            try {
                trace("URIRequestDispatcher.include");

                String path = uri_.getPath().substring(context_path_.length());

                ServletReg servlet = findServlet(path, req);

                req.setMultipartConfig(servlet.multipart_config_);

                req.setRequestURI(uri_.getRawPath());
                req.setQueryString(uri_.getRawQuery());
                req.setDispatcherType(DispatcherType.INCLUDE);

                FilterChain fc = new CtxFilterChain(servlet, req.getFilterPath(), DispatcherType.INCLUDE);

                fc.doFilter(request, new IncludeResponseWrapper(response));

            } catch (ServletException e) {
                throw e;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new ServletException(e);
            } finally {
                req.close();

                trace("URIRequestDispatcher.include done");
            }
        }
    }

    private class ServletDispatcher implements RequestDispatcher
    {
        private final ServletReg servlet_;

        public ServletDispatcher(ServletReg servlet)
        {
            servlet_ = servlet;
        }

        @Override
        public void forward(ServletRequest request, ServletResponse response)
            throws ServletException, IOException
        {
            /*
                9.4 The Forward Method
                ...
                If the response has been committed, an IllegalStateException
                must be thrown.
             */
            if (response.isCommitted()) {
                throw new IllegalStateException("Response already committed");
            }

            trace("ServletDispatcher.forward");

            DispatcherType dtype = request.getDispatcherType();

            Request req;
            if (request instanceof Request) {
                req = (Request) request;
            } else {
                req = (Request) request.getAttribute(Request.BARE);
            }

            try {
                req.setDispatcherType(DispatcherType.FORWARD);

                /*
                    9.4 The Forward Method
                    ...
                    If output data exists in the response buffer that has not
                    been committed, the content must be cleared before the
                    target servlet's service method is called.
                 */
                response.resetBuffer();

                servlet_.service(request, response);

                /*
                    9.4 The Forward Method
                    ...
                    Before the forward method of the RequestDispatcher interface
                    returns without exception, the response content must be sent
                    and committed, and closed by the servlet container, unless
                    the request was put into the asynchronous mode. If an error
                    occurs in the target of the RequestDispatcher.forward() the
                    exception may be propagated back through all the calling
                    filters and servlets and eventually back to the container
                 */
                if (!request.isAsyncStarted()) {
                    response.flushBuffer();
                }

            /*
                9.5 Error Handling

                If the servlet that is the target of a request dispatcher
                throws a runtime exception or a checked exception of type
                ServletException or IOException, it should be propagated
                to the calling servlet. All other exceptions should be
                wrapped as ServletExceptions and the root cause of the
                exception set to the original exception, as it should
                not be propagated.
             */
            } catch (ServletException e) {
                throw e;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new ServletException(e);
            } finally {
                req.setDispatcherType(dtype);

                trace("ServletDispatcher.forward done");
            }
        }

        @Override
        public void include(ServletRequest request, ServletResponse response)
            throws ServletException, IOException
        {
            trace("ServletDispatcher.include");

            DispatcherType dtype = request.getDispatcherType();

            Request req;
            if (request instanceof Request) {
                req = (Request) request;
            } else {
                req = (Request) request.getAttribute(Request.BARE);
            }

            try {
                req.setDispatcherType(DispatcherType.INCLUDE);

                servlet_.service(request, new IncludeResponseWrapper(response));

            } catch (ServletException e) {
                throw e;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new ServletException(e);
            } finally {
                req.setDispatcherType(dtype);

                trace("ServletDispatcher.include done");
            }
        }
    }

    @Override
    public RequestDispatcher getNamedDispatcher(String name)
    {
        trace("getNamedDispatcher for " + name);

        ServletReg servlet = name2servlet_.get(name);
        if (servlet != null) {
            return new ServletDispatcher(servlet);
        }

        return null;
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String uriInContext)
    {
        trace("getRequestDispatcher for " + uriInContext);
        try {
            return new URIRequestDispatcher(context_path_ + uriInContext);
        } catch (URISyntaxException e) {
            log("getRequestDispatcher: failed to create dispatcher: " + e);
        }

        return null;
    }

    public RequestDispatcher getRequestDispatcher(URI uri)
    {
        trace("getRequestDispatcher for " + uri.getRawPath());
        return new URIRequestDispatcher(uri);
    }

    @Override
    public String getRealPath(String path)
    {
        trace("getRealPath for " + path);

        File f = new File(webapp_, path.isEmpty() ? "" : path.substring(1));

        return f.getAbsolutePath();
    }

    @Override
    public URL getResource(String path) throws MalformedURLException
    {
        trace("getResource for " + path);

        File f = new File(webapp_, path.substring(1));

        if (f.exists()) {
            return new URL("file:" + f.getAbsolutePath());
        }

        return null;
    }

    @Override
    public InputStream getResourceAsStream(String path)
    {
        trace("getResourceAsStream for " + path);

        try {
            File f = new File(webapp_, path.substring(1));

            return new FileInputStream(f);
        } catch (FileNotFoundException e) {
            log("getResourceAsStream: failed " + e);

            return null;
        }
    }

    @Override
    public Set<String> getResourcePaths(String path)
    {
        trace("getResourcePaths for " + path);

        File dir = new File(webapp_, path.substring(1));
        File[] list = dir.listFiles();

        if (list == null) {
            return null;
        }

        Set<String> res = new HashSet<>();
        Path root = webapp_.toPath();

        for (File f : list) {
            String r = "/" + root.relativize(f.toPath());
            if (f.isDirectory()) {
                r += "/";
            }

            trace("getResourcePaths: " + r);

            res.add(r);
        }

        return res;
    }

    @Override
    public String getServerInfo()
    {
        trace("getServerInfo: " + server_info_);
        return server_info_;
    }

    @Override
    @Deprecated
    public Servlet getServlet(String name) throws ServletException
    {
        log("getServlet for " + name);
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    @Deprecated
    public Enumeration<String> getServletNames()
    {
        log("getServletNames");
        return Collections.enumeration(Collections.EMPTY_LIST);
    }

    @SuppressWarnings("unchecked")
    @Override
    @Deprecated
    public Enumeration<Servlet> getServlets()
    {
        log("getServlets");
        return Collections.enumeration(Collections.EMPTY_LIST);
    }

    @Override
    @Deprecated
    public void log(Exception exception, String msg)
    {
        log(msg, exception);
    }

    @Override
    public void log(String msg)
    {
        msg = "Context." + msg;
        log(0, msg, msg.length());
    }

    @Override
    public void log(String message, Throwable throwable)
    {
        log(message);
    }

    private static native void log(long ctx_ptr, String msg, int msg_len);


    public static void trace(String msg)
    {
        msg = "Context." + msg;
        trace(0, msg, msg.length());
    }

    private static native void trace(long ctx_ptr, String msg, int msg_len);

    @Override
    public String getInitParameter(String name)
    {
        trace("getInitParameter for " + name);
        return init_params_.get(name);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Enumeration<String> getInitParameterNames()
    {
        trace("getInitParameterNames");
        return Collections.enumeration(Collections.EMPTY_LIST);
    }

    @Override
    public String getServletContextName()
    {
        log("getServletContextName");
        return "No Context";
    }

    @Override
    public String getContextPath()
    {
        trace("getContextPath");
        return context_path_;
    }

    @Override
    public boolean setInitParameter(String name, String value)
    {
        trace("setInitParameter " + name + " = " + value);
        return init_params_.putIfAbsent(name, value) == null;
    }

    @Override
    public Object getAttribute(String name)
    {
        trace("getAttribute " + name);

        return attributes_.get(name);
    }

    @Override
    public Enumeration<String> getAttributeNames()
    {
        trace("getAttributeNames");

        Set<String> names = attributes_.keySet();
        return Collections.enumeration(names);
    }

    @Override
    public void setAttribute(String name, Object object)
    {
        trace("setAttribute " + name);

        Object prev = attributes_.put(name, object);

        if (ctx_attr_listeners_.isEmpty()) {
            return;
        }

        ServletContextAttributeEvent scae = new ServletContextAttributeEvent(
            this, name, prev == null ? object : prev);

        for (ServletContextAttributeListener l : ctx_attr_listeners_) {
            if (prev == null) {
                l.attributeAdded(scae);
            } else {
                l.attributeReplaced(scae);
            }
        }
    }

    @Override
    public void removeAttribute(String name)
    {
        trace("removeAttribute " + name);

        Object value = attributes_.remove(name);

        if (ctx_attr_listeners_.isEmpty()) {
            return;
        }

        ServletContextAttributeEvent scae = new ServletContextAttributeEvent(
            this, name, value);

        for (ServletContextAttributeListener l : ctx_attr_listeners_) {
            l.attributeRemoved(scae);
        }
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String name,
        Class<? extends Filter> filterClass)
    {
        log("addFilter<C> " + name + ", " + filterClass.getName());

        checkContextState();

        FilterReg reg = new FilterReg(name, filterClass);
        filters_.add(reg);
        name2filter_.put(name, reg);
        return reg;
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String name, Filter filter)
    {
        log("addFilter<F> " + name);

        checkContextState();

        FilterReg reg = new FilterReg(name, filter);
        filters_.add(reg);
        name2filter_.put(name, reg);
        return reg;
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String name, String className)
    {
        log("addFilter<N> " + name + ", " + className);

        checkContextState();

        FilterReg reg = new FilterReg(name, className);
        filters_.add(reg);
        name2filter_.put(name, reg);
        return reg;
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String name,
        Class<? extends Servlet> servletClass)
    {
        log("addServlet<C> " + name + ", " + servletClass.getName());

        checkContextState();

        ServletReg reg = null;
        try {
            reg = new ServletReg(name, servletClass);
            servlets_.add(reg);
            name2servlet_.put(name, reg);
        } catch(Exception e) {
            System.err.println("addServlet: exception caught: " + e.toString());
        }

        return reg;
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String name, Servlet servlet)
    {
        log("addServlet<S> " + name);

        checkContextState();

        ServletReg reg = null;
        try {
            reg = new ServletReg(name, servlet);
            servlets_.add(reg);
            name2servlet_.put(name, reg);
        } catch(Exception e) {
            System.err.println("addServlet: exception caught: " + e.toString());
        }

        return reg;
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String name, String className)
    {
        log("addServlet<N> " + name + ", " + className);

        checkContextState();

        ServletReg reg = null;
        try {
            reg = new ServletReg(name, className);
            servlets_.add(reg);
            name2servlet_.put(name, reg);
        } catch(Exception e) {
            System.err.println("addServlet: exception caught: " + e.toString());
        }

        return reg;
    }

    @Override
    public ServletRegistration.Dynamic addJspFile(String jspName, String jspFile)
    {
        log("addJspFile: " + jspName + " " + jspFile);

        return null;
    }

    @Override
    public <T extends Filter> T createFilter(Class<T> c) throws ServletException
    {
        log("createFilter<C> " + c.getName());

        checkContextState();

        try {
            Constructor<T> ctor = c.getConstructor();
            T filter = ctor.newInstance();
            return filter;
        } catch (Exception e) {
            log("createFilter() failed " + e);

            throw new ServletException(e);
        }
    }

    @Override
    public <T extends Servlet> T createServlet(Class<T> c) throws ServletException
    {
        log("createServlet<C> " + c.getName());

        checkContextState();

        try {
            Constructor<T> ctor = c.getConstructor();
            T servlet = ctor.newInstance();
            return servlet;
        } catch (Exception e) {
            log("createServlet() failed " + e);

            throw new ServletException(e);
        }
    }

    @Override
    public Set<SessionTrackingMode> getDefaultSessionTrackingModes()
    {
        log("getDefaultSessionTrackingModes");

        return default_session_tracking_modes_;
    }

    @Override
    public Set<SessionTrackingMode> getEffectiveSessionTrackingModes()
    {
        log("getEffectiveSessionTrackingModes");

        return session_tracking_modes_;
    }

    public boolean isSessionIdValid(String id)
    {
        synchronized (sessions_) {
            return sessions_.containsKey(id);
        }
    }

    public Session getSession(String id)
    {
        synchronized (sessions_) {
            Session s = sessions_.get(id);

            if (s != null) {
                s.accessed();

                if (s.checkTimeOut()) {
                    s.invalidate();
                    return null;
                }
            }

            return s;
        }
    }

    public Session createSession()
    {
        Session session = new Session(this, generateSessionId(),
                                      sess_attr_proxy_, session_timeout_ * 60);

        if (!sess_listeners_.isEmpty())
        {
            HttpSessionEvent event = new HttpSessionEvent(session);

            for (HttpSessionListener l : sess_listeners_)
            {
                l.sessionCreated(event);
            }
        }

        synchronized (sessions_) {
            sessions_.put(session.getId(), session);

            return session;
        }
    }

    public void invalidateSession(Session session)
    {
        synchronized (sessions_) {
            sessions_.remove(session.getId());
        }

        if (!sess_listeners_.isEmpty())
        {
            HttpSessionEvent event = new HttpSessionEvent(session);

            for (int i = sess_listeners_.size() - 1; i >= 0; i--)
            {
                sess_listeners_.get(i).sessionDestroyed(event);
            }
        }
    }

    public void changeSessionId(Session session)
    {
        String old_id;

        synchronized (sessions_) {
            old_id = session.getId();
            sessions_.remove(old_id);

            session.setId(generateSessionId());

            sessions_.put(session.getId(), session);
        }

        if (!sess_id_listeners_.isEmpty())
        {
            HttpSessionEvent event = new HttpSessionEvent(session);
            for (HttpSessionIdListener l : sess_id_listeners_)
            {
                l.sessionIdChanged(event, old_id);
            }
        }
    }

    private String generateSessionId()
    {
        return UUID.randomUUID().toString();
    }

    @Override
    public FilterRegistration getFilterRegistration(String filterName)
    {
        log("getFilterRegistration " + filterName);
        return name2filter_.get(filterName);
    }

    @Override
    public Map<String, ? extends FilterRegistration> getFilterRegistrations()
    {
        log("getFilterRegistrations");
        return name2filter_;
    }

    @Override
    public ServletRegistration getServletRegistration(String servletName)
    {
        log("getServletRegistration " + servletName);
        return name2servlet_.get(servletName);
    }

    @Override
    public Map<String, ? extends ServletRegistration> getServletRegistrations()
    {
        log("getServletRegistrations");
        return name2servlet_;
    }

    @Override
    public SessionCookieConfig getSessionCookieConfig()
    {
        log("getSessionCookieConfig");

        return session_cookie_config_;
    }

    @Override
    public void setSessionTrackingModes(Set<SessionTrackingMode> modes)
    {
        log("setSessionTrackingModes");

        session_tracking_modes_ = modes;
    }

    @Override
    public void addListener(String className)
    {
        trace("addListener<N> " + className);

        checkContextState();

        if (listener_classnames_.contains(className)) {
            log("addListener<N> " + className + " already added as listener");
            return;
        }

        try {
            Class<?> cls = loader_.loadClass(className);

            Constructor<?> ctor = cls.getConstructor();
            EventListener listener = (EventListener) ctor.newInstance();

            addListener(listener);

            listener_classnames_.add(className);
        } catch (Exception e) {
            log("addListener<N>: exception caught: " + e.toString());
        }
    }

    @Override
    public <T extends EventListener> void addListener(T t)
    {
        trace("addListener<T> " + t.getClass().getName());

        checkContextState();

        for (int i = 0; i < LISTENER_TYPES.length; i++) {
            Class<?> c = LISTENER_TYPES[i];
            if (c.isAssignableFrom(t.getClass())) {
                trace("addListener<T>: assignable to " + c.getName());
            }
        }

        if (t instanceof ServletContextListener) {
            ctx_listeners_.add((ServletContextListener) t);
        }

        if (t instanceof ServletContextAttributeListener) {
            ctx_attr_listeners_.add((ServletContextAttributeListener) t);
        }

        if (t instanceof ServletRequestListener) {
            req_init_listeners_.add((ServletRequestListener) t);
            req_destroy_listeners_.add(0, (ServletRequestListener) t);
        }

        if (t instanceof ServletRequestAttributeListener) {
            req_attr_listeners_.add((ServletRequestAttributeListener) t);
        }

        if (t instanceof HttpSessionAttributeListener) {
            sess_attr_listeners_.add((HttpSessionAttributeListener) t);
        }

        if (t instanceof HttpSessionIdListener) {
            sess_id_listeners_.add((HttpSessionIdListener) t);
        }

        if (t instanceof HttpSessionListener) {
            sess_listeners_.add((HttpSessionListener) t);
        }
    }

    @Override
    public void addListener(Class<? extends EventListener> listenerClass)
    {
        String className = listenerClass.getName();
        trace("addListener<C> " + className);

        checkContextState();

        if (listener_classnames_.contains(className)) {
            log("addListener<C> " + className + " already added as listener");
            return;
        }

        try {
            Constructor<?> ctor = listenerClass.getConstructor();
            EventListener listener = (EventListener) ctor.newInstance();

            addListener(listener);

            listener_classnames_.add(className);
        } catch (Exception e) {
            log("addListener<C>: exception caught: " + e.toString());
        }
    }

    @Override
    public <T extends EventListener> T createListener(Class<T> clazz)
        throws ServletException
    {
        trace("createListener<C> " + clazz.getName());

        checkContextState();

        try
        {
            return clazz.getDeclaredConstructor().newInstance();
        }
        catch (Exception e)
        {
            throw new ServletException(e);
        }
    }

    @Override
    public ClassLoader getClassLoader()
    {
        trace("getClassLoader");
        return loader_;
    }

    @Override
    public int getEffectiveMajorVersion()
    {
        log("getEffectiveMajorVersion");
        return SERVLET_MAJOR_VERSION;
    }

    @Override
    public int getEffectiveMinorVersion()
    {
        log("getEffectiveMinorVersion");
        return SERVLET_MINOR_VERSION;
    }

    private final List<TaglibDescriptor> taglibs_ = new ArrayList<>();
    private final List<JspPropertyGroupDescriptor> prop_groups_ = new ArrayList<>();

    private class JspConfig implements JspConfigDescriptor
    {
        @Override
        public Collection<TaglibDescriptor> getTaglibs()
        {
            trace("getTaglibs");
            return taglibs_;
        }

        @Override
        public Collection<JspPropertyGroupDescriptor> getJspPropertyGroups()
        {
            trace("getJspPropertyGroups");
            return prop_groups_;
        }
    }

    private final JspConfig jsp_config_ = new JspConfig();

    @Override
    public JspConfigDescriptor getJspConfigDescriptor()
    {
        trace("getJspConfigDescriptor");

        return jsp_config_;
    }

    @Override
    public void declareRoles(String... roleNames)
    {
        log("declareRoles");
        //LOG.warn(__unimplmented);
    }

    @Override
    public String getVirtualServerName()
    {
        log("getVirtualServerName");
        return null;
    }

    @Override
    public int getSessionTimeout()
    {
        trace("getSessionTimeout");

        return session_timeout_;
    }

    @Override
    public void setSessionTimeout(int sessionTimeout)
    {
        trace("setSessionTimeout: " + sessionTimeout);

        session_timeout_ = sessionTimeout;
    }

    @Override
    public String getRequestCharacterEncoding()
    {
        log("getRequestCharacterEncoding");

        return null;
    }

    @Override
    public void setRequestCharacterEncoding(String encoding)
    {
        log("setRequestCharacterEncoding: " + encoding);
    }

    @Override
    public String getResponseCharacterEncoding()
    {
        log("getResponseCharacterEncoding");

        return null;
    }

    @Override
    public void setResponseCharacterEncoding(String encoding)
    {
        log("setResponseCharacterEncoding: " + encoding);
    }

    public ServletRequestAttributeListener getRequestAttributeListener()
    {
        return req_attr_proxy_;
    }
}
