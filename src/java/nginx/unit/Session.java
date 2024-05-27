package nginx.unit;

import java.io.Serializable;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;

import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Andrey Kazankov
 */
public class Session implements HttpSession, Serializable
{
    private final Map<String, Object> attributes = new HashMap<>();
    private final long creation_time = new Date().getTime();
    private long last_access_time = creation_time;
    private long access_time = creation_time;
    private int max_inactive_interval;
    private String id;
    private final Context context;
    private boolean is_new = true;
    private final HttpSessionAttributeListener attr_listener;

    public Session(Context context, String id,
        HttpSessionAttributeListener al, int max_inactive_interval)
    {
        this.id = id;
        this.context = context;
        attr_listener = al;
        this.max_inactive_interval = max_inactive_interval;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    @Override
    public long getCreationTime()
    {
        return creation_time;
    }

    @Override
    public String getId()
    {
        return id;
    }

    @Override
    public long getLastAccessedTime()
    {
        return last_access_time;
    }

    @Override
    public ServletContext getServletContext()
    {
        return context;
    }

    @Override
    public void setMaxInactiveInterval(int i)
    {
        max_inactive_interval = i;
    }

    @Override
    public int getMaxInactiveInterval()
    {
        return max_inactive_interval;
    }

    @Deprecated
    @Override
    public javax.servlet.http.HttpSessionContext getSessionContext()
    {
        return null;
    }

    @Override
    public Object getAttribute(String s)
    {
        synchronized (attributes) {
            return attributes.get(s);
        }
    }

    @Deprecated
    @Override
    public Object getValue(String s)
    {
        return getAttribute(s);
    }

    @Override
    public Enumeration<String> getAttributeNames()
    {
        synchronized (attributes) {
            return Collections.enumeration(attributes.keySet());
        }
    }

    @Deprecated
    @Override
    public String[] getValueNames()
    {
        synchronized (attributes) {
            return attributes.keySet().toArray(new String[attributes.keySet().size()]);
        }
    }

    @Override
    public void setAttribute(String s, Object o)
    {
        Object old;

        if (o != null && o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener l = (HttpSessionBindingListener) o;
            HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s);

            l.valueBound(e);
        }

        synchronized (attributes) {
            if (o != null) {
                old = attributes.put(s, o);
            } else {
                old = attributes.remove(s);
            }
        }

        if (old != null && old instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener l = (HttpSessionBindingListener) old;
            HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s);

            l.valueUnbound(e);
        }

        if (attr_listener == null) {
            return;
        }

        if (o == null) {
            if (old != null) {
                HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s, old);
                attr_listener.attributeRemoved(e);
            }

            return;
        }

        if (old != null) {
            HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s, old);
            attr_listener.attributeReplaced(e);
        } else {
            HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s, o);
            attr_listener.attributeAdded(e);
        }
    }

    @Deprecated
    @Override
    public void putValue(String s, Object o)
    {
        setAttribute(s,o);
    }

    @Override
    public void removeAttribute(String s)
    {
        Object o;

        synchronized (attributes) {
            o = attributes.remove(s);
        }

        if (o != null && o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener l = (HttpSessionBindingListener) o;
            HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s);

            l.valueUnbound(e);
        }

        if (attr_listener == null || o == null) {
            return;
        }

        HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, s, o);
        attr_listener.attributeRemoved(e);
    }

    @Deprecated
    @Override
    public void removeValue(String s)
    {
        removeAttribute(s);
    }

    @Override
    public void invalidate()
    {
        context.invalidateSession(this);

        unboundAttributes();
    }

    private void unboundAttributes()
    {
        for (Map.Entry<String, Object> a : attributes.entrySet()) {
            Object o = a.getValue();
            if (o != null && o instanceof HttpSessionBindingListener) {
                HttpSessionBindingListener l = (HttpSessionBindingListener) o;
                HttpSessionBindingEvent e = new HttpSessionBindingEvent(this, a.getKey());

                l.valueUnbound(e);
            }
        }

        attributes.clear();
    }

    @Override
    public boolean isNew()
    {
        return is_new;
    }

    public void accessed() {
        synchronized (this) {
            is_new = false;

            last_access_time = access_time;
            access_time = new Date().getTime();
        }
    }

    public boolean checkTimeOut()
    {
        return (max_inactive_interval > 0) &&
                (access_time - last_access_time > max_inactive_interval * 1000);
    }
}