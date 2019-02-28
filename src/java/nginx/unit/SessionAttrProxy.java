package nginx.unit;

import java.util.List;

import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;

public class SessionAttrProxy implements HttpSessionAttributeListener
{
    private final List<HttpSessionAttributeListener> listeners_;

    public SessionAttrProxy(List<HttpSessionAttributeListener> listeners)
    {
        listeners_ = listeners;
    }

    @Override
    public void attributeAdded(HttpSessionBindingEvent event)
    {
        for (HttpSessionAttributeListener l : listeners_) {
            l.attributeAdded(event);
        }
    }

    @Override
    public void attributeRemoved(HttpSessionBindingEvent event)
    {
        for (HttpSessionAttributeListener l : listeners_) {
            l.attributeRemoved(event);
        }
    }

    @Override
    public void attributeReplaced(HttpSessionBindingEvent event)
    {
        for (HttpSessionAttributeListener l : listeners_) {
            l.attributeReplaced(event);
        }
    }
}
