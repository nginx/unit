package nginx.unit;

import java.util.List;

import javax.servlet.ServletRequestAttributeEvent;
import javax.servlet.ServletRequestAttributeListener;

public class RequestAttrProxy implements ServletRequestAttributeListener
{
    private final List<ServletRequestAttributeListener> listeners_;

    public RequestAttrProxy(List<ServletRequestAttributeListener> listeners)
    {
        listeners_ = listeners;
    }

    @Override
    public void attributeAdded(ServletRequestAttributeEvent srae)
    {
        for (ServletRequestAttributeListener l : listeners_) {
            l.attributeAdded(srae);
        }
    }

    @Override
    public void attributeReplaced(ServletRequestAttributeEvent srae)
    {
        for (ServletRequestAttributeListener l : listeners_) {
            l.attributeReplaced(srae);
        }
    }

    @Override
    public void attributeRemoved(ServletRequestAttributeEvent srae)
    {
        for (ServletRequestAttributeListener l : listeners_) {
            l.attributeRemoved(srae);
        }
    }
}
