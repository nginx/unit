package nginx.unit;

import java.lang.String;
import java.util.Enumeration;
import java.util.NoSuchElementException;

public class HeaderNamesEnumeration implements Enumeration<String> {

    private long headers_ptr;
    private long size;
    private long pos = 0;

    public HeaderNamesEnumeration(long _headers_ptr, long _size) {
        headers_ptr = _headers_ptr;
        size = _size;
    }

    @Override
    public boolean hasMoreElements()
    {
        if (pos >= size) {
            return false;
        }

        pos = nextElementPos(headers_ptr, size, pos);
        return pos < size;
    }

    static private native long nextElementPos(long headers_ptr, long size, long pos);

    @Override
    public String nextElement()
    {
        if (pos >= size) {
            throw new NoSuchElementException();
        }

        return nextElement(headers_ptr, size, pos++);
    }

    static private native String nextElement(long headers_ptr, long size, long pos);
}
