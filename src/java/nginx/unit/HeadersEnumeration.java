package nginx.unit;

import java.lang.String;
import java.util.Enumeration;

public class HeadersEnumeration implements Enumeration<String> {

    private long headers_ptr;
    private long size;
    private long initial_pos;
    private long pos;

    public HeadersEnumeration(long _headers_ptr, long _size, long _initial_pos) {
        headers_ptr = _headers_ptr;
        size = _size;
        initial_pos = _initial_pos;
        pos = _initial_pos;
    }

    @Override
    public boolean hasMoreElements()
    {
        if (pos >= size) {
            return false;
        }

        pos = nextElementPos(headers_ptr, size, initial_pos, pos);
        return pos < size;
    }

    static private native long nextElementPos(long headers_ptr, long size, long initial_pos, long pos);

    @Override
    public String nextElement()
    {
        return nextElement(headers_ptr, size, initial_pos, pos++);
    }

    static private native String nextElement(long headers_ptr, long size, long initial_pos, long pos);
}
