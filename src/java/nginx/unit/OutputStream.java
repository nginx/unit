package nginx.unit;

import java.io.IOException;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;

public class OutputStream extends ServletOutputStream {

    private long req_info_ptr;

    public OutputStream(long ptr) {
        req_info_ptr = ptr;
    }

    @Override
    public void write(int b) throws IOException
    {
        write(req_info_ptr, b);
    }

    private static native void write(long req_info_ptr, int b);


    @Override
    public void write(byte b[], int off, int len) throws IOException
    {
        if (b == null) {
            throw new NullPointerException();
        } else if ((off < 0) || (off > b.length) || (len < 0) ||
                   ((off + len) > b.length) || ((off + len) < 0)) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return;
        }

        write(req_info_ptr, b, off, len);
    }

    private static native void write(long req_info_ptr, byte b[], int off, int len);

    @Override
    public void flush()
    {
        flush(req_info_ptr);
    }

    private static native void flush(long req_info_ptr);

    @Override
    public void close()
    {
        close(req_info_ptr);
    }

    private static native void close(long req_info_ptr);

    @Override
    public boolean isReady()
    {
        return true;
    }

    @Override
    public void setWriteListener(WriteListener listener)
    {
    }
}
