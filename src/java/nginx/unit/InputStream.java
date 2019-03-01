package nginx.unit;

import java.io.IOException;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

public class InputStream extends ServletInputStream {

    private long req_info_ptr;

    public InputStream(long ptr)
    {
        req_info_ptr = ptr;
    }

    @Override
    public int readLine(byte[] b, int off, int len) throws IOException {

        if (len <= 0) {
            return 0;
        }
        return readLine(req_info_ptr, b, off, len);
    }

    private static native int readLine(long req_info_ptr, byte[] b, int off, int len);


    @Override
    public boolean isFinished()
    {
        return isFinished(req_info_ptr);
    }

    private static native boolean isFinished(long req_info_ptr);


    @Override
    public boolean isReady()
    {
        return true;
    }


    @Override
    public void setReadListener(ReadListener listener)
    {
    }


    @Override
    public int read() throws IOException
    {
        return read(req_info_ptr);
    }

    private static native int read(long req_info_ptr);


    @Override
    public int read(byte b[], int off, int len) throws IOException {
        if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        return read(req_info_ptr, b, off, len);
    }

    private static native int read(long req_info_ptr, byte b[], int off, int len);


    @Override
    public long skip(long n) throws IOException {
        return skip(req_info_ptr, n);
    }

    private static native long skip(long req_info_ptr, long n);


    @Override
    public int available() throws IOException {
        return available(req_info_ptr);
    }

    private static native int available(long req_info_ptr);
}
