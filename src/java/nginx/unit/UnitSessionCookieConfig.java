package nginx.unit;

import javax.servlet.SessionCookieConfig;

/*

    <session-config>
        <session-timeout>60</session-timeout>
        <cookie-config></cookie-config>
        <tracking-mode></tracking-mode>
    </session-config>


 */
public class UnitSessionCookieConfig implements SessionCookieConfig {

    private static final String default_name = "JSESSIONID";

    private String name = default_name;
    private String domain;
    private String path;
    private String comment;
    private boolean httpOnly = true;
    private boolean secure = false;
    private int maxAge = -1;

    @Override
    public void setName(String name)
    {
        this.name = name;
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    @Override
    public String getDomain()
    {
        return domain;
    }

    @Override
    public void setPath(String path)
    {
        this.path = path;
    }

    @Override
    public String getPath()
    {
        return path;
    }

    @Override
    public void setComment(String comment)
    {
        this.comment = comment;
    }

    @Override
    public String getComment()
    {
        return comment;
    }

    @Override
    public void setHttpOnly(boolean httpOnly)
    {
        this.httpOnly = httpOnly;
    }

    @Override
    public boolean isHttpOnly()
    {
        return httpOnly;
    }

    @Override
    public void setSecure(boolean secure)
    {
        this.secure = secure;
    }

    @Override
    public boolean isSecure()
    {
        return secure;
    }

    @Override
    public void setMaxAge(int maxAge)
    {
        this.maxAge = maxAge;
    }

    @Override
    public int getMaxAge()
    {
        return maxAge;
    }
}
