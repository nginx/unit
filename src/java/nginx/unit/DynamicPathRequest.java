package nginx.unit;

public interface DynamicPathRequest
    extends DynamicDispatcherRequest
{
    public void setServletPath(String servlet_path, String path_info);

    public void setServletPath(String filter_path, String servlet_path, String path_info);

    public void setRequestURI(String uri);

    public void setQueryString(String query);

    public String getFilterPath();
}
