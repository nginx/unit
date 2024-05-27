package nginx.unit;

public interface InitParams {
    public boolean setInitParameter(String name, String value);

    public String getInitParameter(String name);
}
