package nginx.unit;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.descriptor.JspPropertyGroupDescriptor;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class JspPropertyGroup implements JspPropertyGroupDescriptor
{
    private final List<String> url_patterns_ = new ArrayList<>();
    private String el_ignored_ = null;
    private String page_encoding_ = null;
    private String scripting_invalid_ = null;
    private String is_xml_ = null;
    private final List<String> include_preludes_ = new ArrayList<>();
    private final List<String> include_codas_ = new ArrayList<>();

    private String deffered_syntax_allowed_as_literal_ = null;
    private String trim_directive_whitespaces_ = null;
    private String default_content_type_ = null;
    private String buffer_ = null;
    private String error_on_undeclared_namespace_ = null;

    public JspPropertyGroup(NodeList nodes)
    {
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            String tag_name = node.getNodeName();

            if (tag_name.equals("url-pattern")) {
                url_patterns_.add(node.getTextContent().trim());
                continue;
            }

            if (tag_name.equals("el-ignored")) {
                el_ignored_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("page-encoding")) {
                page_encoding_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("scripting-invalid")) {
                scripting_invalid_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("is-xml")) {
                is_xml_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("include-prelude")) {
                include_preludes_.add(node.getTextContent().trim());
                continue;
            }

            if (tag_name.equals("include-coda")) {
                include_codas_.add(node.getTextContent().trim());
                continue;
            }

            if (tag_name.equals("deferred-syntax-allowed-as-literal")) {
                deffered_syntax_allowed_as_literal_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("trim-directive-whitespaces")) {
                trim_directive_whitespaces_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("default-content-type")) {
                default_content_type_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("buffer")) {
                buffer_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("error-on-undeclared-namespace")) {
                error_on_undeclared_namespace_ = node.getTextContent().trim();
                continue;
            }
        }

    }

    @Override
    public Collection<String> getUrlPatterns()
    {
        return new ArrayList<>(url_patterns_);
    }

    @Override
    public String getElIgnored()
    {
        return el_ignored_;
    }

    @Override
    public String getPageEncoding()
    {
        return page_encoding_;
    }

    @Override
    public String getScriptingInvalid()
    {
        return scripting_invalid_;
    }

    @Override
    public String getIsXml()
    {
        return is_xml_;
    }

    @Override
    public Collection<String> getIncludePreludes()
    {
        return new ArrayList<>(include_preludes_);
    }

    @Override
    public Collection<String> getIncludeCodas()
    {
        return new ArrayList<>(include_codas_);
    }

    @Override
    public String getDeferredSyntaxAllowedAsLiteral()
    {
        return deffered_syntax_allowed_as_literal_;
    }

    @Override
    public String getTrimDirectiveWhitespaces()
    {
        return trim_directive_whitespaces_;
    }

    @Override
    public String getDefaultContentType()
    {
        return default_content_type_;
    }

    @Override
    public String getBuffer()
    {
        return buffer_;
    }

    @Override
    public String getErrorOnUndeclaredNamespace()
    {
        return error_on_undeclared_namespace_;
    }
}

