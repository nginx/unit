package nginx.unit;

import javax.servlet.descriptor.TaglibDescriptor;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Taglib implements TaglibDescriptor
{
    private String uri_ = null;
    private String location_ = null;

    public Taglib(NodeList nodes)
    {
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            String tag_name = node.getNodeName();

            if (tag_name.equals("taglib-uri")) {
                uri_ = node.getTextContent().trim();
                continue;
            }

            if (tag_name.equals("taglib-location")) {
                location_ = node.getTextContent().trim();
                continue;
            }
        }

    }

    @Override
    public String getTaglibURI()
    {
        return uri_;
    }

    @Override
    public String getTaglibLocation()
    {
        return location_;
    }
}

