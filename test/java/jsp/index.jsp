<%@ page contentType="text/plain"%>This is plain text response for "<%= request.getMethod() %> <%= request.getRequestURI() %>".
<% response.addHeader("X-Unit-JSP", "ok"); %>
