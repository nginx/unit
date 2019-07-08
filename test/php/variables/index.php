<?php
$body = file_get_contents('php://input');

header('Content-Length: ' . strlen($body));
header('Request-Method: ' . $_SERVER['REQUEST_METHOD']);
header('Request-Uri: ' . $_SERVER['REQUEST_URI']);
header('Path-Info: ' . $_SERVER['PATH_INFO']);
header('Http-Host: ' . $_SERVER['HTTP_HOST']);
header('Server-Protocol: ' . $_SERVER['SERVER_PROTOCOL']);
header('Server-Software: ' . $_SERVER['SERVER_SOFTWARE']);
header('Custom-Header: ' . $_SERVER['HTTP_CUSTOM_HEADER']);

echo $body;
?>
