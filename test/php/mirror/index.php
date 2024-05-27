<?php
$body = file_get_contents('php://input');
header('Content-Length: ' . strlen($body));
echo $body;
?>
