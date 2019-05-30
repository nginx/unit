<?php
if (!function_exists('http_response_code')) {
    header('Temporary-Header: True', true, 404);
    header_remove('Temporary-Header');
} else {
    http_response_code(404);
}

include('404.html');
?>
