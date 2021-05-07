<?php
if (!isset($_GET['skip'])) {
    echo "0123";
}

if (!fastcgi_finish_request()) {
    error_log("Error in fastcgi_finish_request");
}

echo "4567";

include 'server.php';
?>
